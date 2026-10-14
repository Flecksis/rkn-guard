package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

const SourcesPath = "/var/lib/rkn-guard/sources.json"
const maxSources = 32
const maxSourcesBytes = 64 << 20

type ExtraSource struct {
	ID      int    `json:"id"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type SourceCache struct {
	Networks  []string `json:"networks"`
	UpdatedAt string   `json:"updated_at"`
	LastError string   `json:"last_error,omitempty"`
}

// SourceState хранит настройки и последнюю проверенную копию каждого источника вместе.
type SourceState struct {
	Version int                    `json:"version"`
	NextID  int                    `json:"next_id"`
	Extra   []ExtraSource          `json:"extra"`
	Cache   map[string]SourceCache `json:"cache"`
}

// SourceStore вызывается под общей блокировкой rkn-guard, как обновление наборов.
type SourceStore struct {
	Path       string
	Downloader *Downloader
}

// NormalizeSourceURL принимает только HTTP(S); страницы GitHub переводит на raw.
func NormalizeSourceURL(raw string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", fmt.Errorf("введите URL без пробелов и управляющих символов")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("нужен HTTP(S) URL без пароля и фрагмента #")
	}
	u.Host = strings.ToLower(u.Host)
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if u.Host == "github.com" && len(parts) >= 5 && parts[2] == "blob" {
		u.Host = "raw.githubusercontent.com"
		u.Path = "/" + strings.Join(append(parts[:2], parts[3:]...), "/")
		u.RawPath, u.RawQuery = "", ""
	}
	// Обе формы raw-ссылки на ветку должны считаться одним источником.
	if u.Host == "raw.githubusercontent.com" {
		parts = strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
		if len(parts) >= 6 && parts[2] == "refs" && parts[3] == "heads" {
			u.Path = "/" + strings.Join(append(parts[:2], parts[4:]...), "/")
			u.RawPath = ""
		}
	}
	return u.String(), nil
}

func (s *SourceStore) Load() (*SourceState, error) {
	f, err := os.Open(s.Path)
	if os.IsNotExist(err) {
		return &SourceState{Version: 1, NextID: 1, Extra: []ExtraSource{}, Cache: make(map[string]SourceCache)}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSourcesBytes+1))
	if err != nil || len(data) > maxSourcesBytes {
		return nil, fmt.Errorf("не удалось прочитать настройки списков или файл слишком большой")
	}
	var state SourceState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("повреждён файл настроек %s: %w", s.Path, err)
	}
	if state.Version != 1 || state.NextID < 1 || state.Cache == nil || len(state.Extra) > maxSources {
		return nil, fmt.Errorf("неверный формат настроек %s", s.Path)
	}
	ids, urls := map[int]bool{}, map[string]bool{}
	for _, source := range state.Extra {
		normal, err := NormalizeSourceURL(source.URL)
		if err != nil || normal != source.URL || source.ID < 1 || source.ID >= state.NextID || ids[source.ID] || urls[normal] {
			return nil, fmt.Errorf("неверный или повторяющийся источник в %s", s.Path)
		}
		ids[source.ID], urls[normal] = true, true
	}
	return &state, nil
}

func (s *SourceStore) save(state *SourceState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxSourcesBytes {
		return fmt.Errorf("настройки и сохранённые списки превышают 64 МиБ")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0700); err != nil {
		return err
	}
	return atomicWriteFile(s.Path, append(data, '\n'), 0600)
}

func sourceNetworks(n *domain.NetworkList) []string {
	result := append(append([]string{}, n.IPv4Subnets...), n.IPv6Subnets...)
	sort.Strings(result)
	return result
}

func (s *SourceStore) fetch(source string, strict bool) (*domain.NetworkList, error) {
	lines, err := s.Downloader.downloadSingle(source)
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки: %w", err)
	}
	return parseSubnets(lines, source, strict)
}

// Add сначала проверяет URL и данные. Новый источник остаётся выключенным до выбора в меню.
func (s *SourceStore) Add(raw string, base []string) (int, error) {
	source, err := NormalizeSourceURL(raw)
	if err != nil {
		return 0, err
	}
	state, err := s.Load()
	if err != nil {
		return 0, err
	}
	for _, u := range base {
		normal, err := NormalizeSourceURL(u)
		if err != nil {
			return 0, err
		}
		if source == normal {
			return 0, fmt.Errorf("этот URL уже входит в основные списки")
		}
	}
	for _, existing := range state.Extra {
		if existing.URL == source {
			return 0, fmt.Errorf("список уже добавлен под номером %d", existing.ID)
		}
	}
	if len(state.Extra) >= maxSources {
		return 0, fmt.Errorf("можно добавить не более %d списков", maxSources)
	}
	networks, err := s.fetch(source, true)
	if err != nil {
		return 0, err
	}
	id := state.NextID
	state.NextID++
	state.Extra = append(state.Extra, ExtraSource{ID: id, URL: source})
	state.Cache[source] = SourceCache{Networks: sourceNetworks(networks), UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	return id, s.save(state)
}

func (s *SourceStore) Change(id int, action string) error {
	state, err := s.Load()
	if err != nil {
		return err
	}
	for i, source := range state.Extra {
		if source.ID != id {
			continue
		}
		switch action {
		case "enable":
			state.Extra[i].Enabled = true
		case "disable":
			state.Extra[i].Enabled = false
		case "remove":
			state.Extra = append(state.Extra[:i], state.Extra[i+1:]...)
			delete(state.Cache, source.URL)
		default:
			return fmt.Errorf("неизвестное действие со списком")
		}
		return s.save(state)
	}
	return fmt.Errorf("списка с номером %d нет", id)
}

// Download обновляет источники независимо. При сбое берёт их последнюю проверенную копию.
func (s *SourceStore) Download(base []string) (*domain.NetworkList, []string, error) {
	state, err := s.Load()
	if err != nil {
		return nil, nil, err
	}
	if len(base) == 0 {
		return nil, nil, fmt.Errorf("не заданы основные списки")
	}
	var sources []ExtraSource
	seenURLs := map[string]bool{}
	for _, raw := range base {
		normal, err := NormalizeSourceURL(raw)
		if err != nil {
			return nil, nil, err
		}
		if !seenURLs[normal] {
			sources = append(sources, ExtraSource{URL: normal})
			seenURLs[normal] = true
		}
	}
	for _, source := range state.Extra {
		if source.Enabled && !seenURLs[source.URL] {
			sources = append(sources, source)
			seenURLs[source.URL] = true
		}
	}
	combined, seen := domain.NewNetworkList(), map[string]bool{}
	var warnings []string
	for _, source := range sources {
		cached := state.Cache[source.URL]
		networks, fetchErr := s.fetch(source.URL, source.ID != 0)
		if fetchErr != nil {
			cached.LastError = fetchErr.Error()
			var cacheErr error
			networks, cacheErr = parseSubnets(cached.Networks, source.URL, true)
			if cacheErr != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v. Корректной сохранённой копии нет, источник пропущен", source.URL, fetchErr))
				state.Cache[source.URL] = cached
				continue
			}
			warnings = append(warnings, fmt.Sprintf("%s: %v. Используются последние корректные данные от %s", source.URL, fetchErr, cached.UpdatedAt))
		} else {
			cached = SourceCache{Networks: sourceNetworks(networks), UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
		}
		state.Cache[source.URL] = cached
		for _, subnet := range sourceNetworks(networks) {
			if !seen[subnet] {
				combined.Add(subnet, isIPv6Subnet(subnet))
				seen[subnet] = true
			}
		}
	}
	// Сначала сохраняем проверенные копии. Ошибка записи не должна менять рабочие наборы.
	if err := s.save(state); err != nil {
		return nil, warnings, fmt.Errorf("не удалось сохранить данные списков: %w", err)
	}
	if combined.TotalCount() == 0 {
		return nil, warnings, fmt.Errorf("нет корректных подсетей; текущие наборы оставлены без изменений")
	}
	if combined.IPv4Count() > 65536 || combined.IPv6Count() > 65536 {
		return nil, warnings, fmt.Errorf("общий список превышает 65536 подсетей на семейство; текущие наборы сохранены")
	}
	return combined, warnings, nil
}
