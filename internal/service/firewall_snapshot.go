package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// ErrNoSnapshot возвращается, когда снимка состояния нет и откатываться некуда.
var ErrNoSnapshot = errors.New("снимок состояния firewall не найден")

const (
	// SnapshotDir — каталог снимка состояния системы до установки.
	SnapshotDir = "/var/lib/rkn-guard/snapshot"
	// snapshotManifest — файл манифеста внутри каталога снимка.
	snapshotManifest = "manifest.json"
	// snapshotVersion — версия формата снимка.
	snapshotVersion = 1
)

// snapshotFilePaths — файлы firewall/автозапуска, которые попадают в снимок.
var snapshotFilePaths = []string{
	"/etc/ufw/before.rules",
	"/etc/ufw/before6.rules",
	"/etc/ufw/user.rules",
	"/etc/ufw/user6.rules",
	"/etc/default/ufw",
	"/etc/ufw/ufw.conf",
	"/etc/iptables/rules.v4",
	"/etc/iptables/rules.v6",
}

// snapshotUnits — сервисы и таймеры, состояние автозапуска которых фиксируется.
var snapshotUnits = []string{
	"ufw.service",
	"antiscan-ipset-restore.service",
	"antiscan-move-rules.service",
	"antiscan-aggregate.service",
	"antiscan-aggregate.timer",
	"rkn-guard-update.service",
	"rkn-guard-update.timer",
}

// managedChainPrefixes — цепочки/наборы, которые создаёт rkn-guard.
// Только они удаляются при откате: чужие цепочки (в том числе Docker) не трогаем.
var managedChainPrefixes = []string{"SCANNERS-BLOCK", "RKN-NEXT"}

// FileState — состояние одного файла в снимке.
type FileState struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Mode     uint32 `json:"mode,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	StoredAs string `json:"stored_as,omitempty"`
}

// Snapshot — снимок firewall-состояния до установки.
type Snapshot struct {
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	UFWPresent   bool              `json:"ufw_present"`
	UFWStatus    string            `json:"ufw_status"`
	UFWVerbose   string            `json:"ufw_status_verbose,omitempty"`
	UFWShowAdded string            `json:"ufw_show_added,omitempty"`
	DefaultInput string            `json:"default_input_policy,omitempty"`
	DefaultFwd   string            `json:"default_forward_policy,omitempty"`
	IPTablesV4   string            `json:"iptables_v4,omitempty"`
	IPTablesV6   string            `json:"iptables_v6,omitempty"`
	IPSetSave    string            `json:"ipset,omitempty"`
	Units        map[string]string `json:"units,omitempty"`
	Files        []FileState       `json:"files"`
	Notes        []string          `json:"notes,omitempty"`
}

// UFWWasActive сообщает, был ли UFW включён на момент снимка.
func (s *Snapshot) UFWWasActive() bool {
	return strings.Contains(s.UFWStatus, "Status: active")
}

// Snapshotter снимает и восстанавливает состояние firewall.
type Snapshotter struct {
	// Cmd — исполнитель команд (ufw/iptables/ipset/systemctl).
	Cmd firewallCommands
	// Logger — журнал.
	Logger zerolog.Logger
	// Dir — каталог снимка.
	Dir string
	// Root — префикс файловой системы (используется тестами), "" = корень.
	Root string
	// ExistsFn проверяет наличие команды в PATH.
	ExistsFn func(string) bool
	// Now — источник времени (для тестов).
	Now func() time.Time
}

// NewSnapshotter создаёт Snapshotter для реальной системы.
func NewSnapshotter(logger zerolog.Logger, cmd firewallCommands, commandExists func(string) bool) *Snapshotter {
	return &Snapshotter{
		Cmd:      cmd,
		Logger:   logger,
		Dir:      SnapshotDir,
		Now:      time.Now,
		ExistsFn: commandExists,
	}
}

func (s *Snapshotter) root() string {
	if s.Root == "" {
		return "/"
	}
	return s.Root
}

func (s *Snapshotter) fsPath(p string) string {
	return filepath.Join(s.root(), p)
}

func (s *Snapshotter) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// Capture собирает снимок состояния, ничего не меняя в системе.
func (s *Snapshotter) Capture() (*Snapshot, error) {
	if s.Cmd == nil {
		return nil, errors.New("snapshot: команды не заданы")
	}
	snap := &Snapshot{
		Version:   snapshotVersion,
		CreatedAt: s.now().UTC(),
		Units:     map[string]string{},
	}

	if out, err := s.Cmd.RunOutput("ufw", "status"); err == nil {
		snap.UFWPresent = true
		snap.UFWStatus = strings.TrimSpace(out)
	} else {
		snap.UFWStatus = "ufw: " + err.Error()
	}
	if snap.UFWPresent {
		if out, err := s.Cmd.RunOutput("ufw", "status", "verbose"); err == nil {
			snap.UFWVerbose = out
		}
		if out, err := s.Cmd.RunOutput("ufw", "show", "added"); err == nil {
			snap.UFWShowAdded = out
		}
		snap.DefaultInput, snap.DefaultFwd = snapshotDefaultPolicies(s.fsPath("/etc/default/ufw"))
	}

	for _, name := range []struct {
		bin  string
		args []string
		dst  *string
	}{
		{"iptables-save", nil, &snap.IPTablesV4},
		{"ip6tables-save", nil, &snap.IPTablesV6},
		{"ipset", []string{"save"}, &snap.IPSetSave},
	} {
		out, err := s.Cmd.RunOutput(name.bin, name.args...)
		if err != nil {
			snap.Notes = append(snap.Notes, fmt.Sprintf("%s: %v", name.bin, err))
			continue
		}
		*name.dst = out
	}

	for _, unit := range snapshotUnits {
		if s.commandExists("systemctl") {
			out, err := s.Cmd.RunOutput("systemctl", "is-enabled", unit)
			state := strings.TrimSpace(out)
			if err != nil && state == "" {
				state = "unknown"
			}
			snap.Units[unit] = state
		}
	}

	for _, p := range snapshotFilePaths {
		state, err := s.captureFile(p)
		if err != nil {
			return nil, err
		}
		snap.Files = append(snap.Files, state)
	}

	return snap, nil
}

func (s *Snapshotter) captureFile(p string) (FileState, error) {
	full := s.fsPath(p)
	state := FileState{Path: p}
	info, err := os.Stat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, fmt.Errorf("snapshot: stat %s: %w", p, err)
	}
	content, err := os.ReadFile(full)
	if err != nil {
		return state, fmt.Errorf("snapshot: read %s: %w", p, err)
	}
	sum := sha256.Sum256(content)
	state.Exists = true
	state.Mode = uint32(info.Mode().Perm())
	state.SHA256 = hex.EncodeToString(sum[:])
	state.StoredAs = "files/" + strings.ReplaceAll(strings.TrimPrefix(p, "/"), "/", "__")
	return state, nil
}

// Save снимает состояние и записывает его на диск.
func (s *Snapshotter) Save() (*Snapshot, error) {
	snap, err := s.Capture()
	if err != nil {
		return nil, err
	}
	if err := s.persist(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

func (s *Snapshotter) persist(snap *Snapshot) error {
	dir := s.fsPath(s.Dir)
	filesDir := filepath.Join(dir, "files")
	if err := os.MkdirAll(filesDir, 0o700); err != nil {
		return fmt.Errorf("snapshot: создать каталог: %w", err)
	}
	for i := range snap.Files {
		state := &snap.Files[i]
		if !state.Exists {
			continue
		}
		content, err := os.ReadFile(s.fsPath(state.Path))
		if err != nil {
			return fmt.Errorf("snapshot: прочитать %s: %w", state.Path, err)
		}
		if err := os.WriteFile(filepath.Join(dir, state.StoredAs), content, 0o600); err != nil {
			return fmt.Errorf("snapshot: записать копию %s: %w", state.Path, err)
		}
	}
	payload, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, snapshotManifest+".tmp")
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, snapshotManifest))
}

// Load читает снимок с диска.
func (s *Snapshotter) Load() (*Snapshot, error) {
	payload, err := os.ReadFile(filepath.Join(s.fsPath(s.Dir), snapshotManifest))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSnapshot
		}
		return nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(payload, &snap); err != nil {
		return nil, fmt.Errorf("snapshot: повреждён манифест: %w", err)
	}
	return &snap, nil
}

// Exists сообщает, есть ли сохранённый снимок.
func (s *Snapshotter) Exists() bool {
	_, err := os.Stat(filepath.Join(s.fsPath(s.Dir), snapshotManifest))
	return err == nil
}

// RestoreFromDisk восстанавливает состояние из сохранённого снимка.
func (s *Snapshotter) RestoreFromDisk() error {
	snap, err := s.Load()
	if err != nil {
		return err
	}
	return s.Restore(snap)
}

// Restore возвращает систему к состоянию снимка.
//
// Операция идемпотентна: повторный вызов не должен ничего менять.
func (s *Snapshotter) Restore(snap *Snapshot) (result error) {
	if snap == nil {
		return ErrNoSnapshot
	}
	dir := s.fsPath(s.Dir)

	// 1. Файлы firewall — байт-в-байт как в снимке.
	for _, state := range snap.Files {
		full := s.fsPath(state.Path)
		if !state.Exists {
			if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
				result = errors.Join(result, fmt.Errorf("удалить %s: %w", state.Path, err))
			}
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, state.StoredAs))
		if err != nil {
			result = errors.Join(result, fmt.Errorf("прочитать копию %s: %w", state.Path, err))
			continue
		}
		mode := os.FileMode(state.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := atomicWriteFile(full, content, mode); err != nil {
			result = errors.Join(result, fmt.Errorf("записать %s: %w", state.Path, err))
		}
	}

	// 2. Состояние UFW: включён — reload, выключен — возвращаем выключенным.
	if snap.UFWPresent {
		current, err := s.Cmd.RunOutput("ufw", "status")
		nowActive := err == nil && strings.Contains(current, "Status: active")
		switch {
		case snap.UFWWasActive():
			if err := s.Cmd.Run("ufw", "reload"); err != nil {
				result = errors.Join(result, fmt.Errorf("ufw reload: %w", err))
			}
		case nowActive:
			// Возврат к baseline: UFW был выключен до установки.
			if err := s.Cmd.Run("ufw", "--force", "disable"); err != nil {
				result = errors.Join(result, fmt.Errorf("ufw disable: %w", err))
			}
		}
	}

	// 3. Политики INPUT/FORWARD — как в снимке.
	for _, item := range []struct{ bin, saved string }{
		{"iptables", snap.IPTablesV4},
		{"ip6tables", snap.IPTablesV6},
	} {
		for _, chain := range []string{"INPUT", "FORWARD"} {
			policy := snapshotChainPolicy(item.saved, chain)
			if policy == "" || policy == "-" {
				continue
			}
			if err := s.Cmd.Run(item.bin, "-P", chain, policy); err != nil {
				result = errors.Join(result, fmt.Errorf("%s -P %s %s: %w", item.bin, chain, policy, err))
			}
		}
	}

	// 4. Созданные rkn-guard цепочки и наборы, которых не было в снимке.
	s.removeManagedChains(snap.IPTablesV4, "iptables")
	s.removeManagedChains(snap.IPTablesV6, "ip6tables")
	s.removeManagedSets(snap.IPSetSave)

	// 5. Автозапуск сервисов.
	if s.commandExists("systemctl") {
		names := make([]string, 0, len(snap.Units))
		for name := range snap.Units {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			want := snap.Units[name]
			action := "disable"
			if strings.HasPrefix(want, "enabled") {
				action = "enable"
			}
			if err := s.Cmd.Run("systemctl", action, name); err != nil {
				// Юнита может не быть в системе — это не ошибка отката.
				s.Logger.Debug().Err(err).Str("unit", name).Msg("systemctl не применил состояние автозапуска")
			}
		}
	}

	// 6. Проверка результата.
	return errors.Join(result, s.Verify(snap))
}

// Verify сравнивает текущее состояние с снимком и возвращает расхождения.
func (s *Snapshotter) Verify(snap *Snapshot) error {
	var problems []string
	for _, state := range snap.Files {
		full := s.fsPath(state.Path)
		if !state.Exists {
			if _, err := os.Stat(full); err == nil {
				problems = append(problems, state.Path+": файл появился, хотя в снимке его не было")
			}
			continue
		}
		content, err := os.ReadFile(full)
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", state.Path, err))
			continue
		}
		sum := sha256.Sum256(content)
		if got := hex.EncodeToString(sum[:]); got != state.SHA256 {
			problems = append(problems, fmt.Sprintf("%s: содержимое отличается от снимка", state.Path))
		}
	}

	if snap.UFWPresent {
		current, err := s.Cmd.RunOutput("ufw", "status")
		if err != nil {
			problems = append(problems, "ufw status: "+err.Error())
		} else if snap.UFWWasActive() != strings.Contains(current, "Status: active") {
			problems = append(problems, "состояние UFW не совпадает со снимком")
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("откат не совпал со снимком: %s", strings.Join(problems, "; "))
}

func (s *Snapshotter) removeManagedChains(saved string, bin string) {
	before := snapshotChains(saved)
	for _, chain := range []string{chainName} {
		if before[chain] || !isManagedChain(chain) {
			continue
		}
		if err := s.Cmd.Run(bin, "-F", chain); err != nil {
			s.Logger.Debug().Err(err).Str("chain", chain).Msg("цепочки нет, пропускаю")
		}
		if err := s.Cmd.Run(bin, "-X", chain); err != nil {
			s.Logger.Debug().Err(err).Str("chain", chain).Msg("цепочку удалить не удалось")
		}
	}
}

func (s *Snapshotter) removeManagedSets(saved string) {
	before := snapshotSets(saved)
	for _, name := range []string{ipsetV4Name, ipsetV6Name} {
		if before[name] || !isManagedChain(name) {
			continue
		}
		_ = s.Cmd.Run("ipset", "flush", name)
		_ = s.Cmd.Run("ipset", "destroy", name)
	}
}

// commandExists проверяет наличие команды в PATH.
func (s *Snapshotter) commandExists(name string) bool {
	if s.ExistsFn == nil {
		return false
	}
	return s.ExistsFn(name)
}

func isManagedChain(name string) bool {
	for _, prefix := range managedChainPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// snapshotChainPolicy возвращает политику цепочки из вывода iptables-save.
func snapshotChainPolicy(saved, chain string) string {
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ":") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.TrimPrefix(fields[0], ":") == chain {
			return fields[1]
		}
	}
	return ""
}

// snapshotChains возвращает имена цепочек из вывода iptables-save.
func snapshotChains(saved string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(saved, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, ":") {
			continue
		}
		name := strings.TrimPrefix(strings.Fields(line)[0], ":")
		out[name] = true
	}
	return out
}

// snapshotSets возвращает имена наборов ipset из вывода ipset save.
func snapshotSets(saved string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(saved, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "create" {
			out[fields[1]] = true
		}
	}
	return out
}

// snapshotDefaultPolicies читает политики по умолчанию из /etc/default/ufw.
func snapshotDefaultPolicies(path string) (input, forward string) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(value, "\"'")
		switch strings.TrimSpace(key) {
		case "DEFAULT_INPUT_POLICY":
			input = value
		case "DEFAULT_FORWARD_POLICY":
			forward = value
		}
	}
	return input, forward
}

// FormatSnapshotReport — короткая человекочитаемая сводка снимка.
func FormatSnapshotReport(snap *Snapshot) string {
	if snap == nil {
		return "снимок отсутствует"
	}
	state := "выключен"
	if snap.UFWWasActive() {
		state = "включён"
	}
	input := snap.DefaultInput
	if input == "" {
		input = "неизвестно"
	}
	return fmt.Sprintf("UFW %s, DEFAULT_INPUT_POLICY=%s, файлов в снимке: %s, iptables: %d байт",
		state, input, strconv.Itoa(len(snap.Files)), len(snap.IPTablesV4))
}
