package main

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Flecksis/rkn-guard/internal/service"
)

// logLevels — допустимые значения --log-level.
var logLevels = []string{"debug", "info", "warn", "error"}

// inputParams — всё, что пользователь задал флагами и что установщик обязан
// провалидировать до единого изменения в системе.
type inputParams struct {
	command       string
	urls          []string
	managedLists  bool
	sourcesFile   string
	logLevel      string
	requiredPorts []int
}

// validateInputs проверяет пользовательский ввод и возвращает понятную ошибку.
//
// Вызывается до root-проверки и до preflight firewall: некорректный запуск
// завершается кодом 2 без паники и стека, ничего не изменяя.
func validateInputs(p inputParams) error {
	var errs []error

	// --log-level.
	if !containsString(logLevels, strings.ToLower(strings.TrimSpace(p.logLevel))) {
		errs = append(errs, fmt.Errorf("недопустимый --log-level %q: допустимо %s", p.logLevel, strings.Join(logLevels, ", ")))
	}

	// --sources-file: только абсолютный путь без выхода вверх по дереву.
	if strings.TrimSpace(p.sourcesFile) == "" {
		errs = append(errs, errors.New("пустой путь --sources-file"))
	} else if !filepath.IsAbs(p.sourcesFile) {
		errs = append(errs, fmt.Errorf("--sources-file должен быть абсолютным путём, получено %q", p.sourcesFile))
	} else if containsParentSegment(p.sourcesFile) {
		errs = append(errs, fmt.Errorf("--sources-file не должен содержать '..': %q", p.sourcesFile))
	}

	// --required-ports.
	if len(p.requiredPorts) == 0 {
		errs = append(errs, errors.New("пустой список --required-ports: без него нельзя проверить, что default-deny не отрежет доступ"))
	}
	for _, port := range p.requiredPorts {
		if port < 1 || port > 65535 {
			errs = append(errs, fmt.Errorf("--required-ports: порт %d вне диапазона 1-65535", port))
		}
	}

	// --urls: нужен хотя бы один источник; только абсолютные http(s)-адреса.
	if p.command == "full" || p.command == "update" {
		if len(p.urls) == 0 && !p.managedLists {
			errs = append(errs, errors.New("не указаны URL для скачивания подсетей: используйте --urls или --managed-lists"))
		}
		for _, raw := range p.urls {
			if err := validateURL(raw); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func validateURL(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("--urls: пустой URL")
	}
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("--urls: URL содержит пробелы: %q", raw)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("--urls: некорректный URL %q: %v", raw, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("--urls: поддерживаются только http/https, получено %q", raw)
	}
	if parsed.Host == "" {
		return fmt.Errorf("--urls: в URL %q нет хоста", raw)
	}
	if parsed.User != nil {
		return fmt.Errorf("--urls: учётные данные в URL не поддерживаются: %q", raw)
	}
	return nil
}

// parsePortsList разбирает «22,2222,443» в список портов.
func parsePortsList(raw string) ([]int, error) {
	var ports []int
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		port, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("--required-ports: %q не является портом", item)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("--required-ports: порт %d вне диапазона 1-65535", port)
		}
		ports = append(ports, port)
	}
	return service.NormalizePorts(ports), nil
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// joinPorts форматирует список портов для значения флага по умолчанию.
func joinPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range service.NormalizePorts(ports) {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

// containsParentSegment ищет переход вверх по дереву в исходном (не очищенном) пути.
func containsParentSegment(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
