package main

import (
	"strings"
	"testing"
)

func validInput() inputParams {
	return inputParams{
		command:       "full",
		urls:          []string{"https://example.com/list.txt"},
		sourcesFile:   "/etc/rkn-guard/sources.json",
		logLevel:      "info",
		requiredPorts: []int{22, 2222, 443},
	}
}

func TestValidateInputsAcceptsValid(t *testing.T) {
	if err := validateInputs(validInput()); err != nil {
		t.Fatalf("некорректный запуск отклонён: %v", err)
	}
	m := validInput()
	m.urls = nil
	m.managedLists = true
	if err := validateInputs(m); err != nil {
		t.Fatalf("--managed-lists без --urls отклонён: %v", err)
	}
}

func TestValidateInputsRejects(t *testing.T) {
	cases := map[string]func(*inputParams){
		"без источников": func(p *inputParams) { p.urls = nil },
		"ftp":            func(p *inputParams) { p.urls = []string{"ftp://example.com/list"} },
		"относительный":  func(p *inputParams) { p.urls = []string{"example.com/list.txt"} },
		"без хоста":      func(p *inputParams) { p.urls = []string{"https:///list.txt"} },
		"пустой url":     func(p *inputParams) { p.urls = []string{"", "https://ok.example/x"} },
		"пробел в url":   func(p *inputParams) { p.urls = []string{"https://ok.example/a b"} },
		"креды в url":    func(p *inputParams) { p.urls = []string{"https://u:p@ok.example/x"} },
		"пустой путь":    func(p *inputParams) { p.sourcesFile = "  " },
		"относит. путь":  func(p *inputParams) { p.sourcesFile = "sources.json" },
		"traversal":      func(p *inputParams) { p.sourcesFile = "/etc/rkn-guard/../../etc/shadow" },
		"log-level":      func(p *inputParams) { p.logLevel = "verbose" },
		"без портов":     func(p *inputParams) { p.requiredPorts = nil },
		"порт 0":         func(p *inputParams) { p.requiredPorts = []int{0} },
		"порт 70000":     func(p *inputParams) { p.requiredPorts = []int{70000} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := validInput()
			mutate(&p)
			err := validateInputs(p)
			if err == nil {
				t.Fatalf("ожидался отказ для %q", name)
			}
			if strings.Contains(err.Error(), "panic") {
				t.Fatalf("ошибка не должна упоминать panic: %v", err)
			}
		})
	}
}

func TestValidateInputsUninstallDoesNotNeedURLs(t *testing.T) {
	p := validInput()
	p.command = "uninstall"
	p.urls = nil
	if err := validateInputs(p); err != nil {
		t.Fatalf("uninstall не требует --urls: %v", err)
	}
}

func TestParsePortsList(t *testing.T) {
	ports, err := parsePortsList("22, 2222,443,443")
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 3 || ports[0] != 22 || ports[1] != 443 || ports[2] != 2222 {
		t.Fatalf("неожиданный список: %v", ports)
	}
	for _, bad := range []string{"22,ssh", "22,,0", "70000"} {
		if _, err := parsePortsList(bad); err == nil {
			t.Fatalf("принят некорректный список %q", bad)
		}
	}
}

func TestRequiredPortsFlagDefault(t *testing.T) {
	if got := joinPorts([]int{2087, 22, 2443, 2222, 443}); got != "22,443,2087,2222,2443" {
		t.Fatalf("значение по умолчанию: %q", got)
	}
}
