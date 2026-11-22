package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestDeliveryFailurePreservesLogs(t *testing.T) {
	s := &LoggingService{root: t.TempDir()}
	for _, path := range []string{IPv4LogPath, IPv6LogPath} {
		if err := os.MkdirAll(filepath.Dir(s.path(path)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.path(path), []byte("старые данные\n"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := waitForLog(s.path(IPv4LogPath), "absent", time.Now(), 0); err == nil || !strings.Contains(err.Error(), IPv4LogPath) {
		t.Fatal("нет ошибки при потере событий")
	}
	for _, path := range []string{IPv4LogPath, IPv6LogPath} {
		data, _ := os.ReadFile(s.path(path))
		if string(data) != "старые данные\n" {
			t.Fatal("журнал изменён")
		}
	}
}

func TestCollectorShebangUsesUnixNewline(t *testing.T) {
	if !strings.HasPrefix(AggregateLogsScriptTemplate, "#!/usr/bin/python3\n") || strings.Contains(AggregateLogsScriptTemplate, "\r\n") {
		t.Fatal("неверные переводы строк встроенного скрипта")
	}
}

func TestDeliveryDiagnostics(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	path := filepath.Join(dir, "ipv6.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	prefix := "ANTISCAN-v6: chk-0123456789 "
	for _, tc := range []struct{ script, want string }{
		{"echo 'ANTISCAN-v6: chk-0123456789 IN=lo'", "метка есть в журнале ядра"},
		{"exit 1", "нет в журнале ядра"},
		{"echo denied >&2; exit 1", "не удалось проверить журнал ядра"},
	} {
		if err := os.WriteFile(filepath.Join(dir, "journalctl"), []byte("#!/bin/sh\n"+tc.script+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		err := waitForLog(path, prefix, time.Now(), 0)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), path) {
			t.Fatalf("%s: %v", tc.script, err)
		}
	}
}

func TestLoggingHealth(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	s := &LoggingService{root: t.TempDir(), logger: zerolog.Nop()}
	bin := s.path("/bin")
	os.MkdirAll(bin, 0755)
	t.Setenv("PATH", bin)
	for _, path := range []string{RsyslogConfigPath, IPv4LogPath, IPv6LogPath} {
		os.MkdirAll(filepath.Dir(s.path(path)), 0755)
		os.WriteFile(s.path(path), nil, 0640)
	}
	os.WriteFile(filepath.Join(bin, "rsyslogd"), []byte("#!/bin/sh\nexit 0\n"), 0755)
	os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\ntest \"$3\" != \"$FAIL_UNIT\"\n"), 0755)
	for _, unit := range []string{"", "rsyslog", "antiscan-aggregate.timer"} {
		t.Setenv("FAIL_UNIT", unit)
		if err := s.CheckHealth(); (err != nil) != (unit != "") {
			t.Fatalf("%s: %v", unit, err)
		}
	}
	t.Setenv("FAIL_UNIT", "")
	os.Remove(s.path(IPv6LogPath))
	if s.CheckHealth() == nil {
		t.Fatal("нет ошибки при отсутствии журнала")
	}
}

func TestLogrotateOwnerMatchesLogs(t *testing.T) {
	s := &LoggingService{root: t.TempDir(), logger: zerolog.Nop()}
	if err := s.setupLogrotate(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.path(LogrotateConfigPath))
	if !strings.Contains(string(data), "create 0640 "+loggingOwner()+" adm") {
		t.Fatal(string(data))
	}
}
