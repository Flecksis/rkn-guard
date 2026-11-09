package service

import (
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDeliveryFailurePreservesLogs(t *testing.T) {
	s := &LoggingService{root: t.TempDir()}
	for _, path := range []string{"/dev/kmsg", IPv4LogPath, IPv6LogPath} {
		if err := os.MkdirAll(filepath.Dir(s.path(path)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.path(path), []byte("старые данные\n"), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.verifyDelivery(0); err == nil {
		t.Fatal("нет ошибки при потере событий")
	}
	for _, path := range []string{IPv4LogPath, IPv6LogPath} {
		data, _ := os.ReadFile(s.path(path))
		if string(data) != "старые данные\n" {
			t.Fatal("журнал изменён")
		}
	}
	data, _ := os.ReadFile(s.path("/dev/kmsg"))
	if strings.Contains(string(data), "SRC=") {
		t.Fatal("проверка попадает в статистику")
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
