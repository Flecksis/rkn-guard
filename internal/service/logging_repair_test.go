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

func TestLoggingRepair(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	for _, failure := range []string{"", "fresh", "apt", "enable rsyslog", "restart rsyslog", "is-active --quiet rsyslog", "start antiscan-aggregate.timer", "rsyslogd"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			for _, dir := range []string{"bin", "dev", "var/log", "etc/logrotate.d", "etc/systemd/system", "usr/local/bin"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", bin)
			t.Setenv("REPAIR_BIN", bin)
			t.Setenv("REPAIR_CALLS", filepath.Join(root, "calls"))
			t.Setenv("REPAIR_FAIL", failure)
			write := func(name, body string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			write("python3", "exit 0\n")
			write("logrotate", "exit 0\n")
			write("apt-get", `echo apt >> "$REPAIR_CALLS"
test "$REPAIR_FAIL" = apt && exit 1
printf '#!/bin/sh\ntest "$REPAIR_FAIL" != rsyslogd\n' > "$REPAIR_BIN/rsyslogd"
/bin/chmod +x "$REPAIR_BIN/rsyslogd"
`)
			write("systemctl", `echo "$*" >> "$REPAIR_CALLS"
test "$*" = "$REPAIR_FAIL" && exit 1
test "$1" = show && echo inactive
exit 0
`)
			write("chown", "exit 0\n")
			write("chmod", "exit 0\n")
			s := &LoggingService{logger: zerolog.Nop(), root: root}
			kernel := s.path("/dev/kmsg")
			if err := os.WriteFile(kernel, nil, 0600); err != nil {
				t.Fatal(err)
			}
			stop, done := make(chan struct{}), make(chan struct{})
			t.Cleanup(func() { close(stop); <-done })
			go func() {
				defer close(done)
				previous := ""
				for {
					select {
					case <-stop:
						return
					case <-time.After(10 * time.Millisecond):
					}
					data, _ := os.ReadFile(kernel)
					if len(data) == 0 || string(data) == previous || !strings.Contains(string(data), "ANTISCAN-v6:") {
						continue
					}
					for _, path := range []string{IPv4LogPath, IPv6LogPath} {
						f, err := os.OpenFile(s.path(path), os.O_APPEND|os.O_WRONLY, 0640)
						if err == nil {
							f.Write(data)
							f.Close()
						}
					}
					previous = string(data)
				}
			}()
			for _, path := range []string{IPv4LogPath, IPv6LogPath, AggregateLogPath, AggregateLogsTimerPath} {
				if failure == "fresh" {
					continue
				}
				if err := os.WriteFile(s.path(path), []byte("старые данные\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if failure != "" && failure != "fresh" {
				if err := os.MkdirAll(filepath.Dir(s.path(RsyslogConfigPath)), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.path(RsyslogConfigPath), []byte("прежний конфиг\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := s.Refresh()
			if failure == "rsyslogd" || failure == "enable rsyslog" {
				calls, _ := os.ReadFile(filepath.Join(root, "calls"))
				if strings.Contains(string(calls), "restart rsyslog") {
					t.Fatal("перезапуск после ошибки проверки")
				}
			}
			if (err != nil) != (failure != "" && failure != "fresh") {
				t.Fatalf("failure=%q err=%v", failure, err)
			}
			if failure == "" || failure == "fresh" {
				if err := s.Refresh(); err != nil {
					t.Fatal(err)
				}
				calls, _ := os.ReadFile(filepath.Join(root, "calls"))
				if strings.Count(string(calls), "apt\n") != 1 {
					t.Fatal(string(calls))
				}
				config, err := os.ReadFile(s.path(RsyslogConfigPath))
				if err != nil || string(config) != RsyslogConfigTemplate {
					t.Fatal(err)
				}
			}
			for _, path := range []string{IPv4LogPath, IPv6LogPath, AggregateLogPath} {
				data, _ := os.ReadFile(s.path(path))
				want := "старые данные\n"
				if failure == "fresh" {
					want = ""
				}
				if !strings.HasPrefix(string(data), want) || (path == AggregateLogPath && string(data) != want) {
					t.Fatalf("изменён %s", path)
				}
			}
			if failure != "" && failure != "fresh" {
				config, _ := os.ReadFile(s.path(RsyslogConfigPath))
				if string(config) != "прежний конфиг\n" {
					t.Fatal("при сбое не восстановлен конфиг")
				}
				t.Setenv("REPAIR_FAIL", "")
				if err := s.Refresh(); err != nil {
					t.Fatalf("повтор после сбоя: %v", err)
				}
			}
		})
	}
}

func TestLoggingConfigBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rsyslog.conf")
	if err := os.WriteFile(path, []byte("custom"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := writeLoggingConfig(path, []byte("fixed")); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path + ".before-repair")
	if err != nil || string(data) != "custom" {
		t.Fatal(string(data), err)
	}
}
