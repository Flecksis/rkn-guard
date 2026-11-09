package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestLoggingRepair(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	for _, failure := range []string{"", "fresh", "apt", "restart rsyslog", "is-active --quiet rsyslog", "start antiscan-aggregate.timer", "rsyslogd"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			for _, dir := range []string{"bin", "var/log", "etc/logrotate.d", "etc/systemd/system", "usr/local/bin"} {
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
			for _, path := range []string{IPv4LogPath, IPv6LogPath, AggregateLogPath, AggregateLogsTimerPath} {
				if failure == "fresh" {
					continue
				}
				if err := os.WriteFile(s.path(path), []byte("старые данные\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			err := s.Refresh()
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
				if string(data) != want {
					t.Fatalf("изменён %s", path)
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
