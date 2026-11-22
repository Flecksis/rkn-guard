package service

import (
	"os"
	"os/exec"
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
			t.Setenv("TEST_LOG_DIR", s.path("/var/log"))
			for _, command := range []string{"iptables", "ip6tables"} {
				write(command, `test "$3" = "-I" || exit 0
for arg do prefix="$arg"; done
case "$prefix" in *ANTISCAN-v4:*) family=4;; *) family=6;; esac
echo "${prefix}IN=lo SRC=localhost" >> "$TEST_LOG_DIR/iptables-scanners-ipv$family.log"
`)
			}
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
			err := s.Refresh("iptables")
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
				if err := s.Refresh("iptables"); err != nil {
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
				if err := s.Refresh("iptables"); err != nil {
					t.Fatalf("повтор после сбоя: %v", err)
				}
			}
		})
	}
}

func TestLoggingConfigBackup(t *testing.T) {
	s := &LoggingService{root: t.TempDir()}
	path := s.path("rsyslog.conf")
	if err := os.WriteFile(path, []byte("custom"), 0644); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.writeLoggingConfig(path, []byte("fixed")); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(s.path("/var/backups/rkn-guard/rsyslog.conf.before-repair"))
	if err != nil || string(data) != "custom" {
		t.Fatal(string(data), err)
	}
}

func TestLogrotateLegacyBackup(t *testing.T) {
	s := &LoggingService{root: t.TempDir()}
	path := s.path(LogrotateConfigPath)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	data := []byte(s.path("test.log") + " {\n    missingok\n}\n")
	if err := os.WriteFile(s.path("test.log"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, path + ".before-repair"} {
		if err := os.WriteFile(name, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	config := s.path("logrotate.conf")
	if err := os.WriteFile(config, []byte("include "+filepath.Dir(path)+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	check := func() ([]byte, error) {
		cmd := exec.Command("logrotate", "-d", "-s", "/dev/null", config)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		return cmd.CombinedOutput()
	}
	_, lookupErr := exec.LookPath("logrotate")
	if lookupErr == nil {
		if out, err := check(); err == nil || !strings.Contains(string(out), "duplicate log entry") {
			t.Fatalf("expected duplicate log entry: %v: %s", err, out)
		}
	}
	for i := 0; i < 2; i++ {
		if err := s.writeLoggingConfig(path, data); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path + ".before-repair"); !os.IsNotExist(err) {
		t.Fatalf("legacy backup still present: %v", err)
	}
	saved, err := os.ReadFile(s.path("/var/backups/rkn-guard/iptables-scanners.before-repair"))
	if err != nil || string(saved) != string(data) {
		t.Fatalf("backup: %q, %v", saved, err)
	}
	t.Run("logrotate", func(t *testing.T) {
		if lookupErr != nil {
			t.Skip("logrotate unavailable")
		}
		if out, err := check(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	})
}
