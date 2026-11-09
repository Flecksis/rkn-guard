package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestRestoreServiceErrors(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nif [ \"$1\" = \"$FAIL_COMMAND\" ]; then echo failed >&2; exit 1; fi\n"), 0755)
	s := NewIpsetService(zerolog.Nop(), NewCommandService(zerolog.Nop()))
	for _, failure := range []string{"daemon-reload", "enable", ""} {
		t.Setenv("FAIL_COMMAND", failure)
		err := s.createRestoreService(filepath.Join(dir, "restore.service"))
		if (err != nil) != (failure != "") {
			t.Fatalf("%s: %v", failure, err)
		}
	}
}

func TestRepeatedChainSetupDoesNotFlush(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux commands")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("CALLS", filepath.Join(dir, "calls"))
	script := `#!/bin/sh
echo "$*" >> "$CALLS"
case " $* " in
    *" -C "*) test "$FAIL_INSERT" != yes ;;
    *" -I "*) exit 1 ;;
    *" -F "*|*" -X "*) exit 99 ;;
    *) exit 0 ;;
esac
`
	for _, binary := range []string{"iptables", "ip6tables"} {
		os.WriteFile(filepath.Join(dir, binary), []byte(script), 0755)
	}
	s := NewIptablesService(zerolog.Nop(), NewCommandService(zerolog.Nop()), true)
	for _, failure := range []string{"", "yes"} {
		t.Setenv("FAIL_INSERT", failure)
		for _, version := range []IPVersion{IPv4, IPv6} {
			err := s.setupVersionChain(version, ipsetV4Name, false)
			if (err != nil) != (failure == "yes") {
				t.Fatalf("%s: %v", failure, err)
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Contains(string(data), " -F ") || strings.Contains(string(data), " -X ") {
		t.Fatal(string(data))
	}
}
