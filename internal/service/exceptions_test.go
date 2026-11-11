package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExceptionValidation(t *testing.T) {
	for _, input := range [][3]string{{"192.0.2.10", "TCP", "443"}, {"2001:db8::10", "udp", "65535"}} {
		if _, err := ParseException(input[0], input[1], input[2]); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range [][3]string{{"192.0.2.0/24", "tcp", "443"}, {"host", "tcp", "443"}, {"fe80::1%eth0", "tcp", "443"}, {"::ffff:192.0.2.10", "tcp", "443"}, {"192.0.2.10", "icmp", "443"}, {"192.0.2.10", "tcp", "0"}, {"192.0.2.10", "udp", "65536"}, {"192.0.2.10;id", "tcp", "443"}} {
		if _, err := ParseException(input[0], input[1], input[2]); err == nil {
			t.Fatalf("accepted %v", input)
		}
	}
}

func TestExceptionStorageAndRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exceptions.json")
	if entries, err := LoadExceptions(path); err != nil || len(entries) != 0 {
		t.Fatal(entries, err)
	}
	data := `[{"ip":"192.0.2.10","protocol":"tcp","port":443},{"ip":"2001:db8::10","protocol":"udp","port":53}]`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := LoadExceptions(path)
	if err != nil {
		t.Fatal(err)
	}
	v4, v6 := exceptionLines(entries, IPv4), exceptionLines(entries, IPv6)
	if !strings.Contains(v4, "-s 192.0.2.10 -p tcp --dport 443") || strings.Contains(v4, "2001:") || !strings.Contains(v6, "-s 2001:db8::10 -p udp --dport 53") {
		t.Fatal(v4, v6)
	}
	if strings.Contains(v4+v6, "ACCEPT") || strings.Count(v4+v6, "-j RETURN") != 2 {
		t.Fatal(v4, v6)
	}
	if err := os.WriteFile(path, []byte(`[{"ip":"192.0.2.10","protocol":"tcp","port":443},{"ip":"192.0.2.10","protocol":"TCP","port":443}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExceptions(path); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := os.WriteFile(path, []byte(`broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExceptions(path); err == nil {
		t.Fatal("corrupt file accepted")
	}
}
