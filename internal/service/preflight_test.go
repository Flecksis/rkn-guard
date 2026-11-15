package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

type fakePreflight struct {
	bins    map[string]bool
	outputs map[string]string
	failRun map[string]error
	calls   []string
}

func (f *fakePreflight) Run(name string, args ...string) error {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err, ok := f.failRun[name]; ok {
		return err
	}
	return nil
}

func (f *fakePreflight) RunOutput(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if err, ok := f.failRun[name]; ok {
		return "", err
	}
	return f.outputs[name], nil
}

func (f *fakePreflight) exists(name string) bool { return f.bins[name] }

func TestIpsetPreflightRejectsMissingBinaryWithoutTouchingAnything(t *testing.T) {
	f := &fakePreflight{bins: map[string]bool{}}
	err := IpsetPreflight(f, f.exists)
	if !errors.Is(err, ErrIpsetUnavailable) {
		t.Fatalf("ожидался ErrIpsetUnavailable, получено %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("при отсутствии ipset не должно быть ни одной команды: %v", f.calls)
	}
}

func TestIpsetPreflightRejectsBrokenKernel(t *testing.T) {
	f := &fakePreflight{
		bins:    map[string]bool{"ipset": true, "modprobe": true},
		outputs: map[string]string{"lsmod": "Module Size Used by\nnf_tables 1\n"},
		failRun: map[string]error{
			"modprobe": errors.New("modprobe: FATAL: Module ip_set not found"),
			"ipset":    errors.New("ipset v7.15: Kernel error received: Operation not permitted"),
		},
	}
	err := IpsetPreflight(f, f.exists)
	if !errors.Is(err, ErrIpsetUnavailable) {
		t.Fatalf("ожидался ErrIpsetUnavailable, получено %v", err)
	}
	if !strings.Contains(err.Error(), "модуль ядра") {
		t.Fatalf("в ошибке нет состояния модуля: %v", err)
	}
	if !strings.Contains(err.Error(), "RKN-PREFLIGHT-") {
		t.Fatalf("в ошибке нет пробного набора: %v", err)
	}
}

func TestIpsetPreflightPassesWithLoadedModule(t *testing.T) {
	f := &fakePreflight{
		bins:    map[string]bool{"ipset": true},
		outputs: map[string]string{"lsmod": "Module Size Used by\nip_set 61440 3 ip_set_hash_net\nxt_set 16384 2\n"},
	}
	if err := IpsetPreflight(f, f.exists); err != nil {
		t.Fatalf("рабочий ipset отклонён: %v", err)
	}
	joined := strings.Join(f.calls, "\n")
	if !strings.Contains(joined, "ipset create RKN-PREFLIGHT-") || !strings.Contains(joined, "ipset destroy RKN-PREFLIGHT-") {
		t.Fatalf("не выполнена функциональная проба: %v", f.calls)
	}
}

func TestIpsetPreflightAcceptsBuiltinModule(t *testing.T) {
	// ip_set вкомпилирован в ядро: lsmod пуст, но ipset работает.
	f := &fakePreflight{
		bins:    map[string]bool{"ipset": true},
		outputs: map[string]string{"lsmod": "Module Size Used by\n"},
	}
	if err := IpsetPreflight(f, f.exists); err != nil {
		t.Fatalf("встроенный в ядро ip_set отклонён: %v", err)
	}
}

const ssSample = `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0          127.0.0.1:53        0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*     users:(("sshd",pid=712,fd=3))
tcp   LISTEN 0      128             [::]:22           [::]:*     users:(("sshd",pid=712,fd=4))
tcp   LISTEN 0      4096               *:2222            *:*     users:(("node",pid=900,fd=9))
tcp   LISTEN 0      128          127.0.0.1:443       0.0.0.0:*
`

func TestParseSSListeners(t *testing.T) {
	listeners := ParseSSListeners(ssSample)
	for _, want := range []int{22, 2222, 443, 53} {
		if _, ok := listeners[want]; !ok {
			t.Fatalf("порт %d не найден в %v", want, listeners)
		}
	}
	if listeners[2087] != "" {
		t.Fatalf("несуществующий порт найден: %v", listeners)
	}
	if listeners[2222] != "*" {
		t.Fatalf("адрес 2222: %q", listeners[2222])
	}
}

func TestCheckMandatoryPortsReportsAndProtectsSSH(t *testing.T) {
	report, err := CheckMandatoryPorts([]int{22, 2222, 443, 2443, 2087}, []int{22}, ssSample)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(report.ProtectedPorts()); got != "[22 443 2222]" {
		t.Fatalf("protected ports: %s", got)
	}
	if !strings.Contains(report.String(), "2443=absent") {
		t.Fatalf("отчёт не показывает отсутствующий порт: %s", report)
	}
}

func TestCheckMandatoryPortsRejectsUnverifiableSSH(t *testing.T) {
	_, err := CheckMandatoryPorts([]int{22}, []int{2087}, ssSample)
	if !errors.Is(err, ErrSSHUnverified) {
		t.Fatalf("ожидался ErrSSHUnverified, получено %v", err)
	}
}

func TestCheckMandatoryPortsRejectsEmptyList(t *testing.T) {
	if _, err := CheckMandatoryPorts(nil, []int{22}, ssSample); err == nil {
		t.Fatal("пустой список обязательных портов принят")
	}
}

func TestRulesMayBlockMandatoryPorts(t *testing.T) {
	setRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "DROP"}
	safePortRule := []string{"-p", "tcp", "--dport", "8080", "-j", "DROP"}
	dangerousPortRule := []string{"-p", "tcp", "--dport", "22", "-j", "DROP"}
	rangeRule := []string{"-p", "tcp", "--dport", "2000:3000", "-j", "REJECT"}
	blanket := []string{"-j", "DROP"}

	if got := RulesMayBlockMandatoryPorts([][]string{setRule, safePortRule}, []int{22, 2222}); len(got) != 0 {
		t.Fatalf("безопасные правила признаны опасными: %v", got)
	}
	for name, rule := range map[string][]string{"dport 22": dangerousPortRule, "range": rangeRule, "blanket": blanket} {
		if got := RulesMayBlockMandatoryPorts([][]string{rule}, []int{22, 2222}); len(got) != 1 {
			t.Fatalf("%s: правило не распознано как опасное: %v", name, got)
		}
	}
}

func TestPlannedRulesAreSetScoped(t *testing.T) {
	s := &IptablesService{enableLogging: true}
	for _, rule := range s.PlannedRules() {
		joined := strings.Join(rule, " ")
		if !strings.Contains(joined, "--match-set") && strings.Contains(joined, "DROP") {
			t.Fatalf("правило без привязки к набору: %s", joined)
		}
	}
	if got := RulesMayBlockMandatoryPorts(s.PlannedRules(), DefaultRequiredPorts); len(got) != 0 {
		t.Fatalf("план правил отрезает обязательные порты: %v", got)
	}
}

func TestSSHPortsFromEnv(t *testing.T) {
	env := map[string]string{"SSH_CONNECTION": "198.51.100.7 51000 10.0.0.5 2222"}
	got := SSHPortsFromEnv(func(k string) string { return env[k] })
	if fmt.Sprint(got) != "[22 2222]" {
		t.Fatalf("порты SSH: %v", got)
	}
	if got := SSHPortsFromEnv(func(string) string { return "" }); fmt.Sprint(got) != "[22]" {
		t.Fatalf("по умолчанию ожидался только 22: %v", got)
	}
}
