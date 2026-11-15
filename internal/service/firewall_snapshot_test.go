package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// scriptedFirewall — фейковый исполнитель команд с ответами по имени команды.
type scriptedFirewall struct {
	calls   []string
	outputs map[string]string
	fail    map[string]error
	onRun   func(name string, args []string)
}

func newScriptedFirewall() *scriptedFirewall {
	return &scriptedFirewall{outputs: map[string]string{}, fail: map[string]error{}}
}

func (f *scriptedFirewall) key(name string, args []string) string {
	if len(args) == 0 {
		return name
	}
	return name + " " + strings.Join(args, " ")
}

func (f *scriptedFirewall) Run(name string, args ...string) error {
	f.calls = append(f.calls, f.key(name, args))
	if f.onRun != nil {
		f.onRun(name, args)
	}
	return f.fail[f.key(name, args)]
}

func (f *scriptedFirewall) RunOutput(name string, args ...string) (string, error) {
	key := f.key(name, args)
	if err := f.fail[key]; err != nil {
		return "", err
	}
	return f.outputs[key], nil
}

func (f *scriptedFirewall) called(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *scriptedFirewall) countCalls(substr string) int {
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// fakeRoot создаёт временный корень и возвращает путь к нему.
func fakeRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func writeFake(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFake(t *testing.T, root, path string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

const (
	fakeBeforeRules   = "# ufw before.rules\n*filter\n:ufw-before-input - [0:0]\n-A ufw-before-input -j LOG\nCOMMIT\n"
	fakeDefaultUFW    = "DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_FORWARD_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\n"
	snapshotIPTables  = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	installedIPTables = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n" +
		":SCANNERS-BLOCK - [0:0]\n:DOCKER-USER - [0:0]\n" +
		"-A INPUT -j ufw-before-input\n-A INPUT -j SCANNERS-BLOCK\n-A DOCKER-USER -j RETURN\nCOMMIT\n"
)

// newFakeSnapshotter собирает Snapshotter поверх временного корня.
func newFakeSnapshotter(t *testing.T, fw *scriptedFirewall) (*Snapshotter, string) {
	t.Helper()
	root := fakeRoot(t)
	writeFake(t, root, "/etc/ufw/before.rules", fakeBeforeRules)
	writeFake(t, root, "/etc/ufw/before6.rules", fakeBeforeRules)
	writeFake(t, root, "/etc/default/ufw", fakeDefaultUFW)

	fw.outputs["ufw status"] = "Status: inactive\n"
	fw.outputs["ufw status verbose"] = "Status: inactive\n"
	fw.outputs["ufw show added"] = "ufw allow ssh"
	// Фейк ведёт себя как настоящий ufw: disable/enable меняют статус.
	fw.onRun = func(name string, args []string) {
		if name != "ufw" {
			return
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "disable"):
			fw.outputs["ufw status"] = "Status: inactive\n"
		case strings.Contains(joined, "enable"), strings.Contains(joined, "reload"):
			fw.outputs["ufw status"] = "Status: active\n"
		}
	}
	fw.outputs["iptables-save"] = snapshotIPTables
	fw.outputs["ip6tables-save"] = snapshotIPTables
	fw.outputs["ipset save"] = ""
	for _, unit := range snapshotUnits {
		fw.outputs["systemctl is-enabled "+unit] = "disabled\n"
	}

	s := &Snapshotter{
		Cmd:      fw,
		Logger:   zerolog.Nop(),
		Dir:      "/var/lib/rkn-guard/snapshot",
		Root:     root,
		ExistsFn: func(string) bool { return true },
		Now:      func() time.Time { return time.Unix(1700000000, 0).UTC() },
	}
	if err := os.MkdirAll(filepath.Join(root, SnapshotDir), 0o700); err != nil {
		t.Fatal(err)
	}
	return s, root
}

// TestApplyUFWNeverEnablesFirewall — FIX-1: выключенный UFW не включается.
func TestApplyUFWNeverEnablesFirewall(t *testing.T) {
	fw := newScriptedFirewall()
	err := applyUFW(fw, false)
	if !errors.Is(err, ErrUFWInactive) {
		t.Fatalf("ожидалась ErrUFWInactive, получено %v", err)
	}
	if len(fw.calls) != 0 {
		t.Fatalf("при выключенном UFW не должно быть команд, выполнено: %v", fw.calls)
	}

	active := newScriptedFirewall()
	active.outputs["ufw status"] = "Status: active\n"
	if err := applyUFW(active, true); err != nil {
		t.Fatalf("активный UFW должен применяться reload'ом: %v", err)
	}
	if active.called("--force") || active.called("enable") {
		t.Fatalf("rkn-guard не должен включать UFW: %v", active.calls)
	}
	if active.countCalls("ufw reload") != 1 {
		t.Fatalf("ожидался один ufw reload, получено %v", active.calls)
	}
}

// TestPlanFirewallRefusesInactiveUFW — установка падает, firewall не меняется.
func TestPlanFirewallRefusesInactiveUFW(t *testing.T) {
	fw := newScriptedFirewall()
	fw.outputs["ufw status"] = "Status: inactive\n"
	exists := func(string) bool { return true }

	plan, err := PlanFirewall(fw, exists, false)
	if !errors.Is(err, ErrUFWInactive) {
		t.Fatalf("ожидалась ErrUFWInactive, получено %v", err)
	}
	if plan.CanWriteRules() {
		t.Fatal("правила некуда ставить, а план разрешает запись")
	}
	if len(fw.calls) != 0 {
		t.Fatalf("проверка не должна менять firewall, выполнено: %v", fw.calls)
	}

	fwActive := newScriptedFirewall()
	fwActive.outputs["ufw status"] = "Status: active\n"
	plan, err = PlanFirewall(fwActive, exists, false)
	if err != nil || !plan.CanWriteRules() {
		t.Fatalf("активный UFW должен разрешать запись: plan=%+v err=%v", plan, err)
	}

	noUFW := newScriptedFirewall()
	plan, err = PlanFirewall(noUFW, func(string) bool { return false }, false)
	if err != nil || !plan.CanWriteRules() {
		t.Fatalf("без UFW правила ставятся напрямую: plan=%+v err=%v", plan, err)
	}
}

// TestPlanFirewallObserveOnly — режим наблюдения не трогает firewall.
func TestPlanFirewallObserveOnly(t *testing.T) {
	fw := newScriptedFirewall()
	fw.outputs["ufw status"] = "Status: inactive\n"
	plan, err := PlanFirewall(fw, func(string) bool { return true }, true)
	if err != nil {
		t.Fatalf("observe-only не должен падать: %v", err)
	}
	if plan.CanWriteRules() || !plan.ObserveOnly {
		t.Fatalf("observe-only обязан запрещать запись: %+v", plan)
	}
	if len(fw.calls) != 0 {
		t.Fatalf("observe-only не должен менять систему: %v", fw.calls)
	}
}

// TestSnapshotRestoreReturnsBaseline — FIX-2: uninstall/rollback возвращает снимок.
func TestSnapshotRestoreReturnsBaseline(t *testing.T) {
	fw := newScriptedFirewall()
	s, root := newFakeSnapshotter(t, fw)

	snap, err := s.Save()
	if err != nil {
		t.Fatalf("снимок не создан: %v", err)
	}
	if snap.UFWWasActive() {
		t.Fatal("в снимке UFW должен быть выключен")
	}
	if !strings.Contains(snap.IPTablesV4, ":INPUT ACCEPT") {
		t.Fatalf("политика INPUT не попала в снимок: %q", snap.IPTablesV4)
	}

	// Имитируем установку: rkn-guard включил firewall и добавил правила.
	writeFake(t, root, "/etc/ufw/before.rules", fakeBeforeRules+
		"# SCANNERS-BLOCK chain - managed by antiscan\n-A ufw-before-input -j SCANNERS-BLOCK\n# END SCANNERS-BLOCK\n")
	fw.outputs["ufw status"] = "Status: active\n"
	fw.outputs["iptables-save"] = installedIPTables
	fw.calls = nil

	if err := s.RestoreFromDisk(); err != nil {
		t.Fatalf("откат не удался: %v", err)
	}

	if got := readFake(t, root, "/etc/ufw/before.rules"); got != fakeBeforeRules {
		t.Fatalf("before.rules не вернулся к снимку:\n%s", got)
	}
	if !fw.called("ufw --force disable") {
		t.Fatalf("UFW должен быть выключен обратно: %v", fw.calls)
	}
	if fw.called("ufw --force enable") || fw.countCalls("ufw enable") != 0 {
		t.Fatalf("включение UFW недопустимо: %v", fw.calls)
	}
	if !fw.called("iptables -P INPUT ACCEPT") {
		t.Fatalf("политика INPUT не восстановлена: %v", fw.calls)
	}
	if !fw.called("iptables -F SCANNERS-BLOCK") {
		t.Fatalf("цепочка rkn-guard не удалена: %v", fw.calls)
	}
	if fw.called("DOCKER-USER") {
		t.Fatalf("служебные цепочки Docker трогать нельзя: %v", fw.calls)
	}
	if err := s.Verify(snap); err != nil {
		t.Fatalf("состояние не совпало со снимком: %v", err)
	}
}

// TestSnapshotRestoreKeepsActiveUFW — если UFW был включён, откат делает reload.
func TestSnapshotRestoreKeepsActiveUFW(t *testing.T) {
	fw := newScriptedFirewall()
	s, root := newFakeSnapshotter(t, fw)
	fw.outputs["ufw status"] = "Status: active\n"
	fw.outputs["ufw status verbose"] = "Status: active\n"

	snap, err := s.Save()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.UFWWasActive() {
		t.Fatal("снимок должен фиксировать активный UFW")
	}
	writeFake(t, root, "/etc/ufw/before.rules", fakeBeforeRules+"# SCANNERS-BLOCK chain - managed by antiscan\n")
	fw.calls = nil

	if err := s.Restore(snap); err != nil {
		t.Fatalf("откат не удался: %v", err)
	}
	if fw.called("ufw --force disable") || fw.called("ufw disable") {
		t.Fatalf("активный UFW выключать нельзя: %v", fw.calls)
	}
	if !fw.called("ufw reload") {
		t.Fatalf("после отката нужен ufw reload: %v", fw.calls)
	}
}

// TestSnapshotRestoreIsIdempotent — повторный откат ничего не меняет.
func TestSnapshotRestoreIsIdempotent(t *testing.T) {
	fw := newScriptedFirewall()
	s, root := newFakeSnapshotter(t, fw)
	snap, err := s.Save()
	if err != nil {
		t.Fatal(err)
	}

	// Первый откат: система «после установки».
	writeFake(t, root, "/etc/ufw/before.rules", fakeBeforeRules+"# SCANNERS-BLOCK chain - managed by antiscan\n")
	fw.outputs["ufw status"] = "Status: active\n"
	if err := s.Restore(snap); err != nil {
		t.Fatalf("первый откат: %v", err)
	}
	firstDisables := fw.countCalls("ufw --force disable")
	if firstDisables != 1 {
		t.Fatalf("ожидалось одно выключение UFW, получено %d (%v)", firstDisables, fw.calls)
	}

	// Второй откат: состояние уже равно снимку.
	if err := s.Restore(snap); err != nil {
		t.Fatalf("второй откат: %v", err)
	}
	if fw.countCalls("ufw --force disable") != firstDisables {
		t.Fatalf("повторный откат не должен выключать UFW снова: %v", fw.calls)
	}
	if got := readFake(t, root, "/etc/ufw/before.rules"); got != fakeBeforeRules {
		t.Fatalf("файл изменился при повторном откате: %q", got)
	}
}

// TestRestoreWithoutSnapshot — без снимка откат честно отказывается.
func TestRestoreWithoutSnapshot(t *testing.T) {
	s, _ := newFakeSnapshotter(t, newScriptedFirewall())
	if err := os.RemoveAll(filepath.Join(s.Root, SnapshotDir)); err != nil {
		t.Fatal(err)
	}
	if s.Exists() {
		t.Fatal("снимка быть не должно")
	}
	if err := s.RestoreFromDisk(); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("ожидалась ErrNoSnapshot, получено %v", err)
	}
}

// TestSnapshotFormatReport — сводка не паникует и содержит состояние.
func TestSnapshotFormatReport(t *testing.T) {
	s, _ := newFakeSnapshotter(t, newScriptedFirewall())
	snap, err := s.Capture()
	if err != nil {
		t.Fatal(err)
	}
	report := FormatSnapshotReport(snap)
	if !strings.Contains(report, "UFW выключен") || !strings.Contains(report, "DEFAULT_INPUT_POLICY=DROP") {
		t.Fatalf("неожиданная сводка: %s", report)
	}
	if FormatSnapshotReport(nil) != "снимок отсутствует" {
		t.Fatal("nil-снимок должен описываться явно")
	}
}

// TestSnapshotPolicyParsing — политики берутся из iptables-save.
func TestSnapshotPolicyParsing(t *testing.T) {
	if got := snapshotChainPolicy(snapshotIPTables, "INPUT"); got != "ACCEPT" {
		t.Fatalf("политика INPUT распознана как %q", got)
	}
	if got := snapshotChainPolicy(installedIPTables, "FORWARD"); got != "DROP" {
		t.Fatalf("политика FORWARD распознана как %q", got)
	}
	if got := snapshotChainPolicy("", "INPUT"); got != "" {
		t.Fatalf("пустой ввод должен давать пустую политику, получено %q", got)
	}
	sets := snapshotSets("create SCANNERS-BLOCK-V4 hash:net family inet\n")
	if !sets["SCANNERS-BLOCK-V4"] || sets["RKN-NEXT4"] {
		t.Fatalf("наборы распознаны неверно: %v", sets)
	}
	_ = fmt.Sprint(sets)
}
