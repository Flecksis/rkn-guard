package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// fakeIptables — in-memory netfilter: позволяет проверить, что при сбое IPv6
// изменения IPv4 откатываются и не остаётся состояния «v4 есть, v6 нет».
type fakeIptables struct {
	exists map[IPVersion]bool
	input  map[IPVersion]bool
	rules  map[IPVersion][][]string
	fail   map[string]bool
	calls  []string
}

func newFakeIptables() *fakeIptables {
	return &fakeIptables{
		exists: map[IPVersion]bool{},
		input:  map[IPVersion]bool{},
		rules:  map[IPVersion][][]string{},
		fail:   map[string]bool{},
	}
}

func (f *fakeIptables) note(op string, v IPVersion) error {
	f.calls = append(f.calls, string(v)+"/"+op)
	if f.fail[string(v)+"/"+op] {
		return errForced
	}
	return nil
}

var errForced = errors.New("forced failure")

func (f *fakeIptables) ChainExists(v IPVersion, _ Table, _ string) bool { return f.exists[v] }

func (f *fakeIptables) CreateChain(v IPVersion, _ Table, _ string) error {
	if err := f.note("CreateChain", v); err != nil {
		return err
	}
	f.exists[v] = true
	return nil
}

func (f *fakeIptables) DeleteChain(v IPVersion, _ Table, _ string) error {
	if err := f.note("DeleteChain", v); err != nil {
		return err
	}
	delete(f.exists, v)
	f.rules[v] = nil
	return nil
}

func (f *fakeIptables) FlushChain(v IPVersion, _ Table, _ string) error {
	if err := f.note("FlushChain", v); err != nil {
		return err
	}
	f.rules[v] = nil
	return nil
}

func (f *fakeIptables) RuleExists(v IPVersion, _ Table, chain string, spec []string) bool {
	if chain == string(ChainInput) {
		return f.input[v]
	}
	return false
}

func (f *fakeIptables) AppendRule(v IPVersion, _ Table, _ string, spec []string) error {
	if err := f.note("AppendRule", v); err != nil {
		return err
	}
	f.rules[v] = append(f.rules[v], spec)
	return nil
}

func (f *fakeIptables) InsertRule(v IPVersion, _ Table, _ string, _ int, spec []string) error {
	if err := f.note("InsertRule", v); err != nil {
		return err
	}
	f.rules[v] = append(f.rules[v], spec)
	return nil
}

func (f *fakeIptables) DeleteRule(v IPVersion, _ Table, _ string, _ []string) error {
	return f.note("DeleteRule", v)
}

func (f *fakeIptables) DeleteRuleByNumber(v IPVersion, _ Table, _ string, _ int) error {
	return f.note("DeleteRuleByNumber", v)
}

func (f *fakeIptables) Save(v IPVersion, _ string) error { return f.note("Save", v) }

func (f *fakeIptables) LinkChainToInput(v IPVersion, _ string, _ int) error {
	if err := f.note("LinkChainToInput", v); err != nil {
		return err
	}
	f.input[v] = true
	return nil
}

func (f *fakeIptables) UnlinkChainFromInput(v IPVersion, _ string) error {
	if err := f.note("UnlinkChainFromInput", v); err != nil {
		return err
	}
	f.input[v] = false
	return nil
}

func (f *fakeIptables) ListChainRules(v IPVersion, _ Table, _ string) (string, error) {
	var b strings.Builder
	for _, rule := range f.rules[v] {
		b.WriteString("-A " + chainName + " " + strings.Join(rule, " ") + "\n")
	}
	return b.String(), nil
}

func newTestIptablesService(t *testing.T, fake *fakeIptables) *IptablesService {
	t.Helper()
	t.Setenv("PATH", t.TempDir()) // ufw недоступен: правила идут напрямую в INPUT
	return &IptablesService{
		logger:      zerolog.Nop(),
		cmdSvc:      NewCommandService(zerolog.Nop()),
		iptablesCmd: fake,
	}
}

func TestSetupChainRollsBackIPv4WhenIPv6Fails(t *testing.T) {
	fake := newFakeIptables()
	fake.fail[string(IPv6)+"/AppendRule"] = true // падает на DROP-правиле IPv6
	s := newTestIptablesService(t, fake)

	if err := s.SetupChain(); err == nil {
		t.Fatal("ожидалась ошибка настройки IPv6")
	}
	if fake.exists[IPv4] || fake.exists[IPv6] {
		t.Fatalf("цепочка осталась: v4=%v v6=%v", fake.exists[IPv4], fake.exists[IPv6])
	}
	if fake.input[IPv4] || fake.input[IPv6] {
		t.Fatalf("привязка к INPUT осталась: v4=%v v6=%v", fake.input[IPv4], fake.input[IPv6])
	}
	if len(fake.rules[IPv4]) != 0 || len(fake.rules[IPv6]) != 0 {
		t.Fatalf("правила остались: v4=%v v6=%v", fake.rules[IPv4], fake.rules[IPv6])
	}
}

func TestSetupChainRestoresPreExistingIPv4Chain(t *testing.T) {
	fake := newFakeIptables()
	fake.exists[IPv4] = true
	oldRule := []string{"-m", "set", "--match-set", ipsetV4Name, "src", "-j", "RETURN"}
	fake.rules[IPv4] = [][]string{oldRule}
	fake.fail[string(IPv6)+"/CreateChain"] = true
	s := newTestIptablesService(t, fake)

	if err := s.SetupChain(); err == nil {
		t.Fatal("ожидалась ошибка настройки IPv6")
	}
	if !fake.exists[IPv4] {
		t.Fatal("существовавшая до установки цепочка IPv4 удалена")
	}
	if len(fake.rules[IPv4]) != 1 || strings.Join(fake.rules[IPv4][0], " ") != strings.Join(oldRule, " ") {
		t.Fatalf("прежние правила IPv4 не восстановлены: %v", fake.rules[IPv4])
	}
	if fake.input[IPv4] {
		t.Fatal("привязка IPv4 к INPUT не снята")
	}
}

func TestSetupChainAppliesBothFamilies(t *testing.T) {
	fake := newFakeIptables()
	s := newTestIptablesService(t, fake)

	if err := s.SetupChain(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []IPVersion{IPv4, IPv6} {
		if !fake.exists[v] || !fake.input[v] || len(fake.rules[v]) == 0 {
			t.Fatalf("%s: набор не применён (exists=%v input=%v rules=%d)", v, fake.exists[v], fake.input[v], len(fake.rules[v]))
		}
	}
}
