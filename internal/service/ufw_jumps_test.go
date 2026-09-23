package service

import (
	"errors"
	"strings"
	"testing"
)

type failingJumpCommands struct {
	fakeFirewall
	failAt int
}

func (f *failingJumpCommands) RunOutput(name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(f.calls) == f.failAt {
		return "", errors.New("synthetic jump failure")
	}
	return "-N " + args[1] + "\n-A " + args[1] + " -j SCANNERS-BLOCK\n", nil
}

func TestVerifyUFWJumpsPropagatesEveryFailure(t *testing.T) {
	for failAt := 1; failAt <= 2; failAt++ {
		cmd := &failingJumpCommands{failAt: failAt}
		if err := verifyUFWJumps(cmd); err == nil || !strings.Contains(err.Error(), "synthetic jump failure") {
			t.Fatalf("command %d: expected failure, got %v", failAt, err)
		}
		if len(cmd.calls) != failAt {
			t.Fatalf("continued after failed command %d: %v", failAt, cmd.calls)
		}
	}
}

func TestVerifyUFWJumpsBothFamilies(t *testing.T) {
	cmd := &failingJumpCommands{}
	if err := verifyUFWJumps(cmd); err != nil {
		t.Fatal(err)
	}
	if len(cmd.calls) != 2 || cmd.calls[0] != "iptables -S ufw-before-input" || cmd.calls[1] != "ip6tables -S ufw6-before-input" {
		t.Fatalf("missing jump: %v", cmd.calls)
	}
}

func TestVerifyUFWJumpsRejectsLateOrMissingJump(t *testing.T) {
	for _, output := range []string{"", "-N ufw-before-input\n", "-A ufw-before-input -j ACCEPT\n-A ufw-before-input -j SCANNERS-BLOCK\n"} {
		if err := verifyUFWJumps(&fakeFirewall{status: output}); err == nil {
			t.Fatalf("accepted missing or late jump: %q", output)
		}
	}
}

func TestUFWRecoveryReportsRestoreAndReloadFailures(t *testing.T) {
	cmd := &fakeFirewall{fail: true}
	fileErr := errors.New("disk failure")
	err := rollbackUFW(cmd, true, func() error { return fileErr })
	if !errors.Is(err, fileErr) || !strings.Contains(err.Error(), "UFW rollback reload failed") {
		t.Fatalf("lost rollback error: %v", err)
	}
	if len(cmd.calls) != 1 || cmd.calls[0] != "ufw reload" {
		t.Fatalf("unexpected recovery: %v", cmd.calls)
	}
}

func TestUFWRecoveryVerifiesActiveStatus(t *testing.T) {
	cmd := &fakeFirewall{status: "Status: inactive"}
	err := rollbackUFW(cmd, true, func() error { return nil })
	if err == nil {
		t.Fatal("accepted inactive UFW after rollback")
	}
}

func TestUFWRecoveryRestoresFilesBeforeReload(t *testing.T) {
	cmd := &fakeFirewall{status: "Status: active"}
	restored := false
	err := rollbackUFW(cmd, true, func() error {
		if len(cmd.calls) != 0 {
			t.Fatal("reloaded before restoring files")
		}
		restored = true
		return nil
	})
	if err != nil || !restored || len(cmd.calls) != 1 {
		t.Fatalf("incomplete recovery: %v, %v", err, cmd.calls)
	}
}

func TestUFWRecoveryDoesNotEnableInitiallyInactiveFirewall(t *testing.T) {
	cmd := &fakeFirewall{}
	err := rollbackUFW(cmd, false, func() error { return nil })
	if err != nil || len(cmd.calls) != 0 {
		t.Fatalf("unexpected recovery commands: %v, %v", err, cmd.calls)
	}
}
