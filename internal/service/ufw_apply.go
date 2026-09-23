package service

import (
	"errors"
	"fmt"
	"strings"
)

func rollbackUFW(cmd firewallCommands, reload bool, restoreFiles func() error) error {
	err := restoreFiles()
	if err != nil {
		err = fmt.Errorf("restore UFW files: %w", err)
	}
	if reload {
		if applyErr := applyUFW(cmd, true); applyErr != nil {
			err = errors.Join(err, fmt.Errorf("UFW rollback reload failed: %w", applyErr))
		}
	}
	return err
}

type firewallCommands interface {
	Run(string, ...string) error
	RunOutput(string, ...string) (string, error)
}

// Ошибка проверки должна запустить откат в saveWithUFW.
func verifyUFWJumps(cmd firewallCommands) error {
	for _, rule := range []struct{ binary, chain string }{
		{"iptables", "ufw-before-input"},
		{"ip6tables", "ufw6-before-input"},
	} {
		output, err := cmd.RunOutput(rule.binary, "-S", rule.chain)
		if err != nil {
			return fmt.Errorf("verify %s jump: %w", rule.binary, err)
		}
		first := ""
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A ") {
				first = line
				break
			}
		}
		if first != "-A "+rule.chain+" -j "+chainName {
			return fmt.Errorf("%s: SCANNERS-BLOCK is not the first rule", rule.chain)
		}
	}
	return nil
}

func applyUFW(cmd firewallCommands, wasActive bool) error {
	args := []string{"reload"}
	if !wasActive {
		args = []string{"--force", "enable"}
	}
	if err := cmd.Run("ufw", args...); err != nil {
		return fmt.Errorf("apply UFW rules: %w", err)
	}
	status, err := cmd.RunOutput("ufw", "status")
	if err != nil {
		return fmt.Errorf("verify UFW: %w", err)
	}
	if !strings.Contains(status, "Status: active") {
		return fmt.Errorf("UFW is not active after applying rules")
	}
	return nil
}
