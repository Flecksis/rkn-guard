package service

import (
	"fmt"
	"strings"
)

type firewallCommands interface {
	Run(string, ...string) error
	RunOutput(string, ...string) (string, error)
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
