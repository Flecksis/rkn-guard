package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"
)

// CommandService provides centralized command execution
type CommandService struct {
	logger zerolog.Logger
}

// NewCommandService creates a new command service
func NewCommandService(logger zerolog.Logger) *CommandService {
	return &CommandService{
		logger: logger,
	}
}

// Run executes a command and returns error if it fails
func (s *CommandService) Run(name string, args ...string) error {
	s.logger.Debug().
		Str("command", name).
		Strs("args", args).
		Msg("Executing command")

	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		s.logger.Error().
			Err(err).
			Str("command", name).
			Strs("args", args).
			Str("stderr", stderr.String()).
			Msg("Command failed")
		return fmt.Errorf("command '%s %s' failed: %w: %s", name, strings.Join(args, " "), err, stderr.String())
	}

	return nil
}

// RunOutput executes a command and returns its output
func (s *CommandService) RunOutput(name string, args ...string) (string, error) {
	s.logger.Debug().
		Str("command", name).
		Strs("args", args).
		Msg("Executing command with output")

	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("command", name).
			Strs("args", args).
			Str("output", string(output)).
			Msg("Command failed")
		return "", fmt.Errorf("command '%s %s' failed: %w: %s", name, strings.Join(args, " "), err, string(output))
	}

	return string(output), nil
}

// RunQuiet executes a command without logging errors (useful for existence checks)
func (s *CommandService) RunQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// RunOutputQuiet executes a command and returns output without logging errors
func (s *CommandService) RunOutputQuiet(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// RunShell executes a shell command (sh -c "command")
func (s *CommandService) RunShell(command string) error {
	s.logger.Debug().
		Str("shell_command", command).
		Msg("Executing shell command")

	return s.Run("sh", "-c", command)
}

// RunShellOutput executes a shell command and returns output
func (s *CommandService) RunShellOutput(command string) (string, error) {
	s.logger.Debug().
		Str("shell_command", command).
		Msg("Executing shell command with output")

	return s.RunOutput("sh", "-c", command)
}

// CommandExists checks if a command is available in PATH
func (s *CommandService) CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	exists := err == nil

	s.logger.Debug().
		Str("command", name).
		Bool("exists", exists).
		Msg("Checking command existence")

	return exists
}

// IsServiceActive checks if a systemd service is active
func (s *CommandService) IsServiceActive(serviceName string) bool {
	if !s.CommandExists("systemctl") {
		return false
	}

	output, err := s.RunOutput("systemctl", "is-active", serviceName)
	if err != nil {
		return false
	}

	return strings.TrimSpace(output) == "active"
}

// IsServiceEnabled checks if a systemd service is enabled
func (s *CommandService) IsServiceEnabled(serviceName string) bool {
	if !s.CommandExists("systemctl") {
		return false
	}

	output, err := s.RunOutput("systemctl", "is-enabled", serviceName)
	if err != nil {
		return false
	}

	return strings.TrimSpace(output) == "enabled"
}

// EnableService enables a systemd service
func (s *CommandService) EnableService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Enabling service")

	return s.Run("systemctl", "enable", serviceName)
}

// StartService starts a systemd service
func (s *CommandService) StartService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Starting service")

	return s.Run("systemctl", "start", serviceName)
}

// StopService stops a systemd service
func (s *CommandService) StopService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Stopping service")

	return s.Run("systemctl", "stop", serviceName)
}

// DisableService disables a systemd service
func (s *CommandService) DisableService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Disabling service")

	return s.Run("systemctl", "disable", serviceName)
}

// RestartService restarts a systemd service
func (s *CommandService) RestartService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Restarting service")

	return s.Run("systemctl", "restart", serviceName)
}

// ReloadService reloads a systemd service
func (s *CommandService) ReloadService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Reloading service")

	return s.Run("systemctl", "reload", serviceName)
}

// DaemonReload reloads systemd daemon
func (s *CommandService) DaemonReload() error {
	s.logger.Info().Msg("Reloading systemd daemon")
	return s.Run("systemctl", "daemon-reload")
}

// IsPackageInstalled checks if a package is installed (Debian/Ubuntu)
func (s *CommandService) IsPackageInstalled(packageName string) bool {
	if !s.CommandExists("dpkg") {
		return false
	}

	output, err := s.RunOutput("dpkg", "-l", packageName)
	if err != nil {
		return false
	}

	// Check if package is installed (starts with "ii")
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "ii") && strings.Contains(line, packageName) {
			return true
		}
	}

	return false
}
