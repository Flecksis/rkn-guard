package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog"
)

// CommandService запускает системные команды.
type CommandService struct {
	logger zerolog.Logger
}

// NewCommandService создаёт исполнитель команд.
func NewCommandService(logger zerolog.Logger) *CommandService {
	return &CommandService{
		logger: logger,
	}
}

// Run запускает команду и возвращает ошибку при сбое.
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

// RunOutput запускает команду и возвращает её вывод.
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

// RunQuiet не пишет ошибки в журнал; это удобно для проверок наличия.
func (s *CommandService) RunQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// RunOutputQuiet возвращает вывод без записи ошибок в журнал.
func (s *CommandService) RunOutputQuiet(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// RunShell запускает команду через sh -c.
func (s *CommandService) RunShell(command string) error {
	s.logger.Debug().
		Str("shell_command", command).
		Msg("Executing shell command")

	return s.Run("sh", "-c", command)
}

// RunShellOutput запускает команду в оболочке и возвращает вывод.
func (s *CommandService) RunShellOutput(command string) (string, error) {
	s.logger.Debug().
		Str("shell_command", command).
		Msg("Executing shell command with output")

	return s.RunOutput("sh", "-c", command)
}

// CommandExists ищет команду в PATH.
func (s *CommandService) CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	exists := err == nil

	s.logger.Debug().
		Str("command", name).
		Bool("exists", exists).
		Msg("Checking command existence")

	return exists
}

// IsServiceActive проверяет, запущен ли сервис systemd.
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

// IsServiceEnabled проверяет, включён ли автозапуск сервиса.
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

// EnableService включает автозапуск сервиса.
func (s *CommandService) EnableService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Enabling service")

	return s.Run("systemctl", "enable", serviceName)
}

// StartService запускает сервис.
func (s *CommandService) StartService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Starting service")

	return s.Run("systemctl", "start", serviceName)
}

// StopService останавливает сервис.
func (s *CommandService) StopService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Stopping service")

	return s.Run("systemctl", "stop", serviceName)
}

// DisableService отключает автозапуск сервиса.
func (s *CommandService) DisableService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Disabling service")

	return s.Run("systemctl", "disable", serviceName)
}

// RestartService перезапускает сервис.
func (s *CommandService) RestartService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Restarting service")

	return s.Run("systemctl", "restart", serviceName)
}

// ReloadService просит сервис перечитать настройки.
func (s *CommandService) ReloadService(serviceName string) error {
	s.logger.Info().
		Str("service", serviceName).
		Msg("Reloading service")

	return s.Run("systemctl", "reload", serviceName)
}

// DaemonReload просит systemd перечитать файлы сервисов.
func (s *CommandService) DaemonReload() error {
	s.logger.Info().Msg("Reloading systemd daemon")
	return s.Run("systemctl", "daemon-reload")
}

// IsPackageInstalled проверяет наличие пакета в Debian и Ubuntu.
func (s *CommandService) IsPackageInstalled(packageName string) bool {
	if !s.CommandExists("dpkg") {
		return false
	}

	output, err := s.RunOutput("dpkg", "-l", packageName)
	if err != nil {
		return false
	}

	// У установленных пакетов строка начинается с ii.
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "ii") && strings.Contains(line, packageName) {
			return true
		}
	}

	return false
}
