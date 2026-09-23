package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/rs/zerolog"
)

// InstallerService устанавливает системные пакеты.
type InstallerService struct {
	logger zerolog.Logger
}

// NewInstallerService создаёт сервис установки.
func NewInstallerService(logger zerolog.Logger) *InstallerService {
	return &InstallerService{
		logger: logger,
	}
}

// EnsureDependencies проверяет и устанавливает зависимости.
func (s *InstallerService) EnsureDependencies() error {
	s.logger.Info().Msg("Проверка зависимостей")

	distro := getDistroType()
	s.logger.Debug().Str("distro", distro).Msg("Detected distribution")

	// Проверяем iptables.
	if !s.commandExists("iptables") {
		s.logger.Info().Msg("Установка iptables")
		if err := s.installPackage("iptables", distro); err != nil {
			return fmt.Errorf("failed to install iptables: %w", err)
		}
		s.logger.Info().Msg("iptables установлен")
	} else {
		s.logger.Debug().Msg("iptables уже установлен")
	}

	// Проверяем ip6tables.
	if !s.commandExists("ip6tables") {
		s.logger.Info().Msg("Установка ip6tables")
		if err := s.installPackage("ip6tables", distro); err != nil {
			return fmt.Errorf("failed to install ip6tables: %w", err)
		}
		s.logger.Info().Msg("ip6tables установлен")
	} else {
		s.logger.Debug().Msg("ip6tables уже установлен")
	}

	// Проверяем ipset.
	if !s.commandExists("ipset") {
		s.logger.Info().Msg("Установка ipset")

		// Сначала пробуем установить пакет без обновления индекса.
		err := s.installPackage("ipset", distro)
		if err != nil {
			// При ошибке в Debian обновляем индекс пакетов.
			if distro == "debian" {
				s.logger.Warn().Msg("Попытка обновления apt-get")
				if err := s.runCommand("apt-get", "update"); err != nil {
					return fmt.Errorf("failed to update apt-get: %w", err)
				}
				// Повторяем установку после обновления.
				if err := s.installPackage("ipset", distro); err != nil {
					return fmt.Errorf("failed to install ipset: %w", err)
				}
			} else {
				return fmt.Errorf("failed to install ipset: %w", err)
			}
		}
		s.logger.Info().Msg("ipset установлен")
	} else {
		s.logger.Debug().Msg("ipset уже установлен")
	}

	s.logger.Info().Msg("Все зависимости удовлетворены")
	return nil
}

// EnsureNetfilterPersistent при необходимости устанавливает netfilter-persistent.
func (s *InstallerService) EnsureNetfilterPersistent() error {
	s.logger.Info().Msg("Проверка системы сохранения правил")

	distro := getDistroType()

	// Этот способ подходит только для систем на базе Debian.
	if distro != "debian" {
		s.logger.Debug().Msg("netfilter-persistent доступен только для Debian-based систем")
		return nil
	}

	// Проверяем, установлен ли UFW.
	if s.commandExists("ufw") {
		s.logger.Info().Msg("UFW обнаружен - netfilter-persistent не требуется")
		s.logger.Debug().Msg("UFW будет управлять сохранением правил")
		return nil
	}

	// Проверяем, установлен ли netfilter-persistent.
	if s.commandExists("netfilter-persistent") {
		s.logger.Debug().Msg("netfilter-persistent уже установлен")
		return nil
	}

	s.logger.Info().Msg("UFW не найден - установка netfilter-persistent и iptables-persistent")

	// Сначала обновляем индекс пакетов.
	if err := s.runCommand("apt-get", "update"); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось обновить apt-get")
	}

	// Отключаем интерактивные вопросы установщика.
	os.Setenv("DEBIAN_FRONTEND", "noninteractive")

	// Устанавливаем оба пакета.
	if err := s.runCommand("apt-get", "install", "-y", "netfilter-persistent", "iptables-persistent"); err != nil {
		return fmt.Errorf("failed to install netfilter-persistent: %w", err)
	}

	s.logger.Info().Msg("netfilter-persistent и iptables-persistent установлены")
	return nil
}

// installPackage выбирает способ установки для дистрибутива.
func (s *InstallerService) installPackage(pkg, distro string) error {
	s.logger.Debug().Str("package", pkg).Str("distro", distro).Msg("Installing package")

	switch distro {
	case "debian":
		return s.runCommand("apt-get", "install", "-y", pkg)
	case "redhat":
		return s.runCommand("yum", "install", "-y", pkg)
	default:
		return fmt.Errorf("unsupported distribution. Please install %s manually", pkg)
	}
}

// commandExists ищет команду в PATH.
func (s *InstallerService) commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// runCommand запускает команду с ограничением времени.
func (s *InstallerService) runCommand(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("command timed out: %s %v", name, args)
	}

	if err != nil {
		s.logger.Debug().
			Str("command", name).
			Strs("args", args).
			Str("output", string(output)).
			Err(err).
			Msg("Command failed")
		return err
	}

	return nil
}

// getDistroType определяет семейство дистрибутива.
func getDistroType() string {
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		return "debian"
	}
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		return "redhat"
	}
	return "unknown"
}

// CheckRootPrivileges проверяет права root.
func (s *InstallerService) CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must be run as root (use sudo)")
	}
	return nil
}
