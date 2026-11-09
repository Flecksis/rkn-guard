package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// LoggingService настраивает сбор журналов.
type LoggingService struct {
	logger zerolog.Logger
	root   string
}

func (s *LoggingService) path(path string) string {
	if s.root == "" {
		return path
	}
	return filepath.Join(s.root, path)
}

// NewLoggingService создаёт сервис настройки журналов.
func NewLoggingService(logger zerolog.Logger) *LoggingService {
	return &LoggingService{
		logger: logger,
	}
}

// Setup настраивает rsyslog, ротацию и сбор статистики.
func (s *LoggingService) Setup() error {
	if err := s.ensureDependencies(); err != nil {
		return err
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return fmt.Errorf("statistics collector requires python3: %w", err)
	}
	s.logger.Info().Msg("Настройка логирования")

	// Создаём настройки rsyslog.
	if err := s.setupRsyslog(); err != nil {
		return fmt.Errorf("failed to setup rsyslog: %w", err)
	}

	// Создаём файлы журналов.
	if err := s.createLogFiles(); err != nil {
		return fmt.Errorf("failed to create log files: %w", err)
	}

	// Настраиваем ротацию журналов.
	if err := s.setupLogrotate(); err != nil {
		return fmt.Errorf("failed to setup logrotate: %w", err)
	}

	// Создаём скрипт сбора статистики.
	if err := s.setupAggregationScript(); err != nil {
		return fmt.Errorf("failed to setup aggregation script: %w", err)
	}

	// Сначала проверяем журнал, потом запускаем сборщик.
	if err := s.reloadRsyslog(); err != nil {
		return err
	}
	// Настраиваем периодический запуск.
	if err := s.setupCronJob(); err != nil {
		return fmt.Errorf("failed to setup cron job: %w", err)
	}

	s.logger.Info().Msg("Конфигурация логирования готова")
	s.logger.Info().Msg("  Сырые логи: /var/log/iptables-scanners-{ipv4,ipv6}.log")
	s.logger.Info().Msg("  Агрегированные: /var/log/iptables-scanners-aggregate.csv (с ASN/netname, обновляются каждые 30 сек)")
	s.logger.Info().Msg("  Rate limit: 10 entries/minute")
	s.logger.Info().Msg("  Проверить статус: systemctl status antiscan-aggregate.timer")

	return nil
}

// Refresh дожидается завершения старого сборщика перед заменой его скрипта.
// Старый сборщик нельзя прерывать после того, как он уже очистил логи.
func (s *LoggingService) Refresh() (result error) {
	if err := s.ensureDependencies(); err != nil {
		return err
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return err
	}
	if _, err := os.Stat(s.path(AggregateLogsTimerPath)); os.IsNotExist(err) {
		return s.Setup()
	}
	if err := exec.Command("systemctl", "stop", "antiscan-aggregate.timer").Run(); err != nil {
		return err
	}
	defer func() {
		if err := exec.Command("systemctl", "start", "antiscan-aggregate.timer").Run(); err != nil && result == nil {
			result = fmt.Errorf("не удалось запустить сборщик: %w", err)
		}
	}()
	deadline := time.Now().Add(5 * time.Minute)
	for {
		output, err := exec.Command("systemctl", "show", "--property=ActiveState", "--value", "antiscan-aggregate.service").Output()
		if err != nil {
			return err
		}
		state := strings.TrimSpace(string(output))
		if state != "active" && state != "activating" && state != "deactivating" {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("old statistics collector is still running; retry setup-logging later")
		}
		time.Sleep(time.Second)
	}
	return s.Setup()
}

// setupRsyslog создаёт настройки rsyslog.
func (s *LoggingService) setupRsyslog() error {
	if err := os.MkdirAll(s.path("/etc/rsyslog.d"), 0755); err != nil {
		return err
	}
	if err := writeLoggingConfig(s.path(RsyslogConfigPath), []byte(RsyslogConfigTemplate)); err != nil {
		return err
	}
	s.logger.Info().Str("path", s.path(RsyslogConfigPath)).Msg("Конфиг rsyslog создан")
	return nil
}

// createLogFiles создаёт журналы с нужными правами.
func (s *LoggingService) createLogFiles() error {
	return s.prepareLogFiles([]string{s.path(IPv4LogPath), s.path(IPv6LogPath)})
}

func (s *LoggingService) prepareLogFiles(logFiles []string) error {
	// Создаём пустые журналы и выставляем права.

	for _, logFile := range logFiles {
		{
			f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", logFile, err)
			}
			f.Close()

			// Выставляем права доступа.
			owner := "root:adm"
			if _, err := user.Lookup("syslog"); err == nil {
				owner = "syslog:adm"
			}
			if err := exec.Command("chown", owner, logFile).Run(); err != nil {
				return fmt.Errorf("не удалось исправить владельца %s: %w", logFile, err)
			}
			if err := exec.Command("chmod", "640", logFile).Run(); err != nil {
				return err
			}

			s.logger.Info().Str("file", logFile).Msg("Создан лог файл")
		}
	}

	return nil
}

// setupLogrotate создаёт настройки ротации.
func (s *LoggingService) setupLogrotate() error {
	if err := writeLoggingConfig(s.path(LogrotateConfigPath), []byte(LogrotateConfigTemplate)); err != nil {
		return err
	}

	s.logger.Info().Str("path", s.path(LogrotateConfigPath)).Msg("Создан logrotate конфиг")
	return nil
}

// setupAggregationScript создаёт скрипт сбора статистики.
func (s *LoggingService) setupAggregationScript() error {
	if err := os.WriteFile(s.path(AggregateLogsScriptPath), []byte(AggregateLogsScriptTemplate), 0755); err != nil {
		return fmt.Errorf("failed to write aggregator script: %w", err)
	}

	// Разрешаем запуск скрипта.
	if err := exec.Command("chmod", "+x", s.path(AggregateLogsScriptPath)).Run(); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	s.logger.Info().Str("path", s.path(AggregateLogsScriptPath)).Msg("Создан скрипт агрегирования логов")
	return nil
}

// setupCronJob создаёт таймер systemd с интервалом 30 секунд.
func (s *LoggingService) setupCronJob() error {
	// Создаём сервис systemd.
	if err := os.WriteFile(s.path(AggregateLogsServicePath), []byte(AggregateLogsServiceTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", s.path(AggregateLogsServicePath)).Msg("Создан systemd сервис")

	// Создаём таймер systemd.
	if err := os.WriteFile(s.path(AggregateLogsTimerPath), []byte(AggregateLogsTimerTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", s.path(AggregateLogsTimerPath)).Msg("Создан systemd timer")

	// Просим systemd перечитать файлы сервисов.
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return err
	}

	// Включаем и запускаем таймер.
	if err := exec.Command("systemctl", "enable", "antiscan-aggregate.timer").Run(); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "start", "antiscan-aggregate.timer").Run(); err != nil {
		return err
	}

	if err := exec.Command("systemctl", "is-active", "--quiet", "antiscan-aggregate.timer").Run(); err != nil {
		return err
	}
	s.logger.Info().Msg("Systemd timer включен и запущен (каждые 30 секунд)")
	return nil
}

// reloadRsyslog перезапускает rsyslog.
func (s *LoggingService) reloadRsyslog() error {
	if output, err := exec.Command("rsyslogd", "-N1").CombinedOutput(); err != nil {
		return fmt.Errorf("ошибка настройки rsyslog: %s: %w", output, err)
	}
	if err := exec.Command("systemctl", "enable", "rsyslog").Run(); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "restart", "rsyslog").Run(); err != nil {
		return err
	}
	if err := exec.Command("systemctl", "is-active", "--quiet", "rsyslog").Run(); err != nil {
		return fmt.Errorf("rsyslog не работает: %w", err)
	}
	s.logger.Info().Msg("Rsyslog перезапущен")
	return nil
}

func (s *LoggingService) ensureDependencies() error {
	installer := NewInstallerService(s.logger)
	for _, dependency := range []struct{ binary, pkg string }{{"python3", "python3"}, {"rsyslogd", "rsyslog"}} {
		if _, err := exec.LookPath(dependency.binary); err == nil {
			continue
		}
		s.logger.Info().Str("package", dependency.pkg).Msg("Восстанавливаем зависимость статистики")
		if err := installer.installPackage(dependency.pkg, getDistroType()); err != nil {
			return fmt.Errorf("не удалось установить %s, статистика не настроена: %w", dependency.pkg, err)
		}
		if _, err := exec.LookPath(dependency.binary); err != nil {
			return err
		}
	}
	return nil
}

func writeLoggingConfig(path string, data []byte) error {
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if string(old) == string(data) {
		return nil
	}
	if err == nil {
		backup, err := os.OpenFile(path+".before-repair", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil && !os.IsExist(err) {
			return err
		}
		if err == nil {
			_, writeErr := backup.Write(old)
			closeErr := backup.Close()
			if writeErr != nil {
				return writeErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return atomicWriteFile(path, data, 0644)
}
