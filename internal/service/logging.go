package service

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/rs/zerolog"
)

// LoggingService настраивает сбор журналов.
type LoggingService struct {
	logger zerolog.Logger
}

// NewLoggingService создаёт сервис настройки журналов.
func NewLoggingService(logger zerolog.Logger) *LoggingService {
	return &LoggingService{
		logger: logger,
	}
}

// Setup настраивает rsyslog, ротацию и сбор статистики.
func (s *LoggingService) Setup() error {
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

	// Настраиваем периодический запуск.
	if err := s.setupCronJob(); err != nil {
		return fmt.Errorf("failed to setup cron job: %w", err)
	}

	// Перезапускаем rsyslog.
	if err := s.reloadRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить rsyslog, может потребоваться ручная перезагрузка")
	}

	s.logger.Info().Msg("Конфигурация логирования готова")
	s.logger.Info().Msg("  Сырые логи: /var/log/iptables-scanners-{ipv4,ipv6}.log")
	s.logger.Info().Msg("  Агрегированные: /var/log/iptables-scanners-aggregate.csv (с ASN/netname, обновляются каждые 30 сек)")
	s.logger.Info().Msg("  Rate limit: 10 entries/minute")
	s.logger.Info().Msg("  Проверить статус: systemctl status antiscan-aggregate.timer")

	return nil
}

// setupRsyslog создаёт настройки rsyslog.
func (s *LoggingService) setupRsyslog() error {
	if err := os.WriteFile(RsyslogConfigPath, []byte(RsyslogConfigTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", RsyslogConfigPath).Msg("Конфиг rsyslog создан")
	return nil
}

// createLogFiles создаёт журналы с нужными правами.
func (s *LoggingService) createLogFiles() error {
	// Создаём пустые журналы и выставляем права.
	logFiles := []string{
		IPv4LogPath,
		IPv6LogPath,
	}

	for _, logFile := range logFiles {
		if _, err := os.Stat(logFile); os.IsNotExist(err) {
			f, err := os.Create(logFile)
			if err != nil {
				return fmt.Errorf("failed to create %s: %w", logFile, err)
			}
			f.Close()

			// Выставляем права доступа.
			if err := exec.Command("chown", "syslog:adm", logFile).Run(); err != nil {
				s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chown log file")
			}
			if err := exec.Command("chmod", "640", logFile).Run(); err != nil {
				s.logger.Warn().Err(err).Str("file", logFile).Msg("Failed to chmod log file")
			}

			s.logger.Info().Str("file", logFile).Msg("Создан лог файл")
		}
	}

	return nil
}

// setupLogrotate создаёт настройки ротации.
func (s *LoggingService) setupLogrotate() error {
	if err := os.WriteFile(LogrotateConfigPath, []byte(LogrotateConfigTemplate), 0644); err != nil {
		return err
	}

	s.logger.Info().Str("path", LogrotateConfigPath).Msg("Создан logrotate конфиг")
	return nil
}

// setupAggregationScript создаёт скрипт сбора статистики.
func (s *LoggingService) setupAggregationScript() error {
	if err := os.WriteFile(AggregateLogsScriptPath, []byte(AggregateLogsScriptTemplate), 0755); err != nil {
		return fmt.Errorf("failed to write aggregator script: %w", err)
	}

	// Разрешаем запуск скрипта.
	if err := exec.Command("chmod", "+x", AggregateLogsScriptPath).Run(); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	s.logger.Info().Str("path", AggregateLogsScriptPath).Msg("Создан скрипт агрегирования логов")
	return nil
}

// setupCronJob создаёт таймер systemd с интервалом 30 секунд.
func (s *LoggingService) setupCronJob() error {
	// Создаём сервис systemd.
	if err := os.WriteFile(AggregateLogsServicePath, []byte(AggregateLogsServiceTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsServicePath).Msg("Создан systemd сервис")

	// Создаём таймер systemd.
	if err := os.WriteFile(AggregateLogsTimerPath, []byte(AggregateLogsTimerTemplate), 0644); err != nil {
		return err
	}
	s.logger.Info().Str("path", AggregateLogsTimerPath).Msg("Создан systemd timer")

	// Просим systemd перечитать файлы сервисов.
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезапустить systemd daemon")
	}

	// Включаем и запускаем таймер.
	if err := exec.Command("systemctl", "enable", "antiscan-aggregate.timer").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить antiscan-aggregate")
	}

	if err := exec.Command("systemctl", "start", "antiscan-aggregate.timer").Run(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось включить timer")
	}

	s.logger.Info().Msg("Systemd timer включен и запущен (каждые 30 секунд)")
	return nil
}

// reloadRsyslog перезапускает rsyslog.
func (s *LoggingService) reloadRsyslog() error {
	if err := exec.Command("systemctl", "restart", "rsyslog").Run(); err != nil {
		return err
	}
	s.logger.Info().Msg("Rsyslog перезапущен")
	return nil
}
