package service

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

const (
	ipsetV4Name = "SCANNERS-BLOCK-V4"
	ipsetV6Name = "SCANNERS-BLOCK-V6"
)

// IpsetService управляет наборами ipset.
type IpsetService struct {
	logger   zerolog.Logger
	cmdSvc   *CommandService
	ipsetCmd *IpsetCommandService
}

// NewIpsetService создаёт сервис управления ipset.
func NewIpsetService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetService {
	return &IpsetService{
		logger:   logger,
		cmdSvc:   cmdSvc,
		ipsetCmd: NewIpsetCommandService(logger, cmdSvc),
	}
}

// Restore восстанавливает наборы из файла.
func (s *IpsetService) Restore(path string) error {
	s.logger.Info().Str("path", path).Msg("Загрузка конфигурации ipset")

	if err := s.ipsetCmd.Restore(path); err != nil {
		return fmt.Errorf("failed to restore ipset: %w", err)
	}

	s.logger.Info().Str("path", path).Msg("Конфигурация ipset загружена")
	return nil
}

// CreateRestoreService создаёт сервис восстановления ipset при загрузке.
func (s *IpsetService) CreateRestoreService() error {
	s.logger.Info().Msg("Создание systemd сервиса для загрузки конфигурации ipset")

	if err := os.WriteFile(IpsetRestoreServicePath, []byte(IpsetRestoreServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", IpsetRestoreServicePath).Msg("Создан systemd сервис")

	// Просим systemd перечитать файлы сервисов.
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить демон systemd")
	}

	// Включаем автозапуск сервиса.
	if err := s.cmdSvc.EnableService("antiscan-ipset-restore.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("Сервис systemd успешно включен")

	s.logger.Info().Msg("Ipset будет автоматически восстановлен на системном запуске перед запуском UFW")
	return nil
}
