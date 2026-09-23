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

// IpsetService handles ipset operations
type IpsetService struct {
	logger   zerolog.Logger
	cmdSvc   *CommandService
	ipsetCmd *IpsetCommandService
}

// NewIpsetService creates a new ipset service
func NewIpsetService(logger zerolog.Logger, cmdSvc *CommandService) *IpsetService {
	return &IpsetService{
		logger:   logger,
		cmdSvc:   cmdSvc,
		ipsetCmd: NewIpsetCommandService(logger, cmdSvc),
	}
}

// Restore restores ipset configuration from file
func (s *IpsetService) Restore(path string) error {
	s.logger.Info().Str("path", path).Msg("Загрузка конфигурации ipset")

	if err := s.ipsetCmd.Restore(path); err != nil {
		return fmt.Errorf("failed to restore ipset: %w", err)
	}

	s.logger.Info().Str("path", path).Msg("Конфигурация ipset загружена")
	return nil
}

// CreateRestoreService creates systemd service to restore ipset on boot
func (s *IpsetService) CreateRestoreService() error {
	s.logger.Info().Msg("Создание systemd сервиса для загрузки конфигурации ipset")

	if err := os.WriteFile(IpsetRestoreServicePath, []byte(IpsetRestoreServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", IpsetRestoreServicePath).Msg("Создан systemd сервис")

	// Reload systemd daemon
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить демон systemd")
	}

	// Enable service
	if err := s.cmdSvc.EnableService("antiscan-ipset-restore.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("Сервис systemd успешно включен")

	s.logger.Info().Msg("Ipset будет автоматически восстановлен на системном запуске перед запуском UFW")
	return nil
}
