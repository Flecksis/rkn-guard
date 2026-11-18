package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog"
)

const (
	ufwManagedBlockStart = "# SCANNERS-BLOCK chain - managed by antiscan"
	ufwManagedBlockEnd   = "# END SCANNERS-BLOCK"
)

// UninstallerService отменяет изменения, внесённые rkn-guard в систему.
type UninstallerService struct {
	logger      zerolog.Logger
	cmdSvc      *CommandService
	iptablesCmd *IptablesCommandService
	ipsetCmd    *IpsetCommandService
}

// NewUninstallerService создаёт сервис удаления.
func NewUninstallerService(logger zerolog.Logger, cmdSvc *CommandService) *UninstallerService {
	return &UninstallerService{
		logger:      logger,
		cmdSvc:      cmdSvc,
		iptablesCmd: NewIptablesCommandService(logger, cmdSvc),
		ipsetCmd:    NewIpsetCommandService(logger, cmdSvc),
	}
}

// Uninstall удаляет файлы rkn-guard и восстанавливает настройки firewall.
func (s *UninstallerService) Uninstall(removeLogs bool) error {
	state, err := LoadFirewall()
	if err != nil {
		return err
	}
	if state.Backend != "iptables" {
		if err := s.RemoveLegacyFirewall(); err != nil {
			return err
		}
		if err := RemoveNFT(s.cmdSvc); err != nil {
			return err
		}
		s.stopAndDisableServices()
		s.removeArtifacts(removeLogs)
		return errors.Join(s.reloadSystemdDaemon(), s.reloadRsyslog())
	}
	if _, err := os.Stat(FirewallUnitPath); err == nil || state.CleanupNFT {
		if err := RemoveNFT(s.cmdSvc); err != nil {
			return err
		}
	}
	s.logger.Info().Msg("=== Uninstall rkn-guard ===")
	s.logger.Info().Msg("rkn-guard does not modify Linux routing tables (ip rule/ip route), skipping routing rollback")

	s.stopAndDisableServices()
	s.cleanupIPTablesRuntime()
	if err := s.cleanupUFWBeforeRules(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cleanup UFW before.rules markers")
	}
	s.cleanupIPSet()
	s.removeArtifacts(removeLogs)

	if err := s.reloadSystemdDaemon(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload systemd daemon")
	}

	if err := s.reloadRsyslog(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to reload rsyslog")
	}

	if err := s.persistFirewallState(); err != nil {
		return fmt.Errorf("failed to persist firewall state: %w", err)
	}

	s.logger.Info().Msg("rkn-guard uninstall completed")
	return nil
}

func (s *UninstallerService) stopAndDisableServices() {
	if !s.cmdSvc.CommandExists("systemctl") {
		s.logger.Warn().Msg("systemctl not found, skipping service stop/disable")
		return
	}

	services := []string{
		"rkn-guard-firewall.service",
		"rkn-guard-update.timer",
		"rkn-guard-update.service",
		"antiscan-aggregate.timer",
		"antiscan-aggregate.service",
		"antiscan-move-rules.service",
		"antiscan-ipset-restore.service",
	}

	for _, serviceName := range services {
		if err := s.cmdSvc.StopService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Stop failed, continuing")
		}
		if err := s.cmdSvc.DisableService(serviceName); err != nil {
			s.logger.Warn().Err(err).Str("service", serviceName).Msg("Disable failed, continuing")
		}
	}
}

func (s *UninstallerService) cleanupIPTablesRuntime() {
	s.cleanupIPTablesVersion(IPv4, "ufw-before-input", "iptables")
	s.cleanupIPTablesVersion(IPv6, "ufw6-before-input", "ip6tables")
}

func (s *UninstallerService) cleanupIPTablesVersion(version IPVersion, ufwInputChain, command string) {
	if err := s.iptablesCmd.UnlinkChainFromInput(version, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to unlink chain from INPUT, continuing")
	}

	if err := s.cmdSvc.Run(command, "-D", ufwInputChain, "-j", chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to unlink chain from UFW input, continuing")
	}

	if !s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
		return
	}

	if err := s.iptablesCmd.FlushChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to flush chain, continuing")
	}

	if err := s.iptablesCmd.DeleteChain(version, TableFilter, chainName); err != nil {
		s.logger.Warn().Err(err).Str("version", string(version)).Msg("Failed to delete chain, continuing")
	}
}

func (s *UninstallerService) cleanupUFWBeforeRules() error {
	changedV4, err := s.removeManagedUFWBlock(UFWBeforeRulesPath)
	if err != nil {
		return err
	}

	changedV6, err := s.removeManagedUFWBlock(UFW6BeforeRulesPath)
	if err != nil {
		return err
	}

	if (changedV4 || changedV6) && s.cmdSvc.CommandExists("ufw") {
		if err := s.cmdSvc.Run("ufw", "reload"); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to reload UFW after cleanup")
		}
	}

	return nil
}

func (s *UninstallerService) removeManagedUFWBlock(path string) (bool, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read %s: %w", path, err)
	}

	updated := string(content)
	original := updated
	blocksRemoved := 0

	for {
		start := strings.Index(updated, ufwManagedBlockStart)
		if start == -1 {
			break
		}

		endRel := strings.Index(updated[start:], ufwManagedBlockEnd)
		if endRel == -1 {
			s.logger.Warn().Str("path", path).Msg("Managed block start found but no end marker, skipping")
			break
		}

		end := start + endRel + len(ufwManagedBlockEnd)
		for end < len(updated) && (updated[end] == '\n' || updated[end] == '\r') {
			end++
		}

		updated = updated[:start] + updated[end:]
		blocksRemoved++
	}

	if updated == original {
		return false, nil
	}

	tmpPath := path + ".new"
	if err := os.WriteFile(tmpPath, []byte(updated), 0640); err != nil {
		return false, fmt.Errorf("failed to write %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("failed to replace %s: %w", path, err)
	}

	s.logger.Info().Str("path", path).Int("blocks", blocksRemoved).Msg("Removed rkn-guard managed UFW blocks")
	return true, nil
}

func (s *UninstallerService) cleanupIPSet() {
	for _, setName := range []string{ipsetV4Name, ipsetV6Name} {
		if !s.ipsetCmd.Exists(setName) {
			continue
		}

		if err := s.ipsetCmd.Flush(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to flush ipset, continuing")
		}
		if err := s.ipsetCmd.Destroy(setName); err != nil {
			s.logger.Warn().Err(err).Str("set", setName).Msg("Failed to destroy ipset, continuing")
		}
	}

	if err := removeFileIfExists(IpsetConfigPath); err != nil {
		s.logger.Warn().Err(err).Str("path", IpsetConfigPath).Msg("Failed to remove ipset config")
	}
}

func (s *UninstallerService) removeArtifacts(removeLogs bool) {
	paths := []string{
		FirewallPath,
		FirewallUnitPath,
		"/etc/systemd/system/rkn-guard-update.timer",
		"/etc/systemd/system/rkn-guard-update.service",
		"/etc/rkn-guard-update.conf",
		IpsetRestoreServicePath,
		MoveRulesServicePath,
		AggregateLogsServicePath,
		AggregateLogsTimerPath,
		AggregateLogsScriptPath,
		RsyslogConfigPath,
		LogrotateConfigPath,
		ExceptionsPath,
		ManualIPsPath,
	}

	for _, path := range paths {
		if err := removeFileIfExists(path); err != nil {
			s.logger.Warn().Err(err).Str("path", path).Msg("Failed to remove file, continuing")
		}
	}

	if !removeLogs {
		return
	}
	if err := removeFileIfExists("/var/lib/rkn-guard/attack-stats.json"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to remove attack statistics state")
	}

	logFiles, err := filepath.Glob("/var/log/iptables-scanners-*")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to enumerate log files")
		return
	}

	for _, logFile := range logFiles {
		if err := removeFileIfExists(logFile); err != nil {
			s.logger.Warn().Err(err).Str("path", logFile).Msg("Failed to remove log file")
		}
	}
}

// Убираем старую защиту только после включения новой.
func (s *UninstallerService) RemoveLegacyFirewall() error {
	data, readErr := os.ReadFile(IpsetConfigPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if !strings.Contains(string(data), ipsetV4Name) && !strings.Contains(string(data), ipsetV6Name) && !s.iptablesCmd.ChainExists(IPv4, TableFilter, chainName) && !s.iptablesCmd.ChainExists(IPv6, TableFilter, chainName) {
		return nil
	}
	for _, name := range []string{"antiscan-move-rules.service", "antiscan-ipset-restore.service"} {
		if s.cmdSvc.RunQuiet("systemctl", "cat", name) == nil {
			if err := s.cmdSvc.Run("systemctl", "disable", "--now", name); err != nil {
				return err
			}
		}
	}
	s.cleanupIPTablesRuntime()
	if err := s.cleanupUFWBeforeRules(); err != nil {
		return err
	}
	for _, version := range []IPVersion{IPv4, IPv6} {
		if s.iptablesCmd.ChainExists(version, TableFilter, chainName) {
			return fmt.Errorf("не удалось удалить старую цепочку %s", version)
		}
	}
	for _, name := range []string{ipsetV4Name, ipsetV6Name} {
		if s.ipsetCmd.Exists(name) {
			if err := s.ipsetCmd.Destroy(name); err != nil {
				return err
			}
		}
	}
	if readErr == nil {
		var keep []string
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && (fields[1] == ipsetV4Name || fields[1] == ipsetV6Name) {
				continue
			}
			if strings.TrimSpace(line) != "" {
				keep = append(keep, line)
			}
		}
		if len(keep) == 0 {
			if err := removeFileIfExists(IpsetConfigPath); err != nil {
				return err
			}
		} else if err := atomicWriteFile(IpsetConfigPath, []byte(strings.Join(keep, "\n")+"\n"), 0600); err != nil {
			return err
		}
	}
	for _, path := range []string{IpsetRestoreServicePath, MoveRulesServicePath} {
		if err := removeFileIfExists(path); err != nil {
			return err
		}
	}
	if err := s.persistFirewallState(); err != nil {
		return err
	}
	return s.cmdSvc.DaemonReload()
}

func (s *UninstallerService) reloadSystemdDaemon() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	return s.cmdSvc.DaemonReload()
}

func (s *UninstallerService) reloadRsyslog() error {
	if !s.cmdSvc.CommandExists("systemctl") {
		return nil
	}

	// Проверяем, установлен и запущен ли rsyslog.
	if err := s.cmdSvc.Run("systemctl", "is-active", "rsyslog"); err != nil {
		s.logger.Debug().Msg("rsyslog is not active, skipping reload")
		return nil
	}

	return s.cmdSvc.RestartService("rsyslog")
}

func (s *UninstallerService) persistFirewallState() error {
	if s.cmdSvc.CommandExists("ufw") {
		s.logger.Debug().Msg("UFW detected, skipping manual iptables persistence")
		return nil
	}

	s.logger.Info().Msg("Persisting firewall state to /etc/iptables/")

	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return err
	}

	if err := s.iptablesCmd.Save(IPv4, IptablesRulesV4Path); err != nil {
		return err
	}

	if err := s.iptablesCmd.Save(IPv6, IptablesRulesV6Path); err != nil {
		return err
	}

	if s.cmdSvc.CommandExists("netfilter-persistent") {
		if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
			s.logger.Warn().Err(err).Msg("netfilter-persistent save failed")
		}
	}

	return nil
}

func removeFileIfExists(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
