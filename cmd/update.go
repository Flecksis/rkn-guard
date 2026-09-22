package main

import (
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
)

// runUpdate refreshes ipset contents while deliberately leaving iptables rules
// untouched. Iptables stores the blocked-attack counters on those rules.
func runUpdate(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Обновление списков без сброса счётчиков атак ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("This program must be run as root (use sudo)")
	}

	networks, err := downloader.Download(urls)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	// Setup flushes and refills only ipset sets; it does not recreate the
	// SCANNERS-BLOCK iptables chain, so its packet counters remain intact.
	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup ipset")
	}
	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to fill ipset")
	}
	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Fatal().Err(err).Msg("Failed to save ipset configuration")
	}

	log.Info().Msg("Списки обновлены, счётчики атак сохранены")
}
