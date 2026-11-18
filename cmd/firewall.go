package main

import (
	"fmt"
	"github.com/Flecksis/rkn-guard/internal/domain"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
	"os"
)

func newFirewallCommands() []*cobra.Command {
	return []*cobra.Command{
		{Use: "firewall-select [auto|iptables|nftables|firewalld]", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.NewInstallerService(logger.Global().Logger).CheckRootPrivileges(); err != nil {
				return err
			}
			commands := service.NewCommandService(logger.Global().Logger)
			mode, err := service.SelectFirewall(args[0], commands)
			if err != nil {
				return err
			}
			if err := service.CheckFirewallMode(mode, commands); err != nil {
				return err
			}
			fmt.Println(mode)
			return nil
		}},
		{Use: "firewall-restore", Hidden: true, RunE: func(cmd *cobra.Command, args []string) error {
			lock, err := service.AcquireLock()
			if err != nil {
				return err
			}
			defer lock.Close()
			state, err := service.LoadFirewall()
			if err != nil {
				return err
			}
			if state.Backend == "iptables" {
				return nil
			}
			return service.ApplyNFTState(service.NewCommandService(logger.Global().Logger), state, false)
		}},
		{Use: "firewall-status", Short: "Показать режим и число подсетей", RunE: func(cmd *cobra.Command, args []string) error {
			state, err := service.LoadFirewall()
			if err != nil {
				return err
			}
			fmt.Println(state.Backend)
			if state.Backend != "iptables" {
				fmt.Println(state.Networks.TotalCount())
			}
			return nil
		}},
	}
}

func installNFT(commands *service.CommandService, installer *service.InstallerService, mode string, networks *domain.NetworkList) error {
	if err := installer.EnsureFirewallDependencies(mode); err != nil {
		return err
	}
	next := &service.FirewallState{Backend: mode, Logging: enableLogging, Networks: *networks}
	if err := service.SetupFirewallRestore(commands, mode); err != nil {
		return err
	}
	if err := service.CommitNFTState(commands, next, false); err != nil {
		return err
	}
	if err := service.NewUninstallerService(logger.Global().Logger, commands).RemoveLegacyFirewall(); err != nil {
		return err
	}
	return nil
}

func finishLegacyInstall(commands *service.CommandService) error {
	previous, err := service.LoadFirewall()
	if err != nil {
		return err
	}
	next := &service.FirewallState{Backend: "iptables", Logging: enableLogging, CleanupNFT: previous.Backend != "iptables" || previous.CleanupNFT}
	if err := service.SaveFirewall(next); err != nil {
		return err
	}
	if next.CleanupNFT {
		if err := service.RemoveNFT(commands); err != nil {
			return err
		}
	}
	if _, err := os.Stat(service.FirewallUnitPath); err == nil {
		if err := commands.Run("systemctl", "disable", "--now", "rkn-guard-firewall.service"); err != nil {
			return err
		}
		if err := os.Remove(service.FirewallUnitPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := commands.DaemonReload(); err != nil {
			return err
		}
	}
	next.CleanupNFT = false
	return service.SaveFirewall(next)
}
