package main

import (
	"fmt"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
	"strings"
)

func newExceptionsCommand() *cobra.Command {
	return &cobra.Command{Use: "exceptions list | add IP tcp|udp PORT | delete IP tcp|udp PORT", Args: cobra.MinimumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.NewInstallerService(logger.Global().Logger).CheckRootPrivileges(); err != nil {
			return err
		}
		lock, err := service.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Close()
		if args[0] == "list" && len(args) == 1 {
			entries, err := service.LoadExceptions(service.ExceptionsPath)
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("Исключений нет.")
			}
			for _, e := range entries {
				fmt.Printf("%s %s %d\n", e.IP, e.Protocol, e.Port)
			}
			return nil
		}
		if len(args) != 4 || (args[0] != "add" && args[0] != "delete") {
			return fmt.Errorf("укажите add или delete, IP, TCP/UDP и порт")
		}
		entry, err := service.ParseException(args[1], args[2], args[3])
		if err != nil {
			return err
		}
		commands := service.NewCommandService(logger.Global().Logger)
		rules, err := commands.RunOutput("iptables", "-w", "-S", "SCANNERS-BLOCK")
		if err != nil {
			return err
		}
		firewall := service.NewIptablesService(logger.Global().Logger, commands, strings.Contains(rules, "-j LOG"))
		if err := firewall.ChangeException(args[0], entry); err != nil {
			return err
		}
		fmt.Println("Исключения применены и сохранены.")
		return nil
	}}
}
