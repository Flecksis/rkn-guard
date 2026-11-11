package main

import (
	"fmt"
	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
	"github.com/spf13/cobra"
)

func newManualIPsCommand() *cobra.Command {
	return &cobra.Command{Use: "manual-ips list | add IP | delete IP", Args: cobra.RangeArgs(1, 2), RunE: func(cmd *cobra.Command, args []string) error {
		if err := service.NewInstallerService(logger.Global().Logger).CheckRootPrivileges(); err != nil {
			return err
		}
		lock, err := service.AcquireLock()
		if err != nil {
			return err
		}
		defer lock.Close()
		if args[0] == "list" && len(args) == 1 {
			entries, err := service.LoadManualIPs()
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Println("Ручных банов нет.")
			}
			for _, ip := range entries {
				fmt.Println(ip)
			}
			return nil
		}
		if len(args) != 2 {
			return fmt.Errorf("укажите действие и IP")
		}
		s := service.NewIpsetService(logger.Global().Logger, service.NewCommandService(logger.Global().Logger))
		message, err := s.ChangeManualIP(args[0], args[1])
		if err != nil {
			return err
		}
		fmt.Println(message)
		return nil
	}}
}
