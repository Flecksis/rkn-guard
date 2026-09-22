package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
)

var (
	urls          []string
	enableLogging bool
	confirmYes    bool
	removeLogs    bool
	logLevel      string
	version       = "dev" // Версия будет устанавливаться при сборке через -ldflags
)

func main() {
	// Setup logger
	log := logger.New()
	logger.SetGlobalLogger(log)

	rootCmd := &cobra.Command{
		Use:     "rkn",
		Short:   "Инструмент для управления блокировкой сканеров через iptables и ipset",
		Long:    `Утилита для скачивания списков подсетей сканеров и настройки правил iptables/ipset для их блокировки.`,
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Update logger level if specified
			if logLevel != "" {
				log = logger.NewWithLevel(logLevel)
				logger.SetGlobalLogger(log)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")

	fullCmd := &cobra.Command{
		Use:   "full",
		Short: "Выполнить полную установку (скачать, настроить и применить)",
		Long:  `Скачивает списки подсетей, настраивает ipset и iptables, сохраняет правила для автозагрузки.`,
		Run:   runFull,
	}
	fullCmd.Flags().StringSliceVarP(&urls, "urls", "u", []string{}, "Список URL для скачивания подсетей")
	fullCmd.Flags().BoolVarP(&enableLogging, "enable-logging", "l", false, "Включить логирование заблокированных подключений")
	fullCmd.MarkFlagRequired("urls")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Удалить все изменения, внесённые rkn-guard",
		Long:  `Удаляет цепочки iptables/ipset, systemd сервисы и конфигурационные файлы, созданные rkn-guard.`,
		Run:   runUninstall,
	}
	uninstallCmd.Flags().BoolVar(&confirmYes, "yes", false, "Подтвердить удаление без интерактивного запроса")
	uninstallCmd.Flags().BoolVar(&removeLogs, "remove-logs", false, "Удалить логи rkn-guard из /var/log")

	rootCmd.AddCommand(fullCmd)
	rootCmd.AddCommand(uninstallCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runFull(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Полная установка ===")

	// Create services
	// Create command service
	cmdSvc := service.NewCommandService(log.Logger)

	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)
	iptablesSvc := service.NewIptablesService(log.Logger, cmdSvc, enableLogging)
	loggingSvc := service.NewLoggingService(log.Logger)

	// Check root
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("This program must be run as root (use sudo)")
	}

	if len(urls) == 0 {
		log.Panic().Msg("Не указаны URL для скачивания подсетей. Используйте флаг --urls")
	}

	// UFW Safety Warning
	if cmdSvc.CommandExists("ufw") {
		output, err := cmdSvc.RunOutput("ufw", "status")
		isActive := err == nil && strings.Contains(output, "Status: active")

		if !isActive {
			log.Warn().Msg("⚠️  UFW установлен но неактивен")
			log.Warn().Msg("⚠️  ВНИМАНИЕ: Если UFW не имеет правил для SSH, включение UFW заблокирует доступ!")
			log.Warn().Msg("")
			log.Warn().Msg("Убедитесь что SSH разрешён:")
			log.Warn().Msg("  sudo ufw allow 22/tcp")
			log.Warn().Msg("  sudo ufw allow OpenSSH")
			log.Warn().Msg("")
			log.Warn().Msg("rkn-guard проверит наличие правил SSH и прервёт установку если их нет")
			log.Warn().Msg("")
		}
	}

	// Ensure dependencies
	if err := installer.EnsureDependencies(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install dependencies")
	}

	// Ensure netfilter-persistent is installed
	if err := installer.EnsureNetfilterPersistent(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install netfilter-persistent")
	}

	// Download subnets
	networks, err := downloader.Download(urls)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	// Setup ipset
	if err := ipsetSvc.Setup(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup ipset")
	}

	// Fill ipset with subnets
	if err := ipsetSvc.Fill(networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to fill ipset")
	}

	// Setup iptables
	if err := iptablesSvc.SetupChain(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup iptables")
	}

	// Setup logging if enabled
	if enableLogging {
		if err := loggingSvc.Setup(); err != nil {
			log.Warn().Err(err).Msg("Failed to setup logging configuration")
		}
	}

	// Save rules
	if err := ipsetSvc.Save("/etc/ipset.conf"); err != nil {
		log.Warn().Err(err).Msg("Failed to save ipset configuration")
	}

	// Create systemd service to restore ipset on boot (before UFW starts)
	if err := ipsetSvc.CreateRestoreService(); err != nil {
		log.Warn().Err(err).Msg("Failed to create ipset restore service")
	}

	if err := iptablesSvc.Save(); err != nil {
		log.Error().Msg("╔════════════════════════════════════════════════════════════╗")
		log.Error().Msg("║  ❌ УСТАНОВКА ПРЕРВАНА - КРИТИЧЕСКАЯ ОШИБКА                 ║")
		log.Error().Msg("╚════════════════════════════════════════════════════════════╝")
		log.Error().Msg("")
		log.Fatal().Err(err).Msg("Не удалось сохранить правила iptables")
	}

	log.Info().Msg("Полная установка успешно завершена")
}

func runUninstall(cmd *cobra.Command, args []string) {
	log := logger.Global()
	log.Info().Msg("=== Удаление rkn-guard ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	uninstaller := service.NewUninstallerService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("This program must be run as root (use sudo)")
	}

	if !confirmYes {
		fmt.Print("Это удалит правила rkn-guard, systemd-сервисы и конфигурацию. Продолжить? [y/N]: ")
		if !confirmFromStdin() {
			log.Info().Msg("Удаление отменено пользователем")
			return
		}
	}

	if err := uninstaller.Uninstall(removeLogs); err != nil {
		log.Fatal().Err(err).Msg("Не удалось выполнить uninstall")
	}

	if removeLogs {
		log.Info().Msg("Uninstall завершён, логи удалены")
		return
	}

	log.Info().Msg("Uninstall завершён, логи сохранены")
}

func confirmFromStdin() bool {
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}
