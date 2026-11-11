package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	branch        = "unknown"
)

func main() {
	// Настраиваем журнал.
	log := logger.New()
	logger.SetGlobalLogger(log)

	rootCmd := &cobra.Command{
		Use:     "rkn-guard",
		Short:   "Инструмент для управления блокировкой сканеров через iptables и ipset",
		Long:    `Утилита для скачивания списков подсетей сканеров и настройки правил iptables/ipset для их блокировки.`,
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Если указан уровень сообщений, применяем его.
			if logLevel != "" {
				log = logger.NewWithLevel(logLevel)
				logger.SetGlobalLogger(log)
			}
		},
	}

	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&sourcesFile, "sources-file", service.SourcesPath, "Файл настроек и проверенных копий списков")

	fullCmd := &cobra.Command{
		Use:   "full",
		Short: "Выполнить полную установку (скачать, настроить и применить)",
		Long:  `Скачивает списки подсетей, настраивает ipset и iptables, сохраняет правила для автозагрузки.`,
		Run:   runFull,
	}
	fullCmd.Flags().StringSliceVarP(&urls, "urls", "u", []string{}, "Список URL для скачивания подсетей")
	fullCmd.Flags().BoolVarP(&enableLogging, "enable-logging", "l", false, "Включить логирование заблокированных подключений")
	fullCmd.Flags().BoolVar(&managedLists, "managed-lists", false, "Учесть дополнительные списки и сохранённые копии источников")

	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Обновить списки подсетей без сброса счётчиков атак",
		Long:  `Скачивает и обновляет ipset-наборы, не изменяя цепочки iptables. Счётчики заблокированных атак сохраняются.`,
		Run:   runUpdate,
	}
	updateCmd.Flags().StringSliceVarP(&urls, "urls", "u", []string{}, "Список URL для скачивания подсетей")
	updateCmd.Flags().BoolVar(&managedLists, "managed-lists", false, "Учесть дополнительные списки и сохранённые копии источников")

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Удалить все изменения, внесённые rkn-guard",
		Long:  `Удаляет цепочки iptables/ipset, systemd сервисы и конфигурационные файлы, созданные rkn-guard.`,
		Run:   runUninstall,
	}
	uninstallCmd.Flags().BoolVar(&confirmYes, "yes", false, "Подтвердить удаление без интерактивного запроса")
	uninstallCmd.Flags().BoolVar(&removeLogs, "remove-logs", false, "Удалить логи rkn-guard из /var/log")

	rootCmd.AddCommand(fullCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(uninstallCmd)
	rootCmd.AddCommand(newSourcesCommand())
	rootCmd.AddCommand(newExceptionsCommand())
	rootCmd.AddCommand(newManualIPsCommand())
	rootCmd.AddCommand(&cobra.Command{
		Use:   "stats",
		Short: "Обновить статистику и показать все зарегистрированные адреса",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.NewLoggingService(log.Logger).CheckHealth(); err != nil {
				return fmt.Errorf("сбор статистики не работает; сохранённые данные не удалены: %w", err)
			}
			process := exec.Command("python3", "-c", service.AggregateLogsScriptTemplate, "--display")
			process.Stdout, process.Stderr = os.Stdout, os.Stderr
			return process.Run()
		},
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:   "setup-logging",
		Short: "Обновить сборщик статистики без изменения правил firewall",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := service.NewInstallerService(log.Logger).CheckRootPrivileges(); err != nil {
				return err
			}
			lock, err := service.AcquireLock()
			if err != nil {
				return err
			}
			defer lock.Close()
			return service.NewLoggingService(log.Logger).Refresh()
		},
	})
	rootCmd.AddCommand(&cobra.Command{
		Use:   "build-info",
		Short: "Показать версию и ветку сборки",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("%s\n%s\n", version, branch)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runFull(cmd *cobra.Command, args []string) {
	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

	log := logger.Global()
	log.Info().Msg("=== Полная установка ===")

	// Создаём сервисы.
	// Создаём исполнитель системных команд.
	cmdSvc := service.NewCommandService(log.Logger)

	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)
	iptablesSvc := service.NewIptablesService(log.Logger, cmdSvc, enableLogging)
	loggingSvc := service.NewLoggingService(log.Logger)

	// Проверяем права root.
	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("This program must be run as root (use sudo)")
	}

	if len(urls) == 0 && !managedLists {
		log.Panic().Msg("Не указаны URL для скачивания подсетей. Используйте флаг --urls")
	}

	networks, _, err := downloadConfiguredLists(downloader)
	if errors.Is(err, service.ErrNoSourceData) {
		log.Fatal().Msg("Списки недоступны и пригодного кэша нет. Установка не завершена; действующие наборы и правила не изменены.")
		return
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	// Предупреждаем о необходимости разрешить SSH в UFW.
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

	// Проверяем зависимости.
	if err := installer.EnsureDependencies(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install dependencies")
	}

	// При необходимости устанавливаем netfilter-persistent.
	if err := installer.EnsureNetfilterPersistent(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install netfilter-persistent")
	}

	// Готовим, заменяем и сохраняем наборы до настройки правил firewall.
	if err := applySourceNetworks(ipsetSvc, networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to replace ipset")
	}

	// Настраиваем iptables.
	if err := iptablesSvc.SetupChain(); err != nil {
		log.Fatal().Err(err).Msg("Failed to setup iptables")
	}

	// Настраиваем журнал, если он включён.
	var loggingErr error
	if enableLogging {
		loggingErr = loggingSvc.Refresh()
	}

	// Создаём сервис восстановления ipset, который запускается раньше UFW.
	restoreErr := ipsetSvc.CreateRestoreService()

	if err := iptablesSvc.Save(); err != nil {
		log.Error().Msg("╔════════════════════════════════════════════════════════════╗")
		log.Error().Msg("║  ❌ УСТАНОВКА ПРЕРВАНА - КРИТИЧЕСКАЯ ОШИБКА                 ║")
		log.Error().Msg("╚════════════════════════════════════════════════════════════╝")
		log.Error().Msg("")
		log.Fatal().Err(err).Msg("Не удалось сохранить правила iptables")
	}

	if loggingErr != nil {
		log.Fatal().Err(errors.Join(loggingErr, restoreErr)).Msg("Установка не завершена: статистика не настроена. Применённые правила не удалены; повторите setup-logging после устранения ошибки. При ошибке восстановления ipset повторите полную установку")
	}
	if restoreErr != nil {
		log.Fatal().Err(restoreErr).Msg("Установка не завершена: восстановление ipset при загрузке не настроено. Применённые правила не удалены; повторите установку после устранения ошибки")
	}
	log.Info().Msg("Полная установка успешно завершена")
}

// runUpdate обновляет наборы ipset, не пересоздавая правила iptables.
// Так сохраняются счётчики заблокированных пакетов, которые показывает меню.
func runUpdate(cmd *cobra.Command, args []string) {
	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

	log := logger.Global()
	log.Info().Msg("=== Обновление списков без сброса счётчиков атак ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		log.Fatal().Msg("This program must be run as root (use sudo)")
	}

	networks, warnings, err := downloadConfiguredLists(downloader)
	if errors.Is(err, service.ErrNoSourceData) {
		log.Fatal().Msg("Списки недоступны и пригодного кэша нет. Обновление не выполнено; действующие наборы и правила сохранены.")
		return
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}
	if err := applySourceNetworks(ipsetSvc, networks); err != nil {
		log.Fatal().Err(err).Msg("Failed to replace ipset")
	}

	log.Info().Msg("Списки обновлены, счётчики атак сохранены")
	if len(warnings) > 0 {
		log.Warn().Int("sources_with_errors", len(warnings)).Msg("Обновление завершено с ошибками источников; подробности выше")
		os.Exit(2)
	}
}

func runUninstall(cmd *cobra.Command, args []string) {
	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

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
