package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Flecksis/rkn-guard/internal/logger"
	"github.com/Flecksis/rkn-guard/internal/service"
)

var (
	urls             []string
	enableLogging    bool
	observeOnly      bool
	noFirewallChange bool
	confirmYes       bool
	removeLogs       bool
	logLevel         string
	requiredPortsRaw string
	requiredPorts    []int
	version          = "dev" // Версия будет устанавливаться при сборке через -ldflags
	branch           = "unknown"
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
	fullCmd.Flags().BoolVar(&observeOnly, "observe-only", false, "Ничего не менять в firewall: только показать план и скачанные списки")
	fullCmd.Flags().BoolVar(&noFirewallChange, "no-firewall-changes", false, "Не менять firewall; завершиться ошибкой, если правила некуда ставить")
	fullCmd.Flags().StringVar(&requiredPortsRaw, "required-ports", joinPorts(service.DefaultRequiredPorts),
		"Обязательные порты, которые должны остаться доступны (через запятую)")

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

	rollbackCmd := &cobra.Command{
		Use:   "rollback",
		Short: "Вернуть firewall и автозапуск к состоянию до установки (по снимку)",
		Long: `Восстанавливает UFW (статус и политики), before.rules/user.rules, iptables/ip6tables,
ipset-наборы и состояние автозапуска сервисов из снимка, снятого перед установкой.

Операция идемпотентна: повторный запуск ничего не меняет.`,
		Run: runRollback,
	}
	rollbackCmd.Flags().BoolVar(&confirmYes, "yes", false, "Не спрашивать подтверждение")
	rollbackCmd.Flags().BoolVar(&observeOnly, "observe-only", false, "Только показать снимок, ничего не восстанавливая")

	rootCmd.AddCommand(fullCmd)
	rootCmd.AddCommand(rollbackCmd)
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
	log := logger.Global()

	// D8: пользовательский ввод проверяется до блокировки и до любых изменений.
	ports, err := parsePortsList(requiredPortsRaw)
	if err != nil {
		failInput(log, err)
	}
	if err := validateInputs(inputParams{
		command:       "full",
		urls:          urls,
		managedLists:  managedLists,
		sourcesFile:   sourcesFile,
		logLevel:      logLevel,
		requiredPorts: ports,
	}); err != nil {
		failInput(log, err)
	}
	requiredPorts = ports

	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

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
		failInput(log, errors.New("нужны права root: запустите через sudo"))
	}

	// D5: ipset проверяется ДО любых изменений firewall.
	// Без ipset `ufw reload` оставляет политику INPUT DROP с нулём правил — это потеря SSH.
	if err := service.IpsetPreflight(cmdSvc, cmdSvc.CommandExists); err != nil {
		failPreflight(log, err)
	}
	log.Info().Msg("Preflight ipset: бинарник, модуль ядра и пробный набор работают")

	// FIX-1: состояние firewall проверяется ДО любых изменений в системе.
	// UFW не включается автоматически и политика INPUT не меняется.
	plan, err := service.PlanFirewall(cmdSvc, cmdSvc.CommandExists, observeOnly || noFirewallChange)
	if err != nil {
		log.Error().Msg("╔════════════════════════════════════════════════════════════╗")
		log.Error().Msg("║  УСТАНОВКА ПРЕРВАНА: FIREWALL НЕ ИЗМЕНЁН                   ║")
		log.Error().Msg("╚════════════════════════════════════════════════════════════╝")
		log.Error().Err(err).Msg("Правила некуда ставить")
		log.Error().Msg("Подсказка: ufw status verbose; ufw allow <vpn-port>/tcp; ufw enable — затем повторите установку")
		os.Exit(3)
	}
	if plan.ObserveOnly {
		log.Warn().Msg("Режим наблюдения (--observe-only/--no-firewall-changes): firewall, ipset и systemd не изменяются")
	} else if plan.UFWPresent && plan.UFWActive {
		log.Info().Msg("UFW активен: правила будут добавлены в ufw-before-input и применены reload'ом")
	}
	iptablesSvc.SetObserveOnly(plan.ObserveOnly)

	// D9: обязательные порты проверяются до применения правил.
	if plan.ObserveOnly {
		log.Warn().Ints("required_ports", requiredPorts).Msg("Режим наблюдения: проверка обязательных портов не блокирует запуск")
	} else if err := checkMandatoryPorts(cmdSvc, iptablesSvc, log); err != nil {
		failPreflight(log, err)
	}

	networks, _, err := downloadConfiguredLists(downloader)
	if errors.Is(err, service.ErrNoSourceData) {
		log.Fatal().Msg("Списки недоступны и пригодного кэша нет. Установка не завершена; действующие наборы и правила не изменены.")
		return
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to download subnets")
	}

	// Проверяем зависимости.
	if err := installer.EnsureDependencies(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install dependencies")
	}

	// При необходимости устанавливаем netfilter-persistent.
	if err := installer.EnsureNetfilterPersistent(); err != nil {
		log.Fatal().Err(err).Msg("Failed to install netfilter-persistent")
	}

	// Режим наблюдения: дальше не идём — ничего не меняем.
	if plan.ObserveOnly {
		log.Info().Int("sources", len(urls)).Msg("Режим наблюдения: списки получены, изменения в системе не выполнялись")
		log.Info().Msg("Firewall, ipset, правила и автозапуск не изменялись")
		return
	}

	// FIX-2: снимок состояния до любых изменений. Из него uninstall/rollback
	// возвращает firewall и автозапуск к baseline.
	snapshotter := service.NewSnapshotter(log.Logger, cmdSvc, cmdSvc.CommandExists)
	snap, err := snapshotter.Save()
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось снять снимок состояния firewall; установка прервана, изменений нет")
	}
	log.Info().Str("snapshot", service.FormatSnapshotReport(snap)).Str("dir", service.SnapshotDir).Msg("Снимок состояния до установки сохранён")

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
		log.Fatal().Err(err).Msg("Не удалось сохранить правила iptables. Вернуть system к baseline: rkn-guard rollback --yes")
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
	log := logger.Global()
	if err := validateInputs(inputParams{
		command:      "update",
		urls:         urls,
		managedLists: managedLists,
		sourcesFile:  sourcesFile,
		logLevel:     logLevel,
	}); err != nil {
		failInput(log, err)
	}

	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

	log.Info().Msg("=== Обновление списков без сброса счётчиков атак ===")

	cmdSvc := service.NewCommandService(log.Logger)
	installer := service.NewInstallerService(log.Logger)
	downloader := service.NewDownloader(log.Logger)
	ipsetSvc := service.NewIpsetService(log.Logger, cmdSvc)

	if err := installer.CheckRootPrivileges(); err != nil {
		failInput(log, errors.New("нужны права root: запустите через sudo"))
	}

	// D5: обновление тоже меняет ipset — проверяем его до любых изменений.
	if err := service.IpsetPreflight(cmdSvc, cmdSvc.CommandExists); err != nil {
		failPreflight(log, err)
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

// failInput завершает работу с кодом 2: ошибка в запуске, без паники и стека.
// Ни firewall, ни ipset, ни автозапуск к этому моменту не изменены.
func failInput(log *logger.Logger, err error) {
	log.Error().Err(err).Msg("Установка прервана: некорректные параметры запуска. Firewall, ipset и автозапуск не изменены")
	fmt.Fprintf(os.Stderr, "rkn-guard: %v\n", err)
	os.Exit(2)
}

// failPreflight завершает работу с кодом 3: проверка безопасности не пройдена,
// изменения в системе не выполнялись.
func failPreflight(log *logger.Logger, err error) {
	log.Error().Msg("╔════════════════════════════════════════════════════════════╗")
	log.Error().Msg("║  УСТАНОВКА ПРЕРВАНА: PREFLIGHT НЕ ПРОЙДЕН, ИЗМЕНЕНИЙ НЕТ    ║")
	log.Error().Msg("╚════════════════════════════════════════════════════════════╝")
	log.Error().Err(err).Msg("Проверка безопасности перед применением")
	fmt.Fprintf(os.Stderr, "rkn-guard: %v\n", err)
	os.Exit(3)
}

// checkMandatoryPorts проверяет через `ss -lntup`, что обязательные порты
// слушаются, и что план правил не может их отрезать.
func checkMandatoryPorts(cmdSvc *service.CommandService, iptablesSvc *service.IptablesService, log *logger.Logger) error {
	ssOutput, err := cmdSvc.RunOutput("ss", "-lntup")
	if err != nil {
		// В минимальных образах iproute2 бывает без поддержки -p.
		ssOutput, err = cmdSvc.RunOutput("ss", "-lntu")
	}
	if err != nil {
		return fmt.Errorf("%w: не удалось выполнить ss -lntup: %v", service.ErrSSHUnverified, err)
	}

	sshPorts := service.SSHPortsFromEnv(os.Getenv)
	report, err := service.CheckMandatoryPorts(requiredPorts, sshPorts, ssOutput)
	log.Info().Ints("required_ports", requiredPorts).Ints("ssh_ports", sshPorts).Str("listen_state", report.String()).
		Msg("Обязательные порты: состояние до применения правил")
	for _, st := range report.Mandatory {
		if st.Listening {
			log.Info().Int("port", st.Port).Str("address", st.Address).Msg("Обязательный порт слушается")
			continue
		}
		log.Warn().Int("port", st.Port).Msg("Обязательный порт не слушается: защищать нечего, но и отрезать его нельзя")
	}
	if err != nil {
		return err
	}
	if unsafe := service.RulesMayBlockMandatoryPorts(iptablesSvc.PlannedRules(), requiredPorts); len(unsafe) > 0 {
		return fmt.Errorf("%w: %s", service.ErrMandatoryPortBlocked, strings.Join(unsafe, "; "))
	}
	log.Info().Ints("protected_ports", report.ProtectedPorts()).Msg("План правил не затрагивает обязательные порты")
	return nil
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

// runRollback возвращает firewall и автозапуск к снимку, снятому до установки.
func runRollback(cmd *cobra.Command, args []string) {
	lock, err := service.AcquireLock()
	if err != nil {
		logger.Global().Fatal().Err(err).Msg("Cannot acquire operation lock")
	}
	defer lock.Close()

	log := logger.Global()
	cmdSvc := service.NewCommandService(log.Logger)
	snapshotter := service.NewSnapshotter(log.Logger, cmdSvc, cmdSvc.CommandExists)

	snap, err := snapshotter.Load()
	if errors.Is(err, service.ErrNoSnapshot) {
		log.Fatal().Err(err).Msg("Снимок состояния не найден: откатываться некуда. Установите rkn-guard заново, чтобы снимок был создан")
	}
	if err != nil {
		log.Fatal().Err(err).Msg("Не удалось прочитать снимок состояния")
	}
	log.Info().Str("snapshot", service.FormatSnapshotReport(snap)).Time("created_at", snap.CreatedAt).Msg("Найден снимок состояния")

	if observeOnly {
		log.Info().Msg("Режим наблюдения: снимок показан, восстановление не выполнялось")
		return
	}

	if !confirmYes {
		fmt.Printf("Вернуть firewall к снимку от %s? [y/N]: ", snap.CreatedAt.Format(time.RFC3339))
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(strings.ToLower(line)) != "y" {
			log.Info().Msg("Откат отменён")
			return
		}
	}

	if err := snapshotter.Restore(snap); err != nil {
		log.Fatal().Err(err).Msg("Откат завершён с ошибками: состояние firewall не совпало со снимком")
	}
	log.Info().Msg("Firewall и автозапуск возвращены к состоянию до установки")
}
