package service

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
)

const (
	chainName = "SCANNERS-BLOCK"
)

// iptablesCommands — операции над цепочками, нужные установщику.
// Интерфейс позволяет проверять атомарность IPv4/IPv6 без живого netfilter.
type iptablesCommands interface {
	ChainExists(version IPVersion, table Table, chainName string) bool
	CreateChain(version IPVersion, table Table, chainName string) error
	DeleteChain(version IPVersion, table Table, chainName string) error
	FlushChain(version IPVersion, table Table, chainName string) error
	RuleExists(version IPVersion, table Table, chainName string, ruleSpec []string) bool
	AppendRule(version IPVersion, table Table, chainName string, ruleSpec []string) error
	InsertRule(version IPVersion, table Table, chainName string, position int, ruleSpec []string) error
	DeleteRule(version IPVersion, table Table, chainName string, ruleSpec []string) error
	DeleteRuleByNumber(version IPVersion, table Table, chainName string, ruleNum int) error
	Save(version IPVersion, path string) error
	LinkChainToInput(version IPVersion, chainName string, position int) error
	UnlinkChainFromInput(version IPVersion, chainName string) error
	ListChainRules(version IPVersion, table Table, chainName string) (string, error)
}

// IptablesService управляет правилами iptables и ip6tables.
type IptablesService struct {
	logger        zerolog.Logger
	enableLogging bool
	observeOnly   bool
	cmdSvc        *CommandService
	iptablesCmd   iptablesCommands
}

// SetObserveOnly включает режим наблюдения: firewall не изменяется.
func (s *IptablesService) SetObserveOnly(v bool) {
	s.observeOnly = v
}

// NewIptablesService создаёт сервис управления iptables.
func NewIptablesService(logger zerolog.Logger, cmdSvc *CommandService, enableLogging bool) *IptablesService {
	return &IptablesService{
		logger:        logger,
		enableLogging: enableLogging,
		cmdSvc:        cmdSvc,
		iptablesCmd:   NewIptablesCommandService(logger, cmdSvc),
	}
}

// chainState фиксирует, что установщик успел изменить в одном семействе IP.
// Нужен, чтобы откатить частичное применение: либо оба набора (v4 и v6), либо ни одного.
type chainState struct {
	version  IPVersion
	existed  bool
	snapshot string
	linked   bool
}

// SetupChain создаёт цепочки и добавляет правила.
//
// Атомарность IPv4/IPv6: если IPv6-часть падает, изменения IPv4 откатываются,
// чтобы не осталось состояния «v4 защищён, v6 нет».
func (s *IptablesService) SetupChain() error {
	s.logger.Info().Msg("Настройка цепочек iptables")

	// FIX-1: в режиме наблюдения firewall не трогаем.
	if s.observeOnly {
		s.logger.Warn().Msg("Режим --observe-only: цепочки iptables не создаются")
		return nil
	}

	if _, err := LoadExceptions(ExceptionsPath); err != nil {
		return err
	}
	// Если UFW активен, напрямую к INPUT не подключаемся:
	// правила будут вызываться через ufw-before-input.
	linkToInput := !s.isUFWActive()
	if !linkToInput {
		s.logger.Info().Msg("UFW обнаружен - правила будут добавлены в ufw-before-input")
	}

	// Настраиваем IPv4.
	v4, err := s.setupVersionChain(IPv4, ipsetV4Name, linkToInput)
	if err != nil {
		return errors.Join(fmt.Errorf("failed to setup IPv4 chain: %w", err), s.undoChainState(v4))
	}

	// Настраиваем IPv6.
	v6, err := s.setupVersionChain(IPv6, ipsetV6Name, linkToInput)
	if err != nil {
		rollbackErr := errors.Join(s.undoChainState(v6), s.undoChainState(v4))
		if rollbackErr != nil {
			rollbackErr = fmt.Errorf("откат IPv4/IPv6 неполный, проверьте iptables-save: %w", rollbackErr)
		}
		return errors.Join(fmt.Errorf("failed to setup IPv6 chain: %w", err), rollbackErr)
	}

	s.logger.Info().Msg("Цепочки iptables настроены")
	return nil
}

// undoChainState возвращает одно семейство к состоянию до setupVersionChain.
func (s *IptablesService) undoChainState(st chainState) error {
	if st.version == "" {
		return nil // до изменений дело не дошло
	}
	var errs []error
	if st.linked {
		if err := s.iptablesCmd.UnlinkChainFromInput(st.version, chainName); err != nil {
			errs = append(errs, fmt.Errorf("%s: снять привязку к INPUT: %w", st.version, err))
		}
	}
	if !st.existed {
		if err := s.iptablesCmd.FlushChain(st.version, TableFilter, chainName); err != nil {
			errs = append(errs, fmt.Errorf("%s: очистить цепочку: %w", st.version, err))
		}
		if err := s.iptablesCmd.DeleteChain(st.version, TableFilter, chainName); err != nil {
			errs = append(errs, fmt.Errorf("%s: удалить цепочку: %w", st.version, err))
		}
		return errors.Join(errs...)
	}
	// Цепочка была до установки: возвращаем её прежний набор правил.
	if err := s.iptablesCmd.FlushChain(st.version, TableFilter, chainName); err != nil {
		errs = append(errs, fmt.Errorf("%s: очистить цепочку: %w", st.version, err))
		return errors.Join(errs...)
	}
	for _, rule := range chainRulesFromListing(st.snapshot) {
		if err := s.iptablesCmd.AppendRule(st.version, TableFilter, chainName, rule); err != nil {
			errs = append(errs, fmt.Errorf("%s: вернуть правило %v: %w", st.version, rule, err))
		}
	}
	return errors.Join(errs...)
}

// chainRulesFromListing вытаскивает спецификации правил из вывода `iptables -S`.
func chainRulesFromListing(listing string) [][]string {
	var rules [][]string
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "-A" {
			continue
		}
		rules = append(rules, fields[2:])
	}
	return rules
}

// PlannedRules возвращает правила, которые установщик добавит в цепочку.
// Используется preflight-проверкой обязательных портов (D9).
func (s *IptablesService) PlannedRules() [][]string {
	established := NewRuleBuilder().MatchConntrack("ESTABLISHED", "RELATED").Jump(TargetReturn).Build()
	var rules [][]string
	for _, ipsetName := range []string{ipsetV4Name, ipsetV6Name} {
		rules = append(rules, established)
		if s.enableLogging {
			prefix := "ANTISCAN-v4: "
			if ipsetName == ipsetV6Name {
				prefix = "ANTISCAN-v6: "
			}
			rules = append(rules, NewRuleBuilder().MatchSet(ipsetName, "src").MatchLimit("10/min", "5").
				Jump(TargetLog).LogPrefix(prefix).LogLevel("4").Build())
		}
		rules = append(rules, NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build())
	}
	return rules
}

// setupVersionChain настраивает SCANNERS-BLOCK для выбранной версии IP.
// Возвращает состояние для отката даже при ошибке.
func (s *IptablesService) setupVersionChain(version IPVersion, ipsetName string, linkToInput bool) (chainState, error) {
	s.logger.Debug().Str("version", string(version)).Msg("Настройка цепочки")

	st := chainState{version: version}
	// Проверяем, существует ли цепочка.
	// При повторной установке добавляем недостающие правила, не снимая защиту.
	if st.existed = s.iptablesCmd.ChainExists(version, TableFilter, chainName); !st.existed {
		s.logger.Info().Str("chain", chainName).Str("version", string(version)).Msg("Создание цепочки")
		if err := s.iptablesCmd.CreateChain(version, TableFilter, chainName); err != nil {
			st.version = ""
			return st, fmt.Errorf("failed to create chain: %w", err)
		}
	} else if listing, err := s.iptablesCmd.ListChainRules(version, TableFilter, chainName); err == nil {
		st.snapshot = listing
	}

	// Без UFW подключаем нашу цепочку напрямую к INPUT.
	if linkToInput {
		if !s.iptablesCmd.RuleExists(version, TableFilter, string(ChainInput), []string{"-j", chainName}) {
			s.logger.Info().Str("version", string(version)).Msg("Привязка цепочки к INPUT")
			if err := s.iptablesCmd.LinkChainToInput(version, chainName, 1); err != nil {
				return st, fmt.Errorf("failed to link chain to INPUT: %w", err)
			}
			st.linked = true
		}
	}

	// Пропускаем ответы на исходящие соединения через ESTABLISHED,RELATED.
	establishedRule := NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, establishedRule) {
		s.logger.Info().Str("version", string(version)).Msg("Добавление правила для установленных соединений")
		if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 1, establishedRule); err != nil {
			return st, fmt.Errorf("failed to add ESTABLISHED rule: %w", err)
		}
	}

	// Если включён журнал, добавляем его правило после ESTABLISHED.
	if s.enableLogging {
		versionLabel := "v4"
		if version == IPv6 {
			versionLabel = "v6"
		}
		logPrefix := fmt.Sprintf("ANTISCAN-%s: ", versionLabel)
		logRule := NewRuleBuilder().
			MatchSet(ipsetName, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix(logPrefix).
			LogLevel("4").
			Build()
		if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, logRule) {
			s.logger.Info().Str("version", string(version)).Msg("Добавление правила логирования")
			if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, 2, logRule); err != nil {
				return st, fmt.Errorf("failed to add LOG rule: %w", err)
			}
		}
	}

	// Ставим DROP после правил ESTABLISHED и LOG.
	dropRule := NewRuleBuilder().MatchSet(ipsetName, "src").Jump(TargetDrop).Build()
	if !s.iptablesCmd.RuleExists(version, TableFilter, chainName, dropRule) {
		s.logger.Info().Str("version", string(version)).Msg("Добавление правила блокировки")
		if err := s.iptablesCmd.AppendRule(version, TableFilter, chainName, dropRule); err != nil {
			return st, fmt.Errorf("failed to add DROP rule: %w", err)
		}
	}

	entries, err := LoadExceptions(ExceptionsPath)
	if err != nil {
		return st, err
	}
	if err := s.syncExceptions(entries, version); err != nil {
		return st, err
	}
	return st, nil
}

// Save сохраняет правила доступным в системе способом.
func (s *IptablesService) Save() error {
	s.logger.Info().Msg("Сохранение правил iptables")

	// FIX-1: режим наблюдения не меняет firewall.
	if s.observeOnly {
		s.logger.Warn().Msg("Режим --observe-only: правила не применяются, firewall не изменяется")
		return nil
	}

	// Если UFW установлен, используем его, даже если он пока выключен.
	if s.cmdSvc.CommandExists("ufw") {
		s.logger.Info().Msg("UFW обнаружен - интеграция с UFW")
		return s.saveWithUFW()
	}

	// Без UFW используем netfilter-persistent, установленный вместе с зависимостями.
	if !s.cmdSvc.CommandExists("netfilter-persistent") {
		return fmt.Errorf("netfilter-persistent не установлен. Запустите установку зависимостей")
	}

	s.logger.Info().Msg("Использование netfilter-persistent")
	return s.saveWithNetfilterPersistent()
}

// isUFWActive проверяет наличие и состояние UFW.
// removeManagedBlock удаляет наш блок из файла before.rules.
func (s *IptablesService) removeManagedBlock(content, startMarker string) string {
	endMarker := "# END SCANNERS-BLOCK"

	for {
		start := strings.Index(content, startMarker)
		if start == -1 {
			break
		}

		endRel := strings.Index(content[start:], endMarker)
		if endRel == -1 {
			s.logger.Warn().Msg("Managed block end marker not found, skipping removal")
			break
		}

		end := start + endRel + len(endMarker)
		// Убираем переводы строк после блока.
		for end < len(content) && (content[end] == '\n' || content[end] == '\r') {
			end++
		}

		content = content[:start] + content[end:]
	}

	return content
}

func (s *IptablesService) isUFWActive() bool {
	if !s.cmdSvc.CommandExists("ufw") {
		return false
	}

	output, err := s.cmdSvc.RunOutput("ufw", "status")
	if err != nil {
		return false
	}

	return strings.Contains(output, "Status: active")
}

// saveWithUFW сохраняет и применяет правила через UFW.
func (s *IptablesService) saveWithUFW() (result error) {
	entries, err := LoadExceptions(ExceptionsPath)
	if err != nil {
		return err
	}
	// Перед включением UFW обязательно проверяем доступ по SSH.
	// Иначе можно потерять доступ к серверу, где UFW пока выключен.
	status, err := s.cmdSvc.RunOutput("ufw", "status")
	if err != nil {
		return fmt.Errorf("cannot query UFW: %w", err)
	}
	wasActive := strings.Contains(status, "Status: active")
	if !wasActive {
		// FIX-1: UFW, выключенный до установки, не включается автоматически.
		// Политику INPUT не меняем: включение UFW с DROP и единственным правилом
		// SSH закрыло бы VPN-порты. Правила некуда ставить — установка падает
		// с ErrUFWInactive, firewall остаётся нетронутым.
		s.logger.Error().Msg("UFW установлен, но выключен — правила не применяются, firewall не изменяется")
		return fmt.Errorf("%w. Разрешите нужные порты (ufw allow <port>/tcp), включите UFW вручную "+
			"(ufw enable) и повторите установку, либо удалите ufw, чтобы rkn-guard работал через "+
			"netfilter-persistent. Автовключения UFW нет намеренно", ErrUFWInactive)
	}
	s.logger.Info().Msg("UFW активен — правила ставятся в ufw-before-input и применяются reload'ом")

	// UFW сохраняет правила автоматически
	// Нужно только добавить наши правила в before.rules

	beforeRulesV4 := "/etc/ufw/before.rules"
	beforeRulesV6 := "/etc/ufw/before6.rules"

	// Читаем текущие before.rules
	contentV4, err := os.ReadFile(beforeRulesV4)
	if err != nil {
		return fmt.Errorf("failed to read UFW before.rules: %w", err)
	}

	contentV6, err := os.ReadFile(beforeRulesV6)
	if err != nil {
		return fmt.Errorf("failed to read UFW before6.rules: %w", err)
	}
	infoV4, err := os.Stat(beforeRulesV4)
	if err != nil {
		return err
	}
	infoV6, err := os.Stat(beforeRulesV6)
	if err != nil {
		return err
	}
	applyAttempted := false
	applySucceeded := false
	defer func() {
		if result == nil {
			return
		}
		result = errors.Join(result, rollbackUFW(s.cmdSvc, applyAttempted && (wasActive || applySucceeded), func() error {
			return errors.Join(atomicWriteFile(beforeRulesV4, contentV4, infoV4.Mode().Perm()), atomicWriteFile(beforeRulesV6, contentV6, infoV6.Mode().Perm()))
		}))
	}()

	// Проверяем есть ли уже наша цепочка
	markerV4 := "# SCANNERS-BLOCK chain - managed by antiscan"
	markerV6 := "# SCANNERS-BLOCK chain - managed by antiscan"

	// Удаляем старый managed блок если существует (для поддержки обновлений)
	contentV4Str := string(contentV4)
	if strings.Contains(contentV4Str, markerV4) {
		s.logger.Info().Msg("Обнаружен существующий блок SCANNERS-BLOCK в before.rules, обновляем...")
		contentV4Str = s.removeManagedBlock(contentV4Str, markerV4)
	}

	// Добавляем наши правила в before.rules (внутри существующей секции *filter)
	// Генерируем правила используя RuleBuilder
	establishedRuleV4 := strings.Join(NewRuleBuilder().
		MatchConntrack("ESTABLISHED", "RELATED").
		Jump(TargetReturn).
		Build(), " ")

	logRuleV4 := ""
	if s.enableLogging {
		logRuleV4 = fmt.Sprintf("-A %s %s\n", chainName, strings.Join(NewRuleBuilder().
			MatchSet(ipsetV4Name, "src").
			MatchLimit("10/min", "5").
			Jump(TargetLog).
			LogPrefix("\"ANTISCAN-v4: \"").
			LogLevel("4").
			Build(), " "))
	}

	dropRuleV4 := strings.Join(NewRuleBuilder().
		MatchSet(ipsetV4Name, "src").
		Jump(TargetDrop).
		Build(), " ")

	rulesV4 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
# Этот раздел создаёт rkn-guard. Не редактируйте его вручную.
:%s - [0:0]
-A ufw-before-input -j %s
-A %s %s
%s
-A %s %s
# END SCANNERS-BLOCK

`, chainName, chainName, chainName, establishedRuleV4, exceptionLines(entries, IPv4)+logRuleV4, chainName, dropRuleV4)

	// Сохраняем переход перед остальными правилами таблицы filter.
	newContent, err := insertUFWBlock(contentV4Str, rulesV4, "ufw-before-input")
	if err != nil {
		return fmt.Errorf("before.rules: %w", err)
	}
	if err := atomicWriteFile(beforeRulesV4, []byte(newContent), infoV4.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to write UFW rules: %w", err)
	}
	s.logger.Info().Msg("Обновлён UFW before.rules для IPv4")

	if contentV6 != nil {
		// Удаляем старый managed блок если существует (для поддержки обновлений)
		contentV6Str := string(contentV6)
		if strings.Contains(contentV6Str, markerV6) {
			s.logger.Info().Msg("Обнаружен существующий блок SCANNERS-BLOCK в before6.rules, обновляем...")
			contentV6Str = s.removeManagedBlock(contentV6Str, markerV6)
		}

		// Генерируем правила используя RuleBuilder
		establishedRuleV6 := strings.Join(NewRuleBuilder().
			MatchConntrack("ESTABLISHED", "RELATED").
			Jump(TargetReturn).
			Build(), " ")

		logRuleV6 := ""
		if s.enableLogging {
			logRuleV6 = fmt.Sprintf("-A %s %s\n", chainName, strings.Join(NewRuleBuilder().
				MatchSet(ipsetV6Name, "src").
				MatchLimit("10/min", "5").
				Jump(TargetLog).
				LogPrefix("\"ANTISCAN-v6: \"").
				LogLevel("4").
				Build(), " "))
		}

		dropRuleV6 := strings.Join(NewRuleBuilder().
			MatchSet(ipsetV6Name, "src").
			Jump(TargetDrop).
			Build(), " ")

		rulesV6 := fmt.Sprintf(`
# SCANNERS-BLOCK chain - managed by antiscan
# Этот раздел создаёт rkn-guard. Не редактируйте его вручную.
:%s - [0:0]
-A ufw6-before-input -j %s
-A %s %s
%s
-A %s %s
# END SCANNERS-BLOCK

`, chainName, chainName, chainName, establishedRuleV6, exceptionLines(entries, IPv6)+logRuleV6, chainName, dropRuleV6)

		newContent, err := insertUFWBlock(contentV6Str, rulesV6, "ufw6-before-input")
		if err != nil {
			return fmt.Errorf("before6.rules: %w", err)
		}
		if err := atomicWriteFile(beforeRulesV6, []byte(newContent), infoV6.Mode().Perm()); err != nil {
			return fmt.Errorf("failed to write UFW IPv6 rules: %w", err)
		}
	}

	// Применяем правила через reload, не отключая работающий UFW.
	currentV4, err := os.ReadFile(beforeRulesV4)
	if err != nil {
		return err
	}
	currentV6, err := os.ReadFile(beforeRulesV6)
	if err != nil {
		return err
	}
	// Повторная установка с теми же правилами не сбрасывает счётчики UFW.
	if wasActive && string(currentV4) == string(contentV4) && string(currentV6) == string(contentV6) && verifyUFWJumps(s.cmdSvc) == nil {
		return nil
	}
	applyAttempted = true
	if err := applyUFW(s.cmdSvc, wasActive); err != nil {
		return err
	}
	applySucceeded = true
	if err := verifyUFWJumps(s.cmdSvc); err != nil {
		return err // Отложенный откат восстановит файлы и перезагрузит активный UFW.
	}

	// Порядок уже записан в before-файлах, отдельный сервис для перестановки не нужен.

	s.logger.Info().Msg("Правила iptables интегрированы с UFW")
	return nil
}

// createMoveRuleService создаёт старый сервис перестановки правил после запуска UFW.
func (s *IptablesService) createMoveRuleService() error {
	s.logger.Info().Msg("Создание systemd сервиса для поддержания SCANNERS-BLOCK на позиции 1")

	if err := os.WriteFile(MoveRulesServicePath, []byte(MoveRulesServiceTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create systemd service: %w", err)
	}
	s.logger.Info().Str("path", MoveRulesServicePath).Msg("Создан systemd сервис")

	// Просим systemd перечитать файлы сервисов.
	if err := s.cmdSvc.DaemonReload(); err != nil {
		s.logger.Warn().Err(err).Msg("Не удалось перезагрузить systemd daemon")
	}

	// Включаем автозапуск сервиса.
	if err := s.cmdSvc.EnableService("antiscan-move-rules.service"); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	s.logger.Info().Msg("Systemd сервис включён - SCANNERS-BLOCK будет на позиции 1 после перезагрузки")

	return nil
}

// saveWithNetfilterPersistent сохраняет правила через netfilter-persistent.
func (s *IptablesService) saveWithNetfilterPersistent() error {
	// Создаем директорию если не существует
	if err := os.MkdirAll("/etc/iptables", 0755); err != nil {
		return fmt.Errorf("failed to create /etc/iptables: %w", err)
	}

	if err := s.iptablesCmd.Save(IPv4, "/etc/iptables/rules.v4"); err != nil {
		return fmt.Errorf("failed to save iptables: %w", err)
	}
	s.logger.Info().Msg("Правила IPv4 сохранены в /etc/iptables/rules.v4")

	if err := s.iptablesCmd.Save(IPv6, "/etc/iptables/rules.v6"); err != nil {
		return fmt.Errorf("failed to save ip6tables: %w", err)
	}
	s.logger.Info().Msg("Правила IPv6 сохранены в /etc/iptables/rules.v6")

	// Применяем через netfilter-persistent
	if err := s.cmdSvc.Run("netfilter-persistent", "save"); err != nil {
		return fmt.Errorf("netfilter-persistent save failed: %w", err)
	}

	return nil
}
