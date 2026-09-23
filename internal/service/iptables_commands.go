package service

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// IptablesCommandService выполняет команды iptables и ip6tables.
type IptablesCommandService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewIptablesCommandService создаёт исполнитель команд iptables.
func NewIptablesCommandService(logger zerolog.Logger, cmdSvc *CommandService) *IptablesCommandService {
	return &IptablesCommandService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// IPVersion задаёт версию IP.
type IPVersion string

const (
	IPv4 IPVersion = "ipv4"
	IPv6 IPVersion = "ipv6"
)

// Table задаёт таблицу iptables.
type Table string

const (
	TableFilter Table = "filter"
	TableNat    Table = "nat"
	TableMangle Table = "mangle"
	TableRaw    Table = "raw"
)

// Chain задаёт цепочку iptables.
type Chain string

const (
	ChainInput       Chain = "INPUT"
	ChainOutput      Chain = "OUTPUT"
	ChainForward     Chain = "FORWARD"
	ChainPreRouting  Chain = "PREROUTING"
	ChainPostRouting Chain = "POSTROUTING"
)

// Target задаёт действие правила.
type Target string

const (
	TargetAccept     Target = "ACCEPT"
	TargetDrop       Target = "DROP"
	TargetReject     Target = "REJECT"
	TargetLog        Target = "LOG"
	TargetReturn     Target = "RETURN"
	TargetMasquerade Target = "MASQUERADE"
)

// RulePosition задаёт позицию вставки правила.
type RulePosition string

const (
	PositionAppend RulePosition = "append"
	PositionInsert RulePosition = "insert"
)

// getCommand выбирает iptables или ip6tables.
func (s *IptablesCommandService) getCommand(version IPVersion) string {
	if version == IPv6 {
		return "ip6tables"
	}
	return "iptables"
}

// CreateChain создаёт цепочку.
func (s *IptablesCommandService) CreateChain(version IPVersion, table Table, chainName string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Creating chain")

	args := []string{"-t", string(table), "-N", chainName}
	return s.cmdSvc.Run(cmd, args...)
}

// DeleteChain удаляет цепочку.
func (s *IptablesCommandService) DeleteChain(version IPVersion, table Table, chainName string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Deleting chain")

	args := []string{"-t", string(table), "-X", chainName}
	return s.cmdSvc.Run(cmd, args...)
}

// FlushChain удаляет все правила из цепочки.
func (s *IptablesCommandService) FlushChain(version IPVersion, table Table, chainName string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Flushing chain")

	args := []string{"-t", string(table), "-F", chainName}
	return s.cmdSvc.Run(cmd, args...)
}

// FlushAll очищает все цепочки таблицы.
func (s *IptablesCommandService) FlushAll(version IPVersion, table Table) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("table", string(table)).
		Msg("Flushing all chains")

	args := []string{"-t", string(table), "-F"}
	return s.cmdSvc.Run(cmd, args...)
}

// ChainExists проверяет наличие цепочки.
func (s *IptablesCommandService) ChainExists(version IPVersion, table Table, chainName string) bool {
	cmd := s.getCommand(version)
	args := []string{"-t", string(table), "-L", chainName, "-n"}
	_, err := s.cmdSvc.RunOutputQuiet(cmd, args...)
	return err == nil
}

// RuleExists проверяет наличие правила в цепочке.
func (s *IptablesCommandService) RuleExists(version IPVersion, table Table, chainName string, ruleSpec []string) bool {
	cmd := s.getCommand(version)
	args := append([]string{"-t", string(table), "-C", chainName}, ruleSpec...)
	err := s.cmdSvc.RunQuiet(cmd, args...)
	return err == nil
}

// AppendRule добавляет правило в конец цепочки.
func (s *IptablesCommandService) AppendRule(version IPVersion, table Table, chainName string, ruleSpec []string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("chain", chainName).
		Strs("rule", ruleSpec).
		Msg("Appending rule")

	args := append([]string{"-t", string(table), "-A", chainName}, ruleSpec...)
	return s.cmdSvc.Run(cmd, args...)
}

// InsertRule вставляет правило в указанную позицию.
func (s *IptablesCommandService) InsertRule(version IPVersion, table Table, chainName string, position int, ruleSpec []string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("chain", chainName).
		Int("position", position).
		Strs("rule", ruleSpec).
		Msg("Inserting rule")

	args := []string{"-t", string(table), "-I", chainName}
	if position > 0 {
		args = append(args, fmt.Sprintf("%d", position))
	}
	args = append(args, ruleSpec...)
	return s.cmdSvc.Run(cmd, args...)
}

// DeleteRule удаляет правило из цепочки.
func (s *IptablesCommandService) DeleteRule(version IPVersion, table Table, chainName string, ruleSpec []string) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("chain", chainName).
		Strs("rule", ruleSpec).
		Msg("Deleting rule")

	args := append([]string{"-t", string(table), "-D", chainName}, ruleSpec...)
	return s.cmdSvc.Run(cmd, args...)
}

// DeleteRuleByNumber удаляет правило по номеру.
func (s *IptablesCommandService) DeleteRuleByNumber(version IPVersion, table Table, chainName string, ruleNum int) error {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("chain", chainName).
		Int("rule_number", ruleNum).
		Msg("Deleting rule by number")

	args := []string{"-t", string(table), "-D", chainName, fmt.Sprintf("%d", ruleNum)}
	return s.cmdSvc.Run(cmd, args...)
}

// ListChain возвращает правила цепочки.
func (s *IptablesCommandService) ListChain(version IPVersion, table Table, chainName string) (string, error) {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Str("chain", chainName).
		Msg("Listing chain")

	args := []string{"-t", string(table), "-L", chainName, "-n", "-v"}
	return s.cmdSvc.RunOutput(cmd, args...)
}

// ListAllChains возвращает цепочки таблицы.
func (s *IptablesCommandService) ListAllChains(version IPVersion, table Table) (string, error) {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Msg("Listing all chains")

	args := []string{"-t", string(table), "-L", "-n", "-v"}
	return s.cmdSvc.RunOutput(cmd, args...)
}

// Save сохраняет правила iptables в файл.
func (s *IptablesCommandService) Save(version IPVersion, path string) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("path", path).
		Msg("Saving iptables rules")

	return s.cmdSvc.RunShell(fmt.Sprintf("%s-save > %s", cmd, path))
}

// Restore восстанавливает правила iptables из файла.
func (s *IptablesCommandService) Restore(version IPVersion, path string) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("path", path).
		Msg("Restoring iptables rules")

	return s.cmdSvc.RunShell(fmt.Sprintf("%s-restore < %s", cmd, path))
}

// RuleBuilder собирает аргументы правила iptables.
type RuleBuilder struct {
	spec []string
}

// NewRuleBuilder создаёт сборщик правил.
func NewRuleBuilder() *RuleBuilder {
	return &RuleBuilder{
		spec: make([]string, 0),
	}
}

// Protocol задаёт протокол.
func (rb *RuleBuilder) Protocol(proto string) *RuleBuilder {
	rb.spec = append(rb.spec, "-p", proto)
	return rb
}

// Source задаёт адрес источника.
func (rb *RuleBuilder) Source(addr string) *RuleBuilder {
	rb.spec = append(rb.spec, "-s", addr)
	return rb
}

// Destination задаёт адрес назначения.
func (rb *RuleBuilder) Destination(addr string) *RuleBuilder {
	rb.spec = append(rb.spec, "-d", addr)
	return rb
}

// SourcePort задаёт порт источника.
func (rb *RuleBuilder) SourcePort(port string) *RuleBuilder {
	rb.spec = append(rb.spec, "--sport", port)
	return rb
}

// DestinationPort задаёт порт назначения.
func (rb *RuleBuilder) DestinationPort(port string) *RuleBuilder {
	rb.spec = append(rb.spec, "--dport", port)
	return rb
}

// InInterface задаёт входной интерфейс.
func (rb *RuleBuilder) InInterface(iface string) *RuleBuilder {
	rb.spec = append(rb.spec, "-i", iface)
	return rb
}

// OutInterface задаёт выходной интерфейс.
func (rb *RuleBuilder) OutInterface(iface string) *RuleBuilder {
	rb.spec = append(rb.spec, "-o", iface)
	return rb
}

// Match подключает модуль проверки пакетов.
func (rb *RuleBuilder) Match(module string, options ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", module)
	rb.spec = append(rb.spec, options...)
	return rb
}

// MatchSet добавляет проверку по набору ipset.
func (rb *RuleBuilder) MatchSet(setName, flag string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "set", "--match-set", setName, flag)
	return rb
}

// MatchState добавляет проверку состояния соединения.
func (rb *RuleBuilder) MatchState(states ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "state", "--state", strings.Join(states, ","))
	return rb
}

// MatchConntrack добавляет проверку через conntrack.
func (rb *RuleBuilder) MatchConntrack(states ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "conntrack", "--ctstate", strings.Join(states, ","))
	return rb
}

// MatchLimit ограничивает частоту срабатываний.
func (rb *RuleBuilder) MatchLimit(rate, burst string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "limit", "--limit", rate)
	if burst != "" {
		rb.spec = append(rb.spec, "--limit-burst", burst)
	}
	return rb
}

// Jump задаёт действие правила.
func (rb *RuleBuilder) Jump(target Target) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", string(target))
	return rb
}

// JumpChain задаёт переход в пользовательскую цепочку.
func (rb *RuleBuilder) JumpChain(chainName string) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", chainName)
	return rb
}

// LogPrefix задаёт префикс записи в журнале.
func (rb *RuleBuilder) LogPrefix(prefix string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-prefix", prefix)
	return rb
}

// LogLevel задаёт уровень сообщения.
func (rb *RuleBuilder) LogLevel(level string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-level", level)
	return rb
}

// Comment добавляет комментарий к правилу.
func (rb *RuleBuilder) Comment(comment string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "comment", "--comment", comment)
	return rb
}

// Build возвращает готовые аргументы правила.
func (rb *RuleBuilder) Build() []string {
	return rb.spec
}

// Готовые операции для часто используемых правил.

// AddDropRuleForSet блокирует пакеты по набору ipset.
func (s *IptablesCommandService) AddDropRuleForSet(version IPVersion, chainName, setName, flag string) error {
	rule := NewRuleBuilder().
		MatchSet(setName, flag).
		Jump(TargetDrop).
		Build()
	return s.AppendRule(version, TableFilter, chainName, rule)
}

// AddLogRuleForSet записывает совпадения с набором в журнал с ограничением частоты.
func (s *IptablesCommandService) AddLogRuleForSet(version IPVersion, chainName, setName, flag, logPrefix, rate, burst string) error {
	rule := NewRuleBuilder().
		MatchSet(setName, flag).
		MatchLimit(rate, burst).
		Jump(TargetLog).
		LogPrefix(logPrefix).
		LogLevel("4").
		Build()
	return s.InsertRule(version, TableFilter, chainName, 1, rule)
}

// LinkChainToInput добавляет переход из INPUT в нашу цепочку.
func (s *IptablesCommandService) LinkChainToInput(version IPVersion, chainName string, position int) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.InsertRule(version, TableFilter, string(ChainInput), position, rule)
}

// UnlinkChainFromInput удаляет переход из INPUT.
func (s *IptablesCommandService) UnlinkChainFromInput(version IPVersion, chainName string) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.DeleteRule(version, TableFilter, string(ChainInput), rule)
}
