package service

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

// IptablesCommandService provides high-level iptables/ip6tables operations
type IptablesCommandService struct {
	logger zerolog.Logger
	cmdSvc *CommandService
}

// NewIptablesCommandService creates a new iptables command service
func NewIptablesCommandService(logger zerolog.Logger, cmdSvc *CommandService) *IptablesCommandService {
	return &IptablesCommandService{
		logger: logger,
		cmdSvc: cmdSvc,
	}
}

// IPVersion represents IP version
type IPVersion string

const (
	IPv4 IPVersion = "ipv4"
	IPv6 IPVersion = "ipv6"
)

// Table represents iptables table
type Table string

const (
	TableFilter Table = "filter"
	TableNat    Table = "nat"
	TableMangle Table = "mangle"
	TableRaw    Table = "raw"
)

// Chain represents iptables chain
type Chain string

const (
	ChainInput       Chain = "INPUT"
	ChainOutput      Chain = "OUTPUT"
	ChainForward     Chain = "FORWARD"
	ChainPreRouting  Chain = "PREROUTING"
	ChainPostRouting Chain = "POSTROUTING"
)

// Target represents iptables target
type Target string

const (
	TargetAccept     Target = "ACCEPT"
	TargetDrop       Target = "DROP"
	TargetReject     Target = "REJECT"
	TargetLog        Target = "LOG"
	TargetReturn     Target = "RETURN"
	TargetMasquerade Target = "MASQUERADE"
)

// RulePosition represents where to insert a rule
type RulePosition string

const (
	PositionAppend RulePosition = "append"
	PositionInsert RulePosition = "insert"
)

// getCommand returns the appropriate command for the IP version
func (s *IptablesCommandService) getCommand(version IPVersion) string {
	if version == IPv6 {
		return "ip6tables"
	}
	return "iptables"
}

// CreateChain creates a new chain
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

// DeleteChain deletes a chain
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

// FlushChain flushes all rules from a chain
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

// FlushAll flushes all rules from all chains
func (s *IptablesCommandService) FlushAll(version IPVersion, table Table) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("table", string(table)).
		Msg("Flushing all chains")

	args := []string{"-t", string(table), "-F"}
	return s.cmdSvc.Run(cmd, args...)
}

// ChainExists checks if a chain exists
func (s *IptablesCommandService) ChainExists(version IPVersion, table Table, chainName string) bool {
	cmd := s.getCommand(version)
	args := []string{"-t", string(table), "-L", chainName, "-n"}
	_, err := s.cmdSvc.RunOutputQuiet(cmd, args...)
	return err == nil
}

// RuleExists checks if a rule exists in a chain
func (s *IptablesCommandService) RuleExists(version IPVersion, table Table, chainName string, ruleSpec []string) bool {
	cmd := s.getCommand(version)
	args := append([]string{"-t", string(table), "-C", chainName}, ruleSpec...)
	err := s.cmdSvc.RunQuiet(cmd, args...)
	return err == nil
}

// AppendRule appends a rule to a chain
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

// InsertRule inserts a rule at the beginning of a chain
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

// DeleteRule deletes a rule from a chain
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

// DeleteRuleByNumber deletes a rule by its number in the chain
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

// ListChain lists all rules in a chain
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

// ListAllChains lists all chains in a table
func (s *IptablesCommandService) ListAllChains(version IPVersion, table Table) (string, error) {
	cmd := s.getCommand(version)
	s.logger.Debug().
		Str("version", string(version)).
		Str("table", string(table)).
		Msg("Listing all chains")

	args := []string{"-t", string(table), "-L", "-n", "-v"}
	return s.cmdSvc.RunOutput(cmd, args...)
}

// Save saves iptables rules to a file
func (s *IptablesCommandService) Save(version IPVersion, path string) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("path", path).
		Msg("Saving iptables rules")

	return s.cmdSvc.RunShell(fmt.Sprintf("%s-save > %s", cmd, path))
}

// Restore restores iptables rules from a file
func (s *IptablesCommandService) Restore(version IPVersion, path string) error {
	cmd := s.getCommand(version)
	s.logger.Info().
		Str("version", string(version)).
		Str("path", path).
		Msg("Restoring iptables rules")

	return s.cmdSvc.RunShell(fmt.Sprintf("%s-restore < %s", cmd, path))
}

// RuleBuilder helps build iptables rules
type RuleBuilder struct {
	spec []string
}

// NewRuleBuilder creates a new rule builder
func NewRuleBuilder() *RuleBuilder {
	return &RuleBuilder{
		spec: make([]string, 0),
	}
}

// Protocol sets the protocol
func (rb *RuleBuilder) Protocol(proto string) *RuleBuilder {
	rb.spec = append(rb.spec, "-p", proto)
	return rb
}

// Source sets the source address
func (rb *RuleBuilder) Source(addr string) *RuleBuilder {
	rb.spec = append(rb.spec, "-s", addr)
	return rb
}

// Destination sets the destination address
func (rb *RuleBuilder) Destination(addr string) *RuleBuilder {
	rb.spec = append(rb.spec, "-d", addr)
	return rb
}

// SourcePort sets the source port
func (rb *RuleBuilder) SourcePort(port string) *RuleBuilder {
	rb.spec = append(rb.spec, "--sport", port)
	return rb
}

// DestinationPort sets the destination port
func (rb *RuleBuilder) DestinationPort(port string) *RuleBuilder {
	rb.spec = append(rb.spec, "--dport", port)
	return rb
}

// InInterface sets the input interface
func (rb *RuleBuilder) InInterface(iface string) *RuleBuilder {
	rb.spec = append(rb.spec, "-i", iface)
	return rb
}

// OutInterface sets the output interface
func (rb *RuleBuilder) OutInterface(iface string) *RuleBuilder {
	rb.spec = append(rb.spec, "-o", iface)
	return rb
}

// Match adds a match module
func (rb *RuleBuilder) Match(module string, options ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", module)
	rb.spec = append(rb.spec, options...)
	return rb
}

// MatchSet adds ipset match
func (rb *RuleBuilder) MatchSet(setName, flag string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "set", "--match-set", setName, flag)
	return rb
}

// MatchState adds state match
func (rb *RuleBuilder) MatchState(states ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "state", "--state", strings.Join(states, ","))
	return rb
}

// MatchConntrack adds conntrack match
func (rb *RuleBuilder) MatchConntrack(states ...string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "conntrack", "--ctstate", strings.Join(states, ","))
	return rb
}

// MatchLimit adds rate limiting
func (rb *RuleBuilder) MatchLimit(rate, burst string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "limit", "--limit", rate)
	if burst != "" {
		rb.spec = append(rb.spec, "--limit-burst", burst)
	}
	return rb
}

// Jump sets the target/jump
func (rb *RuleBuilder) Jump(target Target) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", string(target))
	return rb
}

// JumpChain sets jump to a custom chain
func (rb *RuleBuilder) JumpChain(chainName string) *RuleBuilder {
	rb.spec = append(rb.spec, "-j", chainName)
	return rb
}

// LogPrefix sets log prefix
func (rb *RuleBuilder) LogPrefix(prefix string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-prefix", prefix)
	return rb
}

// LogLevel sets log level
func (rb *RuleBuilder) LogLevel(level string) *RuleBuilder {
	rb.spec = append(rb.spec, "--log-level", level)
	return rb
}

// Comment adds a comment
func (rb *RuleBuilder) Comment(comment string) *RuleBuilder {
	rb.spec = append(rb.spec, "-m", "comment", "--comment", comment)
	return rb
}

// Build returns the rule specification
func (rb *RuleBuilder) Build() []string {
	return rb.spec
}

// Helper methods for common operations

// AddDropRuleForSet adds a DROP rule for ipset match
func (s *IptablesCommandService) AddDropRuleForSet(version IPVersion, chainName, setName, flag string) error {
	rule := NewRuleBuilder().
		MatchSet(setName, flag).
		Jump(TargetDrop).
		Build()
	return s.AppendRule(version, TableFilter, chainName, rule)
}

// AddLogRuleForSet adds a LOG rule for ipset match with rate limiting
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

// LinkChainToInput links a custom chain to INPUT chain
func (s *IptablesCommandService) LinkChainToInput(version IPVersion, chainName string, position int) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.InsertRule(version, TableFilter, string(ChainInput), position, rule)
}

// UnlinkChainFromInput unlinks a custom chain from INPUT chain
func (s *IptablesCommandService) UnlinkChainFromInput(version IPVersion, chainName string) error {
	rule := NewRuleBuilder().JumpChain(chainName).Build()
	return s.DeleteRule(version, TableFilter, string(ChainInput), rule)
}
