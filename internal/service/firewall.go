package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Flecksis/rkn-guard/internal/domain"
)

const FirewallPath = "/etc/rkn-guard-firewall.json"
const FirewallUnitPath = "/etc/systemd/system/rkn-guard-firewall.service"

type FirewallState struct {
	Backend    string             `json:"backend"`
	Logging    bool               `json:"logging"`
	CleanupNFT bool               `json:"cleanup_nft,omitempty"`
	Networks   domain.NetworkList `json:"networks"`
}

func LoadFirewall() (*FirewallState, error) {
	data, err := os.ReadFile(FirewallPath)
	if os.IsNotExist(err) {
		return &FirewallState{Backend: "iptables"}, nil
	}
	if err != nil {
		return nil, err
	}
	var state FirewallState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Backend != "iptables" && state.Backend != "nftables" && state.Backend != "firewalld" {
		return nil, fmt.Errorf("неизвестный firewall: %s", state.Backend)
	}
	return &state, nil
}

func SaveFirewall(state *FirewallState) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(FirewallPath, data, 0600)
}

// Старую установку без настроек оставляем на iptables.
func SelectFirewall(request string, cmd *CommandService) (string, error) {
	if request != "auto" {
		if request != "iptables" && request != "nftables" && request != "firewalld" {
			return "", fmt.Errorf("неизвестный firewall: %s", request)
		}
		return request, nil
	}
	if _, err := os.Stat(FirewallPath); err == nil {
		state, err := LoadFirewall()
		if err != nil {
			return "", err
		}
		return state.Backend, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}
	if data, err := os.ReadFile(IpsetConfigPath); err == nil && (strings.Contains(string(data), ipsetV4Name) || strings.Contains(string(data), ipsetV6Name)) {
		return "iptables", nil
	}
	if cmd.RunQuiet("iptables", "-w", "-S", chainName) == nil || cmd.RunQuiet("ip6tables", "-w", "-S", chainName) == nil {
		return "iptables", nil
	}
	firewalld := cmd.RunQuiet("firewall-cmd", "--state") == nil
	ufw, _ := cmd.RunOutputQuiet("ufw", "status")
	if firewalld && strings.Contains(ufw, "Status: active") {
		return "", fmt.Errorf("одновременно активны UFW и firewalld; выберите один менеджер")
	}
	if firewalld {
		return "firewalld", nil
	}
	if strings.Contains(ufw, "Status: active") {
		return "iptables", nil
	}
	if sets, err := cmd.RunOutputQuiet("ipset", "list", "-name"); err == nil && strings.TrimSpace(sets) != "" {
		return "iptables", nil
	}
	for _, binary := range []string{"iptables-save", "ip6tables-save"} {
		rules, _ := cmd.RunOutputQuiet(binary)
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(line, "-A ") {
				return "iptables", nil
			}
		}
	}
	for _, binary := range []string{"iptables", "ip6tables"} {
		rules, _ := cmd.RunOutputQuiet(binary, "-w", "-S")
		for _, line := range strings.Split(rules, "\n") {
			if strings.HasPrefix(line, "-A ") || strings.HasPrefix(line, "-N ") || strings.HasSuffix(line, " DROP") || strings.HasSuffix(line, " REJECT") {
				return "iptables", nil
			}
		}
	}
	return "nftables", nil
}

func CheckFirewallMode(mode string, cmd *CommandService) error {
	active := cmd.RunQuiet("firewall-cmd", "--state") == nil
	ufw, _ := cmd.RunOutputQuiet("ufw", "status")
	if mode != "iptables" && strings.Contains(ufw, "Status: active") {
		return fmt.Errorf("UFW активен; выберите iptables или сначала отключите UFW")
	}
	if mode == "firewalld" {
		if !active {
			return fmt.Errorf("firewalld не запущен; включите его или выберите другой режим")
		}
		data, err := os.ReadFile("/etc/firewalld/firewalld.conf")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == "FirewallBackend" && strings.TrimSpace(parts[1]) != "nftables" {
				return fmt.Errorf("нужен FirewallBackend=nftables")
			}
		}
	} else if active {
		return fmt.Errorf("firewalld уже управляет firewall; выберите режим firewalld")
	}
	return nil
}

func (s *InstallerService) EnsureFirewallDependencies(mode string) error {
	if mode == "iptables" {
		return s.EnsureDependencies()
	}
	for _, pkg := range []string{"nftables", "python3"} {
		binary := pkg
		if pkg == "nftables" {
			binary = "nft"
		}
		if !s.commandExists(binary) {
			if err := s.installPackage(pkg, getDistroType()); err != nil {
				return err
			}
		}
	}
	return nil
}

func SetupFirewallRestore(cmd *CommandService, mode string) error {
	after := "nftables.service"
	if mode == "firewalld" {
		after += " firewalld.service"
	}
	unit := "[Unit]\nDescription=rkn-guard firewall\nDefaultDependencies=no\nAfter=local-fs.target " + after + "\nBefore=network-pre.target shutdown.target\nConflicts=shutdown.target\nWants=network-pre.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/rkn-guard firewall-restore\nRemainAfterExit=yes\n\n[Install]\nWantedBy=multi-user.target\n"
	if err := atomicWriteFile(FirewallUnitPath, []byte(unit), 0644); err != nil {
		return err
	}
	if err := cmd.DaemonReload(); err != nil {
		return err
	}
	return cmd.EnableService("rkn-guard-firewall.service")
}

func RemoveNFT(cmd *CommandService) error {
	tables, err := cmd.RunOutput("nft", "list", "tables")
	if err != nil {
		return err
	}
	if strings.Contains(tables, "table inet rkn_guard\n") {
		return cmd.Run("nft", "delete", "table", "inet", "rkn_guard")
	}
	return nil
}

func ApplyNFTState(cmd *CommandService, state *FirewallState, setsOnly bool) error {
	entries, err := LoadExceptions(ExceptionsPath)
	if err != nil {
		return err
	}
	networks := state.Networks
	networks.IPv4Subnets = append([]string(nil), networks.IPv4Subnets...)
	networks.IPv6Subnets = append([]string(nil), networks.IPv6Subnets...)
	if err := AddManualNetworks(&networks); err != nil {
		return err
	}
	script, err := RenderNFT(&networks, entries, state.Logging, setsOnly)
	if err != nil {
		return err
	}
	return runNFT(cmd, script)
}

func CommitNFTState(cmd *CommandService, next *FirewallState, setsOnly bool) error {
	previous, err := os.ReadFile(FirewallPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	tables, err := cmd.RunOutput("nft", "list", "tables")
	if err != nil {
		return err
	}
	exists := strings.Contains(tables, "table inet rkn_guard\n")
	var snapshot string
	if exists {
		snapshot, err = cmd.RunOutput("nft", "list", "table", "inet", "rkn_guard")
		if err != nil {
			return err
		}
	}
	if err := ApplyNFTState(cmd, next, setsOnly && exists); err != nil {
		return err
	}
	if err := SaveFirewall(next); err != nil {
		var rollback error
		if exists {
			rollback = runNFT(cmd, "delete table inet rkn_guard\n"+snapshot)
		} else {
			rollback = RemoveNFT(cmd)
		}
		if previous != nil {
			rollback = errors.Join(rollback, atomicWriteFile(FirewallPath, previous, 0600))
		}
		return errors.Join(err, rollback)
	}
	return nil
}
