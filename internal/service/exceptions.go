package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const ExceptionsPath = "/etc/rkn-guard/exceptions.json"
const exceptionMarker = "rkn-exception"

type Exception struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

func ParseException(ip, protocol, port string) (Exception, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" || addr.Is4In6() {
		return Exception{}, fmt.Errorf("укажите один IPv4 или IPv6 адрес без маски и зоны")
	}
	protocol = strings.ToLower(protocol)
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return Exception{}, fmt.Errorf("порт должен быть числом от 1 до 65535")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || (protocol != "tcp" && protocol != "udp") {
		return Exception{}, fmt.Errorf("нужны TCP или UDP и порт от 1 до 65535")
	}
	return Exception{addr.String(), protocol, n}, nil
}

func LoadExceptions(path string) ([]Exception, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []Exception
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	seen := map[Exception]bool{}
	for i, entry := range entries {
		normalized, err := ParseException(entry.IP, entry.Protocol, strconv.Itoa(entry.Port))
		if err != nil {
			return nil, err
		}
		if seen[normalized] {
			return nil, fmt.Errorf("повтор исключения")
		}
		entries[i] = normalized
		seen[normalized] = true
	}
	return entries, nil
}

func (e Exception) version() IPVersion {
	if netip.MustParseAddr(e.IP).Is4() {
		return IPv4
	}
	return IPv6
}
func (e Exception) rule() []string {
	return []string{"-s", e.IP, "-p", e.Protocol, "--dport", strconv.Itoa(e.Port), "-m", "comment", "--comment", exceptionMarker, "-j", "RETURN"}
}
func exceptionLines(entries []Exception, version IPVersion) string {
	var out strings.Builder
	for _, e := range entries {
		if e.version() == version {
			fmt.Fprintf(&out, "-A %s %s\n", chainName, strings.Join(e.rule(), " "))
		}
	}
	return out.String()
}

// Удаляем только свои исключения. Правила блокировки остаются на месте.
func (s *IptablesService) syncExceptions(entries []Exception, version IPVersion) error {
	name := "iptables"
	if version == IPv6 {
		name = "ip6tables"
	}
	output, err := s.cmdSvc.RunOutput(name, "-w", "-S", chainName)
	if err != nil {
		return err
	}
	number := 0
	var remove []int
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "-A ") {
			number++
			if strings.Contains(line, "--comment "+exceptionMarker) || strings.Contains(line, "--comment \""+exceptionMarker+"\"") {
				remove = append(remove, number)
			}
		}
	}
	for i := len(remove) - 1; i >= 0; i-- {
		if err := s.iptablesCmd.DeleteRuleByNumber(version, TableFilter, chainName, remove[i]); err != nil {
			return err
		}
	}
	position := 2
	for _, e := range entries {
		if e.version() == version {
			if err := s.iptablesCmd.InsertRule(version, TableFilter, chainName, position, e.rule()); err != nil {
				return err
			}
			position++
		}
	}
	return nil
}

// Сначала сохраняем конфигурацию, затем применяем; при ошибке возвращаем прежнюю.
func (s *IptablesService) ChangeException(action string, entry Exception) error {
	old, err := LoadExceptions(ExceptionsPath)
	if err != nil {
		return err
	}
	next := append([]Exception(nil), old...)
	found := -1
	for i, e := range next {
		if e == entry {
			found = i
		}
	}
	switch action {
	case "add":
		if found >= 0 {
			return fmt.Errorf("исключение уже есть")
		}
		next = append(next, entry)
	case "delete":
		if found < 0 {
			return fmt.Errorf("исключение не найдено")
		}
		next = append(next[:found], next[found+1:]...)
	default:
		return fmt.Errorf("неизвестное действие")
	}
	if err := os.MkdirAll(filepath.Dir(ExceptionsPath), 0755); err != nil {
		return err
	}
	save := func(entries []Exception) error {
		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {
			return err
		}
		return atomicWriteFile(ExceptionsPath, data, 0600)
	}
	apply := func(entries []Exception) error {
		for _, version := range []IPVersion{IPv4, IPv6} {
			if err := s.syncExceptions(entries, version); err != nil {
				return err
			}
		}
		return s.Save()
	}
	if err := save(next); err != nil {
		return err
	}
	if err := apply(next); err != nil {
		return errors.Join(err, save(old), apply(old))
	}
	return nil
}
