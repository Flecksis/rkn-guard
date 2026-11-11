package service

import (
	"errors"
	"fmt"
	"github.com/Flecksis/rkn-guard/internal/domain"
	"net/netip"
	"os"
	"strings"
)

const ManualIPsPath = "/opt/rkn-guard-manual.list"

func LoadManualIPs() ([]string, error) {
	data, err := os.ReadFile(ManualIPsPath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []string
	for _, line := range strings.Fields(string(data)) {
		addr, err := netip.ParseAddr(line)
		if err != nil || addr.Zone() != "" {
			return nil, fmt.Errorf("некорректный ручной IP: %s", line)
		}
		entries = append(entries, addr.Unmap().String())
	}
	return entries, nil
}

func AddManualNetworks(networks *domain.NetworkList) error {
	entries, err := LoadManualIPs()
	if err != nil {
		return err
	}
	for _, ip := range entries {
		addr := netip.MustParseAddr(ip)
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		networks.Add(fmt.Sprintf("%s/%d", ip, bits), addr.Is6())
	}
	return nil
}

func (s *IpsetService) ChangeManualIP(action, ip string) (message string, result error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return "", fmt.Errorf("укажите один IP без маски и зоны")
	}
	addr = addr.Unmap()
	ip = addr.String()
	entries, err := LoadManualIPs()
	if err != nil {
		return "", err
	}
	set := ipsetV4Name
	if addr.Is6() {
		set = ipsetV6Name
	}
	verb := "add"
	if action == "delete" {
		verb = "del"
	} else if action != "add" {
		return "", fmt.Errorf("неизвестное действие")
	}
	oldConfig, configErr := os.ReadFile(IpsetConfigPath)
	if configErr != nil && !os.IsNotExist(configErr) {
		return "", configErr
	}
	oldManual, manualErr := os.ReadFile(ManualIPsPath)
	if manualErr != nil && !os.IsNotExist(manualErr) {
		return "", manualErr
	}
	changed := false
	runtimeChanged := false
	defer func() {
		if result == nil || !changed {
			return
		}
		inverse := "del"
		if action == "delete" {
			inverse = "add"
		}
		restore := func(path string, data []byte, readErr error) error {
			if os.IsNotExist(readErr) {
				err := os.Remove(path)
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			return atomicWriteFile(path, data, 0600)
		}
		var rollback error
		if runtimeChanged {
			rollback = s.cmdSvc.Run("ipset", inverse, set, ip)
		}
		result = errors.Join(result, rollback, restore(IpsetConfigPath, oldConfig, configErr), restore(ManualIPsPath, oldManual, manualErr))
	}()
	stale := false
	if action == "delete" {
		output, err := s.cmdSvc.RunOutput("ipset", "save", set)
		if err != nil {
			return "", err
		}
		exact, recorded := false, false
		for _, entry := range entries {
			if entry == ip {
				recorded = true
			}
		}
		for _, line := range strings.Split(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != "add" {
				continue
			}
			if fields[2] == ip || fields[2] == fmt.Sprintf("%s/%d", ip, addr.BitLen()) {
				exact = true
			}
		}
		if !exact && !recorded {
			return "", fmt.Errorf("отдельной записи IP нет; если адрес заблокирован подсетью, добавьте исключение")
		}
		stale = !exact
	}
	if !stale {
		if err := s.cmdSvc.Run("ipset", verb, set, ip); err != nil {
			return "", err
		}
		runtimeChanged = true
	}
	changed = true
	next := []string{}
	for _, entry := range entries {
		if entry != ip {
			next = append(next, entry)
		}
	}
	if action == "add" {
		next = append(next, ip)
	}
	data, err := s.cmdSvc.RunOutput("ipset", "save")
	if err != nil {
		return "", fmt.Errorf("сохранить наборы не удалось; выполняется откат: %w", err)
	}
	if err := atomicWriteFile(IpsetConfigPath, []byte(data), 0600); err != nil {
		return "", fmt.Errorf("сохранить наборы не удалось; выполняется откат: %w", err)
	}
	if err := atomicWriteFile(ManualIPsPath, []byte(strings.Join(next, "\n")+"\n"), 0600); err != nil {
		return "", fmt.Errorf("сохранить ручной список не удалось; выполняется откат: %w", err)
	}
	if action == "add" {
		return "Ручной бан добавлен и сохранён.", nil
	}
	// Проверяем содержимое набора, чтобы не принять сбой ipset test за отсутствие блокировки.
	output, err := s.cmdSvc.RunOutput("ipset", "save", set)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "add" {
			continue
		}
		prefix, err := netip.ParsePrefix(fields[2])
		if err == nil && prefix.Contains(addr) {
			return "Ручной бан удалён. IP остаётся в заблокированной подсети; используйте исключение.", nil
		}
	}
	return "Ручной бан удалён. Совпадений по подсети нет; обновление списков может вернуть блокировку.", nil
}
