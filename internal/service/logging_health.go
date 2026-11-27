package service

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// CheckHealth отличает пустую статистику от сломанного сбора.
func (s *LoggingService) CheckHealth() error {
	if _, err := exec.LookPath("rsyslogd"); err != nil {
		return fmt.Errorf("не найден rsyslogd: %w", err)
	}
	for _, name := range []string{RsyslogConfigPath, IPv4LogPath, IPv6LogPath} {
		f, err := os.Open(s.path(name))
		if err != nil {
			return err
		}
		info, err := f.Stat()
		f.Close()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s: нужен обычный файл", name)
		}
	}
	for _, unit := range []string{"rsyslog", "antiscan-aggregate.timer"} {
		if err := NewInstallerService(s.logger).runCommand("systemctl", "is-active", "--quiet", unit); err != nil {
			return err
		}
	}
	return nil
}

func (s *LoggingService) verifyDelivery(mode string, timeout time.Duration) error {
	backend, err := SelectFirewall(mode, NewCommandService(s.logger))
	if err != nil {
		return fmt.Errorf("выбор firewall для проверки журнала: %w", err)
	}
	// LOG в iptables принимает не больше 29 байт в префиксе.
	var nonce [5]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	var failures []error
	for _, p := range []struct {
		family, host, path, iptables string
	}{
		{"4", "127.0.0.1", IPv4LogPath, "iptables"},
		{"6", "::1", IPv6LogPath, "ip6tables"},
	} {
		prefix := fmt.Sprintf("ANTISCAN-v%s: chk-%x ", p.family, nonce)
		started := time.Now()
		err := sendLogProbe(backend, p.family, p.host, p.iptables, prefix)
		var socketErr *net.OpError
		if p.family == "6" && errors.As(err, &socketErr) && socketErr.Op == "listen" &&
			(errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)) &&
			ipv6Disabled(s.path("/proc/sys/net/ipv6/conf")) {
			s.logger.Warn().Msg("IPv6 отключён, пропускаю проверку журнала IPv6")
			continue
		}
		if err == nil {
			err = waitForLog(s.path(p.path), prefix, started, timeout)
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("IPv%s (%s): %w", p.family, backend, err))
		}
	}
	return errors.Join(failures...)
}

func ipv6Disabled(conf string) bool {
	entries, err := os.ReadDir(conf)
	if err != nil {
		return os.IsNotExist(err)
	}
	interfaces := 0
	for _, entry := range entries {
		if entry.Name() == "default" {
			continue
		}
		value, err := os.ReadFile(filepath.Join(conf, entry.Name(), "disable_ipv6"))
		if err != nil || strings.TrimSpace(string(value)) != "1" {
			return false
		}
		if entry.Name() != "all" {
			interfaces++
		}
	}
	return interfaces > 0
}

func runProbeCommand(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func sendLogProbe(backend, family, host, iptables, prefix string) (result error) {
	socket, err := net.ListenUDP("udp"+family, &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		if family == "6" && errors.Is(err, syscall.EADDRNOTAVAIL) {
			return fmt.Errorf("открытие UDP на %s: проверьте ip -6 addr show dev lo: %w", host, err)
		}
		return fmt.Errorf("открытие UDP на %s: %w", host, err)
	}
	defer socket.Close()
	addr := socket.LocalAddr().(*net.UDPAddr)
	port := strconv.Itoa(addr.Port)
	var cleanup func() error
	if backend == "iptables" {
		rule := []string{"-o", "lo", "-s", host, "-d", host, "-p", "udp", "--sport", port, "--dport", port, "-j", "LOG", "--log-prefix", prefix}
		err = runProbeCommand(iptables, append([]string{"-w", "5", "-I", "OUTPUT", "1"}, rule...)...)
		cleanup = func() error {
			return runProbeCommand(iptables, append([]string{"-w", "5", "-D", "OUTPUT"}, rule...)...)
		}
	} else {
		table := "rkn_probe_" + family + "_" + port
		proto := "ip"
		if family == "6" {
			proto = "ip6"
		}
		script := fmt.Sprintf("create table inet %s\nadd chain inet %s output { type filter hook output priority -301; policy accept; }\nadd rule inet %s output oifname \"lo\" %s saddr %s %s daddr %s udp sport %s udp dport %s log prefix %q\n", table, table, table, proto, host, proto, host, port, port, prefix)
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, cmdErr := cmd.CombinedOutput(); cmdErr != nil {
			err = fmt.Errorf("nft: %w %s", cmdErr, strings.TrimSpace(string(out)))
		}
		cleanup = func() error { return runProbeCommand("nft", "delete", "table", "inet", table) }
	}
	if err != nil {
		return fmt.Errorf("установка проверочного правила: %w", err)
	}
	defer func() {
		if err := cleanup(); err != nil {
			result = errors.Join(result, fmt.Errorf("удаление проверочного правила: %w", err))
		}
	}()
	if _, err := socket.WriteToUDP([]byte("rkn-guard"), addr); err != nil {
		return fmt.Errorf("отправка UDP на %s: %w", addr, err)
	}
	return nil
}

func waitForLog(path, prefix string, started time.Time, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		ok, err := logContains(path, prefix)
		if err != nil {
			return fmt.Errorf("чтение %s: %w", path, err)
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "-k", "--since", fmt.Sprintf("@%d", started.Unix()), "--grep", strings.TrimSpace(prefix), "-n", "1", "-o", "cat", "--no-pager", "-q")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err == nil && strings.Contains(string(out), strings.TrimSpace(prefix)) {
		return fmt.Errorf("метка есть в журнале ядра, но отсутствует в %s; проверьте вход rsyslog и %s", path, RsyslogConfigPath)
	}
	var exit *exec.ExitError
	if err != nil && !(errors.As(err, &exit) && exit.ExitCode() == 1 && stderr.Len() == 0) {
		return fmt.Errorf("метки нет в %s; не удалось проверить журнал ядра: %w %s", path, err, strings.TrimSpace(stderr.String()))
	}
	return fmt.Errorf("пакет отправлен, метки %q нет в журнале ядра и в %s; проверьте логирование пакетов в ядре", strings.TrimSpace(prefix), path)
}

func logContains(path, token string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return false, err
	}
	start := info.Size() - 65536
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 65536))
	return strings.Contains(string(data), token), err
}
