package service

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
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

// Пишем в журнал ядра без SRC: проверка не увеличивает счётчики атак.
// В native-режиме при необходимости проверяем настоящее сообщение firewall.
func (s *LoggingService) verifyDelivery(timeout time.Duration) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	token := fmt.Sprintf("rkn-guard-check-%x", nonce)
	kernel, err := os.OpenFile(s.path("/dev/kmsg"), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("не удалось проверить доставку событий через /dev/kmsg: %w", err)
	}
	for _, family := range []string{"v4", "v6"} {
		if _, err := fmt.Fprintf(kernel, "<4>ANTISCAN-%s: %s\n", family, token); err != nil {
			kernel.Close()
			return err
		}
	}
	if err := kernel.Close(); err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	probed := false
	for {
		ready := true
		for index, name := range []string{IPv4LogPath, IPv6LogPath} {
			prefix := []string{"ANTISCAN-v4: ", "ANTISCAN-v6: "}[index]
			ok, err := logContains(s.path(name), prefix+token)
			if err != nil {
				return err
			}
			ready = ready && ok
		}
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			if !probed && s.root == "" {
				state, err := LoadFirewall()
				if err == nil && (state.Backend == "nftables" || state.Backend == "firewalld") {
					if err := probeKernelLogging(token); err != nil {
						return err
					}
					probed = true
					deadline = time.Now().Add(timeout)
					continue
				}
			}
			return fmt.Errorf("события ANTISCAN не дошли в оба журнала; проверьте приём сообщений ядра и подключение %s", RsyslogConfigPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// imklog может отбрасывать пользовательские записи в /dev/kmsg.
func probeKernelLogging(token string) (result error) {
	table := "rkn_probe_" + strings.TrimPrefix(token, "rkn-guard-check-")
	script := fmt.Sprintf("add table inet %s\nadd chain inet %s output { type filter hook output priority -301; policy accept; }\n", table, table)
	var sockets []*net.UDPConn
	defer func() {
		for _, socket := range sockets {
			socket.Close()
		}
	}()
	for i, host := range []string{"127.0.0.1", "::1"} {
		socket, err := net.ListenUDP([]string{"udp4", "udp6"}[i], &net.UDPAddr{IP: net.ParseIP(host)})
		if err != nil {
			return err
		}
		sockets = append(sockets, socket)
		port := socket.LocalAddr().(*net.UDPAddr).Port
		script += fmt.Sprintf("add rule inet %s output %s daddr %s udp sport %d udp dport %d log prefix \"ANTISCAN-v%d: %s \"\n", table, []string{"ip", "ip6"}[i], host, port, port, []int{4, 6}[i], token)
	}
	command := exec.Command("nft", "-f", "-")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("проверка журнала ядра: %s: %w", output, err)
	}
	defer func() {
		if output, err := exec.Command("nft", "delete", "table", "inet", table).CombinedOutput(); err != nil {
			result = fmt.Errorf("удаление проверочной таблицы %s: %s: %w", table, output, err)
		}
	}()
	for _, socket := range sockets {
		if _, err := socket.WriteToUDP([]byte(token), socket.LocalAddr().(*net.UDPAddr)); err != nil {
			return err
		}
	}
	return nil
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
