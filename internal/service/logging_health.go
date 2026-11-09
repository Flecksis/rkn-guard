package service

import (
	"crypto/rand"
	"fmt"
	"io"
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
// Правила firewall при этом не меняются.
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
			return fmt.Errorf("события ANTISCAN не дошли в оба журнала; проверьте приём сообщений ядра и подключение %s", RsyslogConfigPath)
		}
		time.Sleep(100 * time.Millisecond)
	}
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
