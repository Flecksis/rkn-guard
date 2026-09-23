package service

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Flecksis/rkn-guard/internal/domain"

	"github.com/rs/zerolog"
)

const maxListBytes = 4 << 20

// Downloader загружает списки подсетей по URL.
type Downloader struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewDownloader создаёт загрузчик списков.
func NewDownloader(logger zerolog.Logger) *Downloader {
	return &Downloader{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Download загружает все источники и собирает общий список подсетей.
func (d *Downloader) Download(urls []string) (*domain.NetworkList, error) {
	if len(urls) == 0 {
		return nil, fmt.Errorf("no list URLs supplied")
	}
	d.logger.Info().Int("url_count", len(urls)).Msg("Началась загрузка списков подсетей")

	networks := domain.NewNetworkList()
	seenSubnets := make(map[string]bool)

	for i, url := range urls {
		d.logger.Info().
			Int("index", i+1).
			Int("total", len(urls)).
			Str("url", url).
			Msg("Загрузка списка подсетей")

		subnets, err := d.downloadSingle(url)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", url, err)
		}

		added := 0
		valid := 0
		for i, subnet := range subnets {
			subnet, _, _ = strings.Cut(subnet, "#")
			subnet = strings.TrimSpace(strings.TrimPrefix(subnet, "\ufeff"))
			if subnet == "" || strings.HasPrefix(subnet, "#") {
				continue
			}

			// Проверяем формат и убираем дубликаты.
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				addr, addrErr := netip.ParseAddr(subnet)
				if addrErr != nil || addr.Zone() != "" {
					return nil, fmt.Errorf("%s line %d: invalid IP or CIDR %q", url, i+1, subnet)
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			if prefix.Bits() == 0 || prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("%s line %d: unsupported prefix %q", url, i+1, subnet)
			}
			valid++
			subnet = prefix.Masked().String()
			if seenSubnets[subnet] {
				continue
			}
			seenSubnets[subnet] = true

			isIPv6 := isIPv6Subnet(subnet)
			networks.Add(subnet, isIPv6)
			if networks.IPv4Count() > 65536 || networks.IPv6Count() > 65536 {
				return nil, fmt.Errorf("list exceeds ipset capacity (65536 per family)")
			}
			added++
		}

		if valid == 0 {
			return nil, fmt.Errorf("%s: source contains no networks", url)
		}
		d.logger.Info().
			Int("added", added).
			Str("url", url).
			Msg("Загрузка списка подсетей завершена")
	}

	d.logger.Info().
		Int("ipv4_count", networks.IPv4Count()).
		Int("ipv6_count", networks.IPv6Count()).
		Int("total", networks.TotalCount()).
		Msg("Загрузка завершена")

	return networks, nil
}

// downloadSingle загружает один источник.
func (d *Downloader) downloadSingle(url string) ([]string, error) {
	resp, err := d.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	subnets := make([]string, 0)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("source exceeds %d bytes", maxListBytes)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(body)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		subnets = append(subnets, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return subnets, nil
}

// isIPv6Subnet определяет, относится ли подсеть к IPv6.
func isIPv6Subnet(subnet string) bool {
	return strings.Contains(subnet, ":")
}
