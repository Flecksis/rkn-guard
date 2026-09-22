package service

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Flecksis/rkn-guard/internal/domain"

	"github.com/rs/zerolog"
)

// Downloader handles downloading subnet lists from URLs
type Downloader struct {
	logger     zerolog.Logger
	httpClient *http.Client
}

// NewDownloader creates a new downloader service
func NewDownloader(logger zerolog.Logger) *Downloader {
	return &Downloader{
		logger: logger,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Download fetches subnets from multiple URLs and returns a NetworkList
func (d *Downloader) Download(urls []string) (*domain.NetworkList, error) {
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
			d.logger.Warn().
				Err(err).
				Str("url", url).
				Msg("Не удалось загрузить из URL, пропуск")
			continue
		}

		added := 0
		for _, subnet := range subnets {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" || strings.HasPrefix(subnet, "#") {
				continue
			}

			// Skip duplicates
			if seenSubnets[subnet] {
				continue
			}
			seenSubnets[subnet] = true

			isIPv6 := isIPv6Subnet(subnet)
			networks.Add(subnet, isIPv6)
			added++
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

// downloadSingle downloads subnets from a single URL
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
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subnets = append(subnets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return subnets, nil
}

// isIPv6Subnet checks if a subnet is IPv6
func isIPv6Subnet(subnet string) bool {
	return strings.Contains(subnet, ":")
}
