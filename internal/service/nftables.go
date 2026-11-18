package service

import (
	"fmt"
	"github.com/Flecksis/rkn-guard/internal/domain"
	"net/netip"
	"os"
	"sort"
	"strings"
)

func nftPrefixes(values []string, ipv6 bool) ([]string, error) {
	seen := map[string]bool{}
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || p.Addr().Is6() != ipv6 || p.Addr().Is4In6() {
			return nil, fmt.Errorf("некорректная подсеть: %s", value)
		}
		seen[p.Masked().String()] = true
	}
	result := make([]string, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}
	sort.Strings(result)
	return result, nil
}

func RenderNFT(networks *domain.NetworkList, exceptions []Exception, logging, setsOnly bool) (string, error) {
	if networks == nil {
		return "", fmt.Errorf("нет списков")
	}
	v4, err := nftPrefixes(networks.IPv4Subnets, false)
	if err != nil {
		return "", err
	}
	v6, err := nftPrefixes(networks.IPv6Subnets, true)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	if !setsOnly {
		out.WriteString("add table inet rkn_guard\n")
		out.WriteString("add set inet rkn_guard blocked4 { type ipv4_addr; flags interval; auto-merge; }\n")
		out.WriteString("add set inet rkn_guard blocked6 { type ipv6_addr; flags interval; auto-merge; }\n")
		out.WriteString("add chain inet rkn_guard input { type filter hook input priority -10; policy accept; }\nflush chain inet rkn_guard input\n")
		out.WriteString("add rule inet rkn_guard input ct state established,related return\n")
		for _, e := range exceptions {
			checked, err := ParseException(e.IP, e.Protocol, fmt.Sprint(e.Port))
			if err != nil || checked != e {
				return "", fmt.Errorf("некорректное исключение")
			}
			family := "ip"
			if netip.MustParseAddr(e.IP).Is6() {
				family = "ip6"
			}
			fmt.Fprintf(&out, "add rule inet rkn_guard input %s saddr %s %s dport %d return\n", family, e.IP, e.Protocol, e.Port)
		}
		for i, family := range []string{"ip", "ip6"} {
			n := 4 + i*2
			if logging {
				fmt.Fprintf(&out, "add rule inet rkn_guard input %s saddr @blocked%d limit rate 10/minute burst 5 packets log prefix \"ANTISCAN-v%d: \" level warn\n", family, n, n)
			}
			fmt.Fprintf(&out, "add rule inet rkn_guard input %s saddr @blocked%d counter drop\n", family, n)
		}
	}
	for i, values := range [][]string{v4, v6} {
		n := 4 + i*2
		fmt.Fprintf(&out, "flush set inet rkn_guard blocked%d\n", n)
		if len(values) > 0 {
			fmt.Fprintf(&out, "add element inet rkn_guard blocked%d { %s }\n", n, strings.Join(values, ", "))
		}
	}
	return out.String(), nil
}

func runNFT(cmd *CommandService, script string) error {
	file, err := os.CreateTemp("", "rkn-guard-*.nft")
	if err != nil {
		return err
	}
	path := file.Name()
	defer os.Remove(path)
	if _, err := file.WriteString(script); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := cmd.Run("nft", "--check", "--file", path); err != nil {
		return err
	}
	return cmd.Run("nft", "--file", path)
}
