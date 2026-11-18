package service

import (
	"github.com/Flecksis/rkn-guard/internal/domain"
	"strings"
	"testing"
)

func TestNFTRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{"1.2.3.4; flush ruleset", "bad", "2001:db8::/64"} {
		if _, err := RenderNFT(&domain.NetworkList{IPv4Subnets: []string{value}}, nil, true, false); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	if _, err := RenderNFT(domain.NewNetworkList(), []Exception{{IP: "1.2.3.4", Protocol: "tcp; accept", Port: 22}}, true, false); err == nil {
		t.Fatal("accepted bad exception")
	}
}

func TestNFTUpdatePreservesRules(t *testing.T) {
	script, err := RenderNFT(&domain.NetworkList{IPv4Subnets: []string{"192.0.2.1/24", "192.0.2.0/24"}}, nil, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "chain") || strings.Contains(script, "rule ") || strings.Contains(script, "counter") {
		t.Fatal("update touches rules")
	}
	if strings.Count(script, "192.0.2.0/24") != 1 {
		t.Fatal("prefixes not normalized")
	}
	if !strings.Contains(script, "flush set inet rkn_guard blocked6") {
		t.Fatal("stale IPv6 set")
	}
}
