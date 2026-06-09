package networkpolicy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tibordp/wigglenet/internal/firewall"
)

// TestCanonicalizeRulesDeterministic verifies that two rule sets with identical
// logical content but different ordering (both of the rules themselves and of
// the slices within each rule) collapse to deep-equal results after
// canonicalization. This is what lets the firewall manager's reflect.DeepEqual
// change detection avoid spurious full ruleset rewrites.
func TestCanonicalizeRulesDeterministic(t *testing.T) {
	allowA := firewall.NetworkPolicyRule{
		Direction:    "ingress",
		Action:       "allow",
		PodIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.1")},
		AllowedIPs:   []netip.Addr{netip.MustParseAddr("10.1.0.2"), netip.MustParseAddr("10.1.0.1")},
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.2.0/24"), netip.MustParsePrefix("192.168.1.0/24")},
		PortRules:    []firewall.PortRule{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 80}},
	}
	denyA := firewall.NetworkPolicyRule{
		Direction: "egress",
		Action:    "deny",
		PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
	}

	// Same content, every slice shuffled into a different order.
	allowB := firewall.NetworkPolicyRule{
		Direction:    "ingress",
		Action:       "allow",
		PodIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")},
		AllowedIPs:   []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("10.1.0.2")},
		AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")},
		PortRules:    []firewall.PortRule{{Protocol: "TCP", Port: 80}, {Protocol: "UDP", Port: 53}},
	}
	denyB := denyA

	rulesX := []firewall.NetworkPolicyRule{denyA, allowA}
	rulesY := []firewall.NetworkPolicyRule{allowB, denyB}

	canonicalizeRules(rulesX)
	canonicalizeRules(rulesY)

	assert.Equal(t, rulesX, rulesY, "logically identical rule sets must canonicalize to equal slices")

	// Canonicalization is idempotent.
	again := append([]firewall.NetworkPolicyRule(nil), rulesX...)
	canonicalizeRules(again)
	assert.Equal(t, rulesX, again)
}
