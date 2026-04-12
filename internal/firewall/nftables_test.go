package firewall

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tibordp/wigglenet/internal/config"
	"sigs.k8s.io/knftables"
)

func newTestNftablesManager(nft knftables.Interface) *nftablesManager {
	return &nftablesManager{
		nft:             nft,
		podCIDRUpdates:  make(chan []netip.Prefix),
		policyUpdates:   make(chan []NetworkPolicyRule),
		currentPodCIDRs: []netip.Prefix{},
		currentPolicies: []NetworkPolicyRule{},
	}
}

func TestNftablesSyncFilterRules(t *testing.T) {
	// Save and restore config
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = true
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = false
	config.EnableNetworkPolicy = false

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPodCIDRs = []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	// Verify table was created
	require.NotNil(t, fake.Table)

	// Verify forward chain exists and is a base chain
	fwdChain := fake.Table.Chains[nftForwardChain]
	require.NotNil(t, fwdChain)
	assert.Equal(t, knftables.ForwardHook, *fwdChain.Hook)
	assert.Equal(t, knftables.FilterType, *fwdChain.Type)

	// Verify firewall chain exists
	firewallChain := fake.Table.Chains[nftFirewallChain]
	require.NotNil(t, firewallChain)

	// Verify rules in firewall chain
	rules := firewallChain.Rules
	require.GreaterOrEqual(t, len(rules), 4)

	assert.Equal(t, "ct state established,related accept", rules[0].Rule)
	assert.Equal(t, "meta nfproto ipv6 meta l4proto icmpv6 accept", rules[1].Rule)
	assert.Contains(t, rules[2].Rule, "ip6 saddr @pod-cidrs-v6 accept")
	assert.Equal(t, "drop", rules[3].Rule)

	// Verify pod CIDR set was populated
	v6Set := fake.Table.Sets[nftPodCIDRsV6]
	require.NotNil(t, v6Set)
	assert.Len(t, v6Set.Elements, 1)
	assert.Equal(t, []string{"2001:db8::/64"}, v6Set.Elements[0].Key)
}

func TestNftablesSyncMasqueradeRules(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = false
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = true
	config.EnableNetworkPolicy = false

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPodCIDRs = []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	// Verify postrouting chain
	postChain := fake.Table.Chains[nftPostroutingChain]
	require.NotNil(t, postChain)
	assert.Equal(t, knftables.PostroutingHook, *postChain.Hook)
	assert.Equal(t, knftables.NATType, *postChain.Type)

	// Verify masquerade chain
	masqChain := fake.Table.Chains[nftMasqueradeChain]
	require.NotNil(t, masqChain)

	rules := masqChain.Rules
	require.GreaterOrEqual(t, len(rules), 3)

	assert.Equal(t, "fib daddr type local accept", rules[0].Rule)
	assert.Contains(t, rules[1].Rule, "ip6 daddr @pod-cidrs-v6 accept")
	assert.Equal(t, "masquerade", rules[2].Rule)
}

func TestNftablesSyncNetworkPolicy(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = false
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = false
	config.EnableNetworkPolicy = true

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPodCIDRs = []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/64"),
	}
	manager.currentPolicies = []NetworkPolicyRule{
		{
			Direction:  "ingress",
			PodIPs:     []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			AllowedIPs: []netip.Addr{netip.MustParseAddr("2001:db8::2")},
			Action:     "allow",
		},
		{
			Direction: "ingress",
			PodIPs:    []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			Action:    "deny",
		},
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	// Verify netpol chain exists
	netpolChain := fake.Table.Chains[nftNetpolChain]
	require.NotNil(t, netpolChain)

	rules := netpolChain.Rules
	// Should have: ct state, icmpv6, allow rule, deny rule (via set)
	require.GreaterOrEqual(t, len(rules), 3)

	assert.Equal(t, "ct state established,related accept", rules[0].Rule)
	assert.Equal(t, "meta nfproto ipv6 meta l4proto icmpv6 accept", rules[1].Rule)

	// Allow rule for the specific ingress policy
	assert.Contains(t, rules[2].Rule, "ip6 daddr 2001:db8::1")
	assert.Contains(t, rules[2].Rule, "ip6 saddr 2001:db8::2")
	assert.Contains(t, rules[2].Rule, "accept")

	// Verify deny set was populated
	ingressV6Set := fake.Table.Sets[nftNetpolIngressV6]
	require.NotNil(t, ingressV6Set)
	assert.Len(t, ingressV6Set.Elements, 1)

	// Verify deny rule using set
	// Find the deny rule (it should reference the set)
	foundDeny := false
	for _, r := range rules {
		if r.Rule == "ip6 daddr @netpol-ingress-v6 drop" {
			foundDeny = true
			break
		}
	}
	assert.True(t, foundDeny, "expected default deny rule using ingress set")
}

func TestNftablesNetworkPolicyWithPorts(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = false
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = false
	config.EnableNetworkPolicy = true

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPolicies = []NetworkPolicyRule{
		{
			Direction:  "ingress",
			PodIPs:     []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			AllowedIPs: []netip.Addr{netip.MustParseAddr("10.0.0.2")},
			Ports:      []int{80},
			Protocol:   "TCP",
			Action:     "allow",
		},
		{
			Direction: "ingress",
			PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			Action:    "deny",
		},
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	netpolChain := fake.Table.Chains[nftNetpolChain]
	require.NotNil(t, netpolChain)

	// Find the allow rule with port match
	foundAllow := false
	for _, r := range netpolChain.Rules {
		if r.Rule != "" &&
			containsAll(r.Rule, "ip daddr 10.0.0.1", "ip saddr 10.0.0.2", "meta l4proto tcp", "th dport 80", "accept") {
			foundAllow = true
			break
		}
	}
	assert.True(t, foundAllow, "expected allow rule with port match")
}

func TestNftablesDualStack(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = true
	config.FilterIPv6 = true
	config.MasqueradeIPv4 = true
	config.MasqueradeIPv6 = true
	config.EnableNetworkPolicy = false

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPodCIDRs = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("2001:db8::/64"),
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	// Both pod CIDR sets should be populated
	v4Set := fake.Table.Sets[nftPodCIDRsV4]
	require.NotNil(t, v4Set)
	assert.Len(t, v4Set.Elements, 1)
	assert.Equal(t, []string{"10.0.0.0/24"}, v4Set.Elements[0].Key)

	v6Set := fake.Table.Sets[nftPodCIDRsV6]
	require.NotNil(t, v6Set)
	assert.Len(t, v6Set.Elements, 1)

	// Firewall chain should have rules for both families
	firewallChain := fake.Table.Chains[nftFirewallChain]
	require.NotNil(t, firewallChain)

	foundV4 := false
	foundV6 := false
	for _, r := range firewallChain.Rules {
		if r.Rule == "ip saddr @pod-cidrs-v4 accept" {
			foundV4 = true
		}
		if r.Rule == "ip6 saddr @pod-cidrs-v6 accept" {
			foundV6 = true
		}
	}
	assert.True(t, foundV4, "expected IPv4 pod CIDR rule")
	assert.True(t, foundV6, "expected IPv6 pod CIDR rule")

	// Masquerade chain should have rules for both families
	masqChain := fake.Table.Chains[nftMasqueradeChain]
	require.NotNil(t, masqChain)

	foundV4Masq := false
	foundV6Masq := false
	for _, r := range masqChain.Rules {
		if r.Rule == "ip daddr @pod-cidrs-v4 accept" {
			foundV4Masq = true
		}
		if r.Rule == "ip6 daddr @pod-cidrs-v6 accept" {
			foundV6Masq = true
		}
	}
	assert.True(t, foundV4Masq, "expected IPv4 masquerade skip rule")
	assert.True(t, foundV6Masq, "expected IPv6 masquerade skip rule")
}

func TestNftablesNetworkPolicyMultiplePeers(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = false
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = false
	config.EnableNetworkPolicy = true

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPolicies = []NetworkPolicyRule{
		{
			Direction: "ingress",
			PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			AllowedIPs: []netip.Addr{
				netip.MustParseAddr("10.0.0.2"),
				netip.MustParseAddr("10.0.0.3"),
				netip.MustParseAddr("10.0.0.4"),
			},
			Action: "allow",
		},
		{
			Direction: "ingress",
			PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			Action:    "deny",
		},
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	netpolChain := fake.Table.Chains[nftNetpolChain]
	require.NotNil(t, netpolChain)

	// Should use anonymous set syntax for multiple peers
	foundAnonSet := false
	for _, r := range netpolChain.Rules {
		if r.Rule != "" &&
			containsAll(r.Rule, "ip daddr 10.0.0.1", "ip saddr {", "10.0.0.2", "10.0.0.3", "10.0.0.4", "accept") {
			foundAnonSet = true
			break
		}
	}
	assert.True(t, foundAnonSet, "expected allow rule with anonymous set for multiple peers")
}

func TestNftablesEgressPolicy(t *testing.T) {
	origFilterIPv4 := config.FilterIPv4
	origFilterIPv6 := config.FilterIPv6
	origMasqIPv4 := config.MasqueradeIPv4
	origMasqIPv6 := config.MasqueradeIPv6
	origNetpol := config.EnableNetworkPolicy
	defer func() {
		config.FilterIPv4 = origFilterIPv4
		config.FilterIPv6 = origFilterIPv6
		config.MasqueradeIPv4 = origMasqIPv4
		config.MasqueradeIPv6 = origMasqIPv6
		config.EnableNetworkPolicy = origNetpol
	}()

	config.FilterIPv4 = false
	config.FilterIPv6 = false
	config.MasqueradeIPv4 = false
	config.MasqueradeIPv6 = false
	config.EnableNetworkPolicy = true

	fake := knftables.NewFake(knftables.InetFamily, nftTable)
	manager := newTestNftablesManager(fake)
	manager.currentPolicies = []NetworkPolicyRule{
		{
			Direction:    "egress",
			PodIPs:       []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			AllowedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			Action:       "allow",
		},
		{
			Direction: "egress",
			PodIPs:    []netip.Addr{netip.MustParseAddr("10.0.0.1")},
			Action:    "deny",
		},
	}

	err := manager.syncRules(context.Background())
	require.NoError(t, err)

	netpolChain := fake.Table.Chains[nftNetpolChain]
	require.NotNil(t, netpolChain)

	// Verify egress allow rule
	foundEgressAllow := false
	for _, r := range netpolChain.Rules {
		if containsAll(r.Rule, "ip saddr 10.0.0.1", "ip daddr 192.168.0.0/16", "accept") {
			foundEgressAllow = true
			break
		}
	}
	assert.True(t, foundEgressAllow, "expected egress allow rule")

	// Verify egress deny set
	egressV4Set := fake.Table.Sets[nftNetpolEgressV4]
	require.NotNil(t, egressV4Set)
	assert.Len(t, egressV4Set.Elements, 1)

	// Verify deny rule
	foundDeny := false
	for _, r := range netpolChain.Rules {
		if r.Rule == "ip saddr @netpol-egress-v4 drop" {
			foundDeny = true
			break
		}
	}
	assert.True(t, foundDeny, "expected default deny egress rule")
}

func containsAll(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
