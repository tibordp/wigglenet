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

	// Verify netpol chain exists and has jumps to sub-chains
	mainChain := fake.Table.Chains[nftNetpolChain]
	require.NotNil(t, mainChain)

	assert.Equal(t, "ct state established,related accept", mainChain.Rules[0].Rule)
	assert.Equal(t, "meta nfproto ipv6 meta l4proto icmpv6 accept", mainChain.Rules[1].Rule)
	assert.Equal(t, "jump netpol-egress", mainChain.Rules[2].Rule)
	assert.Equal(t, "jump netpol-ingress", mainChain.Rules[3].Rule)

	// Allow rule should be in the ingress sub-chain with "return" verdict
	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	foundAllow := false
	for _, r := range ingressChain.Rules {
		if containsAll(r.Rule, "ip6 daddr 2001:db8::1", "ip6 saddr 2001:db8::2", "return") {
			foundAllow = true
			break
		}
	}
	assert.True(t, foundAllow, "expected ingress allow rule with return verdict")

	// Verify deny set was populated and deny rule is in ingress sub-chain
	ingressV6Set := fake.Table.Sets[nftNetpolIngressV6]
	require.NotNil(t, ingressV6Set)
	assert.Len(t, ingressV6Set.Elements, 1)

	foundDeny := false
	for _, r := range ingressChain.Rules {
		if r.Rule == "ip6 daddr @netpol-ingress-v6 drop" {
			foundDeny = true
			break
		}
	}
	assert.True(t, foundDeny, "expected default deny rule in ingress sub-chain")
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
			PortRules:  []PortRule{{Protocol: "TCP", Port: 80}},
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

	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	// Find the allow rule with port match in ingress sub-chain
	foundAllow := false
	for _, r := range ingressChain.Rules {
		if r.Rule != "" &&
			containsAll(r.Rule, "ip daddr 10.0.0.1", "ip saddr 10.0.0.2", "meta l4proto tcp", "th dport 80", "return") {
			foundAllow = true
			break
		}
	}
	assert.True(t, foundAllow, "expected allow rule with port match and return verdict")
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

	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	// Should use anonymous set syntax for multiple peers in ingress sub-chain
	foundAnonSet := false
	for _, r := range ingressChain.Rules {
		if r.Rule != "" &&
			containsAll(r.Rule, "ip daddr 10.0.0.1", "ip saddr {", "10.0.0.2", "10.0.0.3", "10.0.0.4", "return") {
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

	egressChain := fake.Table.Chains[nftNetpolEgressChain]
	require.NotNil(t, egressChain)

	// Verify egress allow rule in egress sub-chain with return verdict
	foundEgressAllow := false
	for _, r := range egressChain.Rules {
		if containsAll(r.Rule, "ip saddr 10.0.0.1", "ip daddr 192.168.0.0/16", "return") {
			foundEgressAllow = true
			break
		}
	}
	assert.True(t, foundEgressAllow, "expected egress allow rule with return verdict")

	// Verify egress deny set and deny rule in egress sub-chain
	egressV4Set := fake.Table.Sets[nftNetpolEgressV4]
	require.NotNil(t, egressV4Set)
	assert.Len(t, egressV4Set.Elements, 1)

	foundDeny := false
	for _, r := range egressChain.Rules {
		if r.Rule == "ip saddr @netpol-egress-v4 drop" {
			foundDeny = true
			break
		}
	}
	assert.True(t, foundDeny, "expected default deny egress rule in egress sub-chain")
}

func TestNftablesMixedProtocolPorts(t *testing.T) {
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
			PortRules: []PortRule{
				{Protocol: "TCP", Port: 80},
				{Protocol: "UDP", Port: 53},
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

	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	// Should have separate rules for TCP and UDP (not one combined rule)
	foundTCP := false
	foundUDP := false
	for _, r := range ingressChain.Rules {
		if containsAll(r.Rule, "meta l4proto tcp", "th dport 80", "return") {
			foundTCP = true
		}
		if containsAll(r.Rule, "meta l4proto udp", "th dport 53", "return") {
			foundUDP = true
		}
	}
	assert.True(t, foundTCP, "expected TCP port 80 rule")
	assert.True(t, foundUDP, "expected UDP port 53 rule")
}

func TestNftablesEndPort(t *testing.T) {
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
			PortRules:  []PortRule{{Protocol: "TCP", Port: 8000, EndPort: 9000}},
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

	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	foundRange := false
	for _, r := range ingressChain.Rules {
		if containsAll(r.Rule, "meta l4proto tcp", "th dport 8000-9000", "return") {
			foundRange = true
			break
		}
	}
	assert.True(t, foundRange, "expected port range 8000-9000 rule with return verdict")
}

func TestNftablesSCTPPort(t *testing.T) {
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
			PortRules:  []PortRule{{Protocol: "SCTP", Port: 80}},
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

	ingressChain := fake.Table.Chains[nftNetpolIngressChain]
	require.NotNil(t, ingressChain)

	foundSCTP := false
	for _, r := range ingressChain.Rules {
		if containsAll(r.Rule, "meta l4proto sctp", "th dport 80", "return") {
			foundSCTP = true
			break
		}
	}
	assert.True(t, foundSCTP, "expected SCTP port 80 rule with return verdict")
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
