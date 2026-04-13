package firewall

//go:generate mockery --all --exported

import (
	"net/netip"
	"testing"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/firewall/mocks"
	"k8s.io/klog/v2/ktesting"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func TestSyncFilterWithGlobalFiltering(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	// Save original values
	origFilterIPv6 := config.FilterIPv6
	defer func() { config.FilterIPv6 = origFilterIPv6 }()

	// Enable global IPv6 filtering for this test
	config.FilterIPv6 = true

	mockIptables := new(mocks.IpTables)
	manager := new(iptablesManager)

	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-FIREWALL")).Return(true, nil)

	mockIptables.On("EnsureRule", iptables.Prepend, iptables.Table("filter"), iptables.ChainForward,
		"-m",
		"comment",
		"--comment",
		"prevent direct ingress traffic to pods",
		"-j",
		"WIGGLENET-FIREWALL",
	).Return(true, nil)

	mockIptables.On("RestoreAll", []byte(`*filter
-F WIGGLENET-FIREWALL
:WIGGLENET-FIREWALL - [0:0]
-A WIGGLENET-FIREWALL -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
-A WIGGLENET-FIREWALL -p ipv6-icmp -j RETURN
-A WIGGLENET-FIREWALL -s 2001:db8::/64 -j RETURN
-A WIGGLENET-FIREWALL -j DROP
COMMIT
`), iptables.NoFlushTables, iptables.NoRestoreCounters).Return(nil)

	cidr := netip.MustParsePrefix("2001:db8::/64")
	policyRules := []NetworkPolicyRule{} // Empty policy rules for basic test
	manager.syncFilterRules(ctx, mockIptables, []netip.Prefix{cidr}, policyRules, true, false)

	mockIptables.AssertExpectations(t)
}

func TestSyncFilterNetworkPolicyOnly(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	// Save original values
	origFilterIPv6 := config.FilterIPv6
	defer func() { config.FilterIPv6 = origFilterIPv6 }()

	// Disable global IPv6 filtering for this test
	config.FilterIPv6 = false

	mockIptables := new(mocks.IpTables)
	manager := new(iptablesManager)

	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-FIREWALL")).Return(true, nil)
	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-NETPOL")).Return(true, nil)
	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-NETPOL-EGR")).Return(true, nil)
	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-NETPOL-ING")).Return(true, nil)

	mockIptables.On("EnsureRule", iptables.Prepend, iptables.Table("filter"), iptables.ChainForward,
		"-m",
		"comment",
		"--comment",
		"NetworkPolicy enforcement",
		"-j",
		"WIGGLENET-NETPOL",
	).Return(true, nil)

	mockIptables.On("RestoreAll", []byte(`*filter
-F WIGGLENET-NETPOL
:WIGGLENET-NETPOL - [0:0]
-A WIGGLENET-NETPOL -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A WIGGLENET-NETPOL -p ipv6-icmp -j RETURN
-A WIGGLENET-NETPOL -j WIGGLENET-NETPOL-EGR
-A WIGGLENET-NETPOL -j WIGGLENET-NETPOL-ING
-A WIGGLENET-NETPOL -j RETURN
-F WIGGLENET-NETPOL-EGR
:WIGGLENET-NETPOL-EGR - [0:0]
-F WIGGLENET-NETPOL-ING
:WIGGLENET-NETPOL-ING - [0:0]
-A WIGGLENET-NETPOL-ING -d 2001:db8::1 -s 2001:db8::2 -j RETURN
COMMIT
`), iptables.NoFlushTables, iptables.NoRestoreCounters).Return(nil)

	// Create a simple NetworkPolicy rule with IPv6 addresses (no port rules)
	policyRules := []NetworkPolicyRule{
		{
			Direction:  "ingress",
			PodIPs:     []netip.Addr{netip.MustParseAddr("2001:db8::1")},
			AllowedIPs: []netip.Addr{netip.MustParseAddr("2001:db8::2")},
			Action:     "allow",
		},
	}

	cidr := netip.MustParsePrefix("2001:db8::/64")
	manager.syncFilterRules(ctx, mockIptables, []netip.Prefix{cidr}, policyRules, true, true)

	mockIptables.AssertExpectations(t)
}

func TestSyncNat(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	mockIptables := new(mocks.IpTables)
	manager := new(iptablesManager)

	mockIptables.On("EnsureChain", iptables.Table("nat"), iptables.Chain("WIGGLENET-MASQ")).Return(true, nil)
	mockIptables.On("EnsureRule", iptables.Append, iptables.Table("nat"), iptables.ChainPostrouting,
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", "WIGGLENET-MASQ",
		"-m", "comment",
		"--comment", "masquerade non-LOCAL traffic",
	).Return(true, nil)
	mockIptables.On("RestoreAll", []byte(`*nat
-F WIGGLENET-MASQ
:WIGGLENET-MASQ - [0:0]
-A WIGGLENET-MASQ -d 2001:db8::/64 -j RETURN
-A WIGGLENET-MASQ -j MASQUERADE
COMMIT
`), iptables.NoFlushTables, iptables.NoRestoreCounters).Return(nil)

	cidr := netip.MustParsePrefix("2001:db8::/64")
	manager.syncMasqueradeRules(ctx, mockIptables, []netip.Prefix{cidr})

	mockIptables.AssertExpectations(t)
}
