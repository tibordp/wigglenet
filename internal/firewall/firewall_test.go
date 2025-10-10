package firewall

//go:generate mockery --all --exported

import (
	"net"
	"testing"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/firewall/mocks"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func TestSyncFilterWithGlobalFiltering(t *testing.T) {
	// Save original values
	origFilterIPv6 := config.FilterIPv6
	defer func() { config.FilterIPv6 = origFilterIPv6 }()
	
	// Enable global IPv6 filtering for this test
	config.FilterIPv6 = true

	mockIptables := new(mocks.IpTables)
	manager := new(firewallManager)

	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-FIREWALL")).Return(true, nil)

	mockIptables.On("EnsureRule", iptables.Append, iptables.Table("filter"), iptables.ChainForward,
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

	_, cidr, _ := net.ParseCIDR("2001:db8::/64")
	policyRules := []NetworkPolicyRule{} // Empty policy rules for basic test
	manager.syncFilterRules(mockIptables, []net.IPNet{*cidr}, policyRules, true, false)

	mockIptables.AssertExpectations(t)
}

func TestSyncFilterNetworkPolicyOnly(t *testing.T) {
	// Save original values
	origFilterIPv6 := config.FilterIPv6
	defer func() { config.FilterIPv6 = origFilterIPv6 }()
	
	// Disable global IPv6 filtering for this test
	config.FilterIPv6 = false

	mockIptables := new(mocks.IpTables)
	manager := new(firewallManager)

	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-FIREWALL")).Return(true, nil)
	mockIptables.On("EnsureChain", iptables.Table("filter"), iptables.Chain("WIGGLENET-NETPOL")).Return(true, nil)

	// Direct NetworkPolicy rule should be installed when global filtering is disabled
	mockIptables.On("EnsureRule", iptables.Append, iptables.Table("filter"), iptables.ChainForward,
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
-A WIGGLENET-NETPOL -d 2001:db8::1 -s 2001:db8::2 -j RETURN
-A WIGGLENET-NETPOL -j RETURN
COMMIT
`), iptables.NoFlushTables, iptables.NoRestoreCounters).Return(nil)

	// Create a simple NetworkPolicy rule with IPv6 addresses
	policyRules := []NetworkPolicyRule{
		{
			Direction:   "ingress",
			PodIPs:      []net.IP{net.ParseIP("2001:db8::1")},
			AllowedIPs:  []net.IP{net.ParseIP("2001:db8::2")},
			Action:      "allow",
		},
	}

	_, cidr, _ := net.ParseCIDR("2001:db8::/64")
	manager.syncFilterRules(mockIptables, []net.IPNet{*cidr}, policyRules, true, true)

	mockIptables.AssertExpectations(t)
}

func TestSyncNat(t *testing.T) {
	mockIptables := new(mocks.IpTables)
	manager := new(firewallManager)

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

	_, cidr, _ := net.ParseCIDR("2001:db8::/64")
	manager.syncMasqueradeRules(mockIptables, []net.IPNet{*cidr})

	mockIptables.AssertExpectations(t)
}
