package firewall

//go:generate mockery --all --exported

import (
	"net"
	"testing"

	"github.com/tibordp/wigglenet/internal/firewall/mocks"
	"k8s.io/kubernetes/pkg/util/iptables"
)

func TestSyncFilter(t *testing.T) {
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
	manager.syncFilterRules(mockIptables, []net.IPNet{*cidr}, true)

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
