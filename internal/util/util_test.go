package util

import (
	"net"
	"net/netip"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddrCompare(t *testing.T) {
	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8:0:3::1"),
		netip.MustParseAddr("2001:db8:0:1::1"),
		netip.MustParseAddr("2001:db8:0:2::1"),
		netip.MustParseAddr("192.168.3.0"),
		netip.MustParseAddr("192.168.4.0"),
		netip.MustParseAddr("2001:db8:0:4::1"),
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("192.168.2.0"),
	}

	expected := []netip.Addr{
		netip.MustParseAddr("192.168.1.0"),
		netip.MustParseAddr("192.168.2.0"),
		netip.MustParseAddr("192.168.3.0"),
		netip.MustParseAddr("192.168.4.0"),
		netip.MustParseAddr("2001:db8:0:1::1"),
		netip.MustParseAddr("2001:db8:0:2::1"),
		netip.MustParseAddr("2001:db8:0:3::1"),
		netip.MustParseAddr("2001:db8:0:4::1"),
	}

	sort.Slice(addrs, func(i, j int) bool {
		return addrs[i].Compare(addrs[j]) < 0
	})

	assert.Equal(t, expected, addrs)
}

func TestInterfacePrefixesFrom(t *testing.T) {
	// Build addresses the way net.Interface.Addrs() returns them: *net.IPNet
	// carrying the host address plus the on-link mask.
	addr := func(ip string, ones, bits int) *net.IPNet {
		return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(ones, bits)}
	}

	in := map[string][]net.Addr{
		"eth0": {
			addr("2001:db8:abcd:1234::5", 64, 128), // routed /64, host bits set
			addr("10.0.0.5", 24, 32),
			addr("fe80::1", 64, 128), // link-local: dropped (not global unicast)
		},
		"lo": {
			addr("::1", 128, 128), // loopback: dropped
		},
		"eth1": {
			&net.IPAddr{IP: net.ParseIP("2001:db8::1")}, // not an *net.IPNet: dropped
		},
	}

	got := interfacePrefixesFrom(in)

	eth0 := got["eth0"]
	if len(eth0) != 2 {
		t.Fatalf("eth0: got %v, want 2 prefixes", eth0)
	}
	// Prefixes preserve host bits and on-link mask length, sorted IPv4 before IPv6.
	assert.Equal(t, "10.0.0.5/24", eth0[0].String())
	assert.Equal(t, "2001:db8:abcd:1234::5/64", eth0[1].String())

	assert.Empty(t, got["lo"], "loopback should be dropped")
	assert.Empty(t, got["eth1"], "non-IPNet addr should be dropped")
}
