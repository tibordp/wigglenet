package util

import (
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
