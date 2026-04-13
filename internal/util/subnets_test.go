package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSummarizeCIDRs(t *testing.T) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.2.0/24"),
		netip.MustParsePrefix("192.168.3.0/24"),
		netip.MustParsePrefix("192.168.4.0/24"),

		netip.MustParsePrefix("2001:db8:0:1::/64"),
		netip.MustParsePrefix("2001:db8:0:2::/64"),
		netip.MustParsePrefix("2001:db8:0:3::/64"),
		netip.MustParsePrefix("2001:db8:0:4::/64"),
	}

	expected := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:0:1::/64"),
		netip.MustParsePrefix("2001:db8:0:2::/63"),
		netip.MustParsePrefix("2001:db8:0:4::/64"),

		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.2.0/23"),
		netip.MustParsePrefix("192.168.4.0/24"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsOverlapping(t *testing.T) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/16"),
		netip.MustParsePrefix("192.168.2.0/24"),
		netip.MustParsePrefix("192.168.3.0/24"),
		netip.MustParsePrefix("192.168.4.0/24"),

		netip.MustParsePrefix("2001:db8:0:1::/48"),
		netip.MustParsePrefix("2001:db8:0:2::/64"),
		netip.MustParsePrefix("2001:db8:0:3::/64"),
		netip.MustParsePrefix("2001:db8:0:4::/64"),
	}

	expected := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsWholeNet(t *testing.T) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("128.0.0.1/1"),
		netip.MustParsePrefix("0.0.0.0/1"),

		netip.MustParsePrefix("4000::/2"),
		netip.MustParsePrefix("::/2"),
		netip.MustParsePrefix("4000::/1"),
		netip.MustParsePrefix("8000::/2"),
		netip.MustParsePrefix("c000::/2"),
	}

	expected := []netip.Prefix{
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsEmbedded(t *testing.T) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("::ffff:192.168.0.0/120"),
		netip.MustParsePrefix("::ffff:192.168.1.0/120"),
	}

	expected := []netip.Prefix{
		netip.MustParsePrefix("::ffff:192.168.0.0/119"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSubtractPrefixesBasic(t *testing.T) {
	// 10.0.0.0/8 except 10.0.5.0/24
	base := netip.MustParsePrefix("10.0.0.0/8")
	excepts := []netip.Prefix{netip.MustParsePrefix("10.0.5.0/24")}

	result := SubtractPrefixes(base, excepts)

	// Result should cover 10.0.0.0/8 minus 10.0.5.0/24
	// Verify the excepted range is not covered and the rest is
	for _, r := range result {
		assert.False(t, r.Overlaps(netip.MustParsePrefix("10.0.5.0/24")) && r.Bits() >= 24,
			"result CIDR %s should not be a subset of the excepted range", r)
	}

	// The union of results should equal base minus except.
	// Quick check: 10.0.4.0 should be in the result, 10.0.5.1 should not
	assert.True(t, containsAddr(result, netip.MustParseAddr("10.0.4.1")))
	assert.False(t, containsAddr(result, netip.MustParseAddr("10.0.5.1")))
	assert.True(t, containsAddr(result, netip.MustParseAddr("10.0.6.1")))
	assert.True(t, containsAddr(result, netip.MustParseAddr("10.1.0.1")))
}

func TestSubtractPrefixesNoOverlap(t *testing.T) {
	base := netip.MustParsePrefix("10.0.0.0/8")
	excepts := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}

	result := SubtractPrefixes(base, excepts)
	assert.Equal(t, []netip.Prefix{base}, result)
}

func TestSubtractPrefixesFullExcept(t *testing.T) {
	base := netip.MustParsePrefix("10.0.0.0/24")
	excepts := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	result := SubtractPrefixes(base, excepts)
	assert.Empty(t, result)
}

func TestSubtractPrefixesMultipleExcepts(t *testing.T) {
	base := netip.MustParsePrefix("10.0.0.0/8")
	excepts := []netip.Prefix{
		netip.MustParsePrefix("10.0.5.0/24"),
		netip.MustParsePrefix("10.0.6.0/24"),
	}

	result := SubtractPrefixes(base, excepts)
	assert.True(t, containsAddr(result, netip.MustParseAddr("10.0.4.1")))
	assert.False(t, containsAddr(result, netip.MustParseAddr("10.0.5.1")))
	assert.False(t, containsAddr(result, netip.MustParseAddr("10.0.6.1")))
	assert.True(t, containsAddr(result, netip.MustParseAddr("10.0.7.1")))
}

func TestSubtractPrefixesIPv6(t *testing.T) {
	base := netip.MustParsePrefix("2001:db8::/32")
	excepts := []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")}

	result := SubtractPrefixes(base, excepts)
	assert.True(t, containsAddr(result, netip.MustParseAddr("2001:db8::1")))
	assert.False(t, containsAddr(result, netip.MustParseAddr("2001:db8:1::1")))
	assert.True(t, containsAddr(result, netip.MustParseAddr("2001:db8:2::1")))
}

// containsAddr checks if any prefix in the list contains the given address.
func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
