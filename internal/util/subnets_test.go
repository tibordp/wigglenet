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
