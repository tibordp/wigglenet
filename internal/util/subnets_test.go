package util

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func parseCIDR(cidr string) net.IPNet {
	_, c, _ := net.ParseCIDR(cidr)
	return *c
}

func TestSummarizeCIDRs(t *testing.T) {
	cidrs := []net.IPNet{
		parseCIDR("192.168.1.0/24"),
		parseCIDR("192.168.2.0/24"),
		parseCIDR("192.168.3.0/24"),
		parseCIDR("192.168.4.0/24"),

		parseCIDR("2001:db8:0:1::/64"),
		parseCIDR("2001:db8:0:2::/64"),
		parseCIDR("2001:db8:0:3::/64"),
		parseCIDR("2001:db8:0:4::/64"),
	}

	expected := []net.IPNet{
		parseCIDR("2001:db8:0:1::/64"),
		parseCIDR("2001:db8:0:2::/63"),
		parseCIDR("2001:db8:0:4::/64"),

		parseCIDR("192.168.1.0/24"),
		parseCIDR("192.168.2.0/23"),
		parseCIDR("192.168.4.0/24"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsOverlapping(t *testing.T) {
	cidrs := []net.IPNet{
		parseCIDR("192.168.1.0/16"),
		parseCIDR("192.168.2.0/24"),
		parseCIDR("192.168.3.0/24"),
		parseCIDR("192.168.4.0/24"),

		parseCIDR("2001:db8:0:1::/48"),
		parseCIDR("2001:db8:0:2::/64"),
		parseCIDR("2001:db8:0:3::/64"),
		parseCIDR("2001:db8:0:4::/64"),
	}

	expected := []net.IPNet{
		parseCIDR("2001:db8::/48"),
		parseCIDR("192.168.0.0/16"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsWholeNet(t *testing.T) {
	cidrs := []net.IPNet{
		parseCIDR("128.0.0.1/1"),
		parseCIDR("0.0.0.0/1"),

		parseCIDR("4000::/2"),
		parseCIDR("::/2"),
		parseCIDR("4000::/1"),
		parseCIDR("8000::/2"),
		parseCIDR("c000::/2"),
	}

	expected := []net.IPNet{
		parseCIDR("::/0"),
		parseCIDR("0.0.0.0/0"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}

func TestSummarizeCIDRsEmbedded(t *testing.T) {
	cidrs := []net.IPNet{
		parseCIDR("192.168.0.0/16"),
		parseCIDR("::ffff:192.168.0.0/120"),
		parseCIDR("::ffff:192.168.1.0/120"),
	}

	expected := []net.IPNet{
		parseCIDR("::ffff:192.168.0.0/119"),
		parseCIDR("192.168.0.0/16"),
	}

	results := SummarizeCIDRs(cidrs)
	assert.Equal(t, expected, results)
}
