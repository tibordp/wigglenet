package util

import (
	"net"
	"reflect"
	"testing"
)

func parseCIDR(cidr string) net.IPNet {
	_, c, _ := net.ParseCIDR(cidr)
	return *c
}

func TestSummarizeSubnets(t *testing.T) {
	subnets := []net.IPNet{
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

	results := SummarizeSubnets(subnets)

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("\nexpected: %v\ngot:      %v", expected, results)
	}
}

func TestSummarizeSubnetsOverlapping(t *testing.T) {
	subnets := []net.IPNet{
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

	results := SummarizeSubnets(subnets)

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("\nexpected: %v\ngot:      %v", expected, results)
	}
}

func TestSummarizeSubnetsWholeNet(t *testing.T) {
	subnets := []net.IPNet{
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

	results := SummarizeSubnets(subnets)

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("\nexpected: %v\ngot:      %v", expected, results)
	}
}
