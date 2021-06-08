package util

import (
	"net"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIPCompare(t *testing.T) {
	cidrs := []net.IP{
		net.ParseIP("2001:db8:0:3::1"),
		net.ParseIP("2001:db8:0:1::1"),
		net.ParseIP("2001:db8:0:2::1"),
		net.ParseIP("192.168.3.0"),
		net.ParseIP("192.168.4.0"),
		net.ParseIP("2001:db8:0:4::1"),
		net.ParseIP("192.168.1.0"),
		net.ParseIP("192.168.2.0"),
	}

	expected := []net.IP{
		net.ParseIP("2001:db8:0:1::1"),
		net.ParseIP("2001:db8:0:2::1"),
		net.ParseIP("2001:db8:0:3::1"),
		net.ParseIP("2001:db8:0:4::1"),
		net.ParseIP("192.168.1.0"),
		net.ParseIP("192.168.2.0"),
		net.ParseIP("192.168.3.0"),
		net.ParseIP("192.168.4.0"),
	}

	sort.Slice(cidrs, func(i, j int) bool {
		return IPCompare(cidrs[i], cidrs[j]) < 0
	})

	assert.Equal(t, expected, cidrs)
}
