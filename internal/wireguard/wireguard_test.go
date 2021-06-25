package wireguard

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func parseKey(s string) wgtypes.Key {
	key, _ := wgtypes.ParseKey(s)
	return key
}

func parseCIDR(cidr string) net.IPNet {
	_, c, _ := net.ParseCIDR(cidr)
	return *c
}

func TestCreateChangesetNoChange(t *testing.T) {
	existingPeers := []wgtypes.Peer{
		{
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
		},
	}

	desiredPeers := []Peer{
		{
			Endpoint: net.ParseIP("192.168.0.1"),
			PodCIDRs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
			NodeCIDRs: []net.IPNet{},
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
		},
	}

	actual := createPeerChangeset(existingPeers, desiredPeers)

	assert.Len(t, actual, 0)
}

func TestCreateChangesetAdd(t *testing.T) {
	existingPeers := []wgtypes.Peer{
		{
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
		},
	}

	desiredPeers := []Peer{
		{
			Endpoint: net.ParseIP("192.168.0.1"),
			PodCIDRs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
			NodeCIDRs: []net.IPNet{},
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
		},

		{
			Endpoint: net.ParseIP("192.168.1.1"),
			PodCIDRs: []net.IPNet{
				parseCIDR("192.168.1.0/24"),
				parseCIDR("2001:db8:0:2::/64"),
			},
			NodeCIDRs: []net.IPNet{},
			PublicKey: parseKey("oFFVKLsHSZ5BFTLdKxubHnvprQ5jdssnaW6nzaQMrGY="),
		},
	}

	expected := []wgtypes.PeerConfig{
		{
			PublicKey:         parseKey("oFFVKLsHSZ5BFTLdKxubHnvprQ5jdssnaW6nzaQMrGY="),
			Remove:            false,
			UpdateOnly:        false,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 24601},
			ReplaceAllowedIPs: false,
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.1.0/24"),
				parseCIDR("2001:db8:0:2::/64"),
			},
			PresharedKey:                nil,
			PersistentKeepaliveInterval: nil,
		},
	}

	actual := createPeerChangeset(existingPeers, desiredPeers)

	assert.Equal(t, expected, actual)
}

func TestCreateChangesetRemove(t *testing.T) {
	existingPeers := []wgtypes.Peer{
		{
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
		},
	}

	desiredPeers := []Peer{}

	expected := []wgtypes.PeerConfig{
		{
			PublicKey:         parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Remove:            true,
			UpdateOnly:        false,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
			PresharedKey:                nil,
			PersistentKeepaliveInterval: nil,
		},
	}

	actual := createPeerChangeset(existingPeers, desiredPeers)

	assert.Equal(t, expected, actual)
}

func TestCreateChangesetUpdate(t *testing.T) {
	existingPeers := []wgtypes.Peer{
		{
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Endpoint:  &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
		},
	}

	desiredPeers := []Peer{
		{
			Endpoint: net.ParseIP("192.168.0.1"),
			PodCIDRs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
			},
			NodeCIDRs: []net.IPNet{
				parseCIDR("2001:db8:1::1/128"),
			},
			PublicKey: parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
		},
	}

	expected := []wgtypes.PeerConfig{
		{
			PublicKey:         parseKey("2H+7wEq3SZOfPjNuoWatIUZnHIeR6SEiv5BiJmSJqEg="),
			Remove:            false,
			UpdateOnly:        true,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("192.168.0.1"), Port: 24601},
			ReplaceAllowedIPs: true,
			AllowedIPs: []net.IPNet{
				parseCIDR("192.168.0.0/24"),
				parseCIDR("2001:db8:0:1::/64"),
				parseCIDR("2001:db8:1::1/128"),
			},
			PresharedKey:                nil,
			PersistentKeepaliveInterval: nil,
		},
	}

	actual := createPeerChangeset(existingPeers, desiredPeers)

	assert.Equal(t, expected, actual)
}
