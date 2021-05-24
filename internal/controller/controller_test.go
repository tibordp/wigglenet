package controller

import (
	"net"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/stretchr/testify/assert"
	"github.com/tibordp/wigglenet/internal/wireguard"
)

func parseCIDR(cidr string) net.IPNet {
	_, c, _ := net.ParseCIDR(cidr)
	return *c
}

func TestMakePeer2(t *testing.T) {
	result := makePeer(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"wigglenet/public-key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
				"wigglenet/node-ips":   `["192.168.0.1","2001:db8::1234"]`,
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "2001:db8::/64",
			PodCIDRs: []string{
				"2001:db8::/64",
				"10.0.0.0/24",
			},
		},
	})

	expected := &wireguard.Peer{
		Endpoint: net.ParseIP("192.168.0.1"),
		NodeCIDRs: []net.IPNet{
			parseCIDR("192.168.0.1/32"),
			parseCIDR("2001:db8::1234/128"),
		},
		PodCIDRs: []net.IPNet{
			parseCIDR("2001:db8::/64"),
			parseCIDR("10.0.0.0/24"),
		},
		PublicKey: []uint8{
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
			21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
			31,
		},
	}

	assert.Equal(t, expected, result)
}

func TestMakePeerInvalid(t *testing.T) {
	result := makePeer(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"wigglenet/public-key": "AAECAwQFBgcICQoLwdHh8=",
				"wigglenet/node-ips":   `["192.168.0.1","2001:db8::1234"]`,
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "2001:db8::/64",
			PodCIDRs: []string{
				"2001:db8::/64",
				"10.0.0.0/24",
			},
		},
	})

	assert.Nil(t, result)
}

func TestMakePeerInvalid1(t *testing.T) {
	result := makePeer(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"wigglenet/public-key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
				"wigglenet/node-ips":   `["192.168.0.1","2001:db8::12345678"]`,
			},
		},
		Spec: v1.NodeSpec{
			PodCIDR: "2001:db8::/64",
			PodCIDRs: []string{
				"2001:db8::/64",
				"10.0.0.0/24",
			},
		},
	})

	assert.Nil(t, result)
}

func TestMakePeerInvalid2(t *testing.T) {
	result := makePeer(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"wigglenet/public-key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
				"wigglenet/node-ips":   `["192.168.0.1","2001:db8::1234"]`,
			},
		},
		Spec: v1.NodeSpec{},
	})

	assert.Nil(t, result)
}
