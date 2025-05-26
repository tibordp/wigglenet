package internal

import (
	"net"
	"testing"
	"time"

	"github.com/tibordp/wigglenet/internal/firewall"
	"github.com/stretchr/testify/assert"
)

func TestSeparateChannelArchitecture(t *testing.T) {
	// Create channels
	podCIDRUpdates := make(chan []net.IPNet, 1)
	policyUpdates := make(chan []firewall.NetworkPolicyRule, 1)

	// Test that channels are separate and don't interfere
	
	// Send pod CIDR update
	_, cidr1, _ := net.ParseCIDR("10.0.0.0/24")
	_, cidr2, _ := net.ParseCIDR("fd00::/64")
	podCIDRs := []net.IPNet{*cidr1, *cidr2}
	
	go func() {
		podCIDRUpdates <- podCIDRs
	}()

	// Send policy update
	policyRules := []firewall.NetworkPolicyRule{
		{
			Direction: "ingress",
			PodIPs:    []net.IP{net.ParseIP("10.0.0.10")},
			AllowedIPs: []net.IP{net.ParseIP("10.0.0.20")},
			Ports:     []int{80},
			Protocol:  "TCP",
			Action:    "allow",
		},
	}
	
	go func() {
		policyUpdates <- policyRules
	}()

	// Verify we can receive both independently
	select {
	case receivedCIDRs := <-podCIDRUpdates:
		assert.Len(t, receivedCIDRs, 2)
		assert.Equal(t, "10.0.0.0/24", receivedCIDRs[0].String())
		assert.Equal(t, "fd00::/64", receivedCIDRs[1].String())
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timed out waiting for pod CIDR update")
	}

	select {
	case receivedPolicies := <-policyUpdates:
		assert.Len(t, receivedPolicies, 1)
		assert.Equal(t, "ingress", receivedPolicies[0].Direction)
		assert.Equal(t, "10.0.0.10", receivedPolicies[0].PodIPs[0].String())
		assert.Equal(t, "10.0.0.20", receivedPolicies[0].AllowedIPs[0].String())
		assert.Len(t, receivedPolicies[0].Ports, 1)
		assert.Equal(t, 80, receivedPolicies[0].Ports[0])
		assert.Equal(t, "TCP", receivedPolicies[0].Protocol)
		assert.Equal(t, "allow", receivedPolicies[0].Action)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timed out waiting for policy update")
	}
}

func TestFirewallManagerChannels(t *testing.T) {
	// Test that firewall manager can be created with separate channels
	podCIDRUpdates := make(chan []net.IPNet)
	policyUpdates := make(chan []firewall.NetworkPolicyRule)

	manager := firewall.New(podCIDRUpdates, policyUpdates)
	assert.NotNil(t, manager)
}