package firewall

import (
	"context"
	"net/netip"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
)

// PortRule represents a single protocol+port(+range) match from a NetworkPolicy.
type PortRule struct {
	Protocol string // "TCP", "UDP", or "SCTP"
	Port     int    // 0 means any port for this protocol
	EndPort  int    // 0 means single port (no range); >0 means port range [Port, EndPort]
}

type NetworkPolicyRule struct {
	PodIPs       []netip.Addr
	AllowedIPs   []netip.Addr
	AllowedCIDRs []netip.Prefix
	PortRules    []PortRule
	Direction    string
	Action       string // "allow" or "deny"
}

type FirewallConfig struct {
	PodCIDRs    []netip.Prefix
	PolicyRules []NetworkPolicyRule
}

func NewConfig(podCIDRs []netip.Prefix) FirewallConfig {
	aggregated := util.SummarizeCIDRs(podCIDRs)
	config := FirewallConfig{
		PodCIDRs:    aggregated,
		PolicyRules: []NetworkPolicyRule{},
	}

	return config
}

func NewConfigWithPolicies(podCIDRs []netip.Prefix, policyRules []NetworkPolicyRule) FirewallConfig {
	aggregated := util.SummarizeCIDRs(podCIDRs)
	config := FirewallConfig{
		PodCIDRs:    aggregated,
		PolicyRules: policyRules,
	}

	return config
}

type Manager interface {
	Run(ctx context.Context)
}

func New(podCIDRUpdates chan []netip.Prefix, policyUpdates chan []NetworkPolicyRule) (Manager, error) {
	switch config.FirewallBackendMode {
	case config.BackendIptables:
		return newIptablesManager(podCIDRUpdates, policyUpdates), nil
	default:
		return newNftablesManager(podCIDRUpdates, policyUpdates)
	}
}
