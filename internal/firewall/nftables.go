package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/tibordp/wigglenet/internal/config"
	klog "k8s.io/klog/v2"
	"sigs.k8s.io/knftables"
)

const (
	nftTable = "wigglenet"

	// Chain names
	nftForwardChain        = "forward"
	nftPostroutingChain    = "postrouting"
	nftFirewallChain       = "firewall"
	nftNetpolChain         = "netpol"
	nftNetpolEgressChain   = "netpol-egress"
	nftNetpolIngressChain  = "netpol-ingress"
	nftMasqueradeChain     = "masq"

	// Set names
	nftPodCIDRsV4         = "pod-cidrs-v4"
	nftPodCIDRsV6         = "pod-cidrs-v6"
	nftNetpolIngressV4    = "netpol-ingress-v4"
	nftNetpolIngressV6    = "netpol-ingress-v6"
	nftNetpolEgressV4     = "netpol-egress-v4"
	nftNetpolEgressV6     = "netpol-egress-v6"

	nftSyncInterval = 1 * time.Minute
)

type nftablesManager struct {
	nft             knftables.Interface
	podCIDRUpdates  chan []netip.Prefix
	policyUpdates   chan []NetworkPolicyRule
	currentPodCIDRs []netip.Prefix
	currentPolicies []NetworkPolicyRule
}

func newNftablesManager(podCIDRUpdates chan []netip.Prefix, policyUpdates chan []NetworkPolicyRule) (Manager, error) {
	nft, err := knftables.New(knftables.InetFamily, nftTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create knftables interface: %w", err)
	}

	return &nftablesManager{
		nft:             nft,
		podCIDRUpdates:  podCIDRUpdates,
		policyUpdates:   policyUpdates,
		currentPodCIDRs: []netip.Prefix{},
		currentPolicies: []NetworkPolicyRule{},
	}, nil
}

func (c *nftablesManager) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	logger.Info("started syncing firewall rules (nftables backend)")
	defer logger.Info("finished syncing firewall rules (nftables backend)")

	timer := time.NewTimer(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(nftSyncInterval)
		case newPodCIDRs := <-c.podCIDRUpdates:
			if !reflect.DeepEqual(newPodCIDRs, c.currentPodCIDRs) {
				logger.Info("received new pod CIDR configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(nftSyncInterval)
				c.currentPodCIDRs = newPodCIDRs
			}
		case newPolicies := <-c.policyUpdates:
			if !reflect.DeepEqual(newPolicies, c.currentPolicies) {
				logger.Info("received new NetworkPolicy configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(nftSyncInterval)
				c.currentPolicies = newPolicies
			}
		}

		err := c.syncRules(ctx)
		if err != nil {
			logger.Error(err, "failed to sync nftables rules")
		}
	}
}

func (c *nftablesManager) syncRules(ctx context.Context) error {
	tx := c.nft.NewTransaction()

	// Ensure table exists
	tx.Add(&knftables.Table{
		Comment: knftables.PtrTo("wigglenet firewall rules"),
	})

	// Determine what features are active
	enableFilter := config.FilterIPv4 || config.FilterIPv6
	enableMasquerade := config.MasqueradeIPv4 || config.MasqueradeIPv6
	enableNetpol := config.EnableNetworkPolicy

	// Split pod CIDRs by family
	var v4cidrs, v6cidrs []netip.Prefix
	for _, cidr := range c.currentPodCIDRs {
		if cidr.Addr().Is6() {
			v6cidrs = append(v6cidrs, cidr)
		} else {
			v4cidrs = append(v4cidrs, cidr)
		}
	}

	// Create pod CIDR sets (used by both firewall and masquerade chains)
	if enableFilter || enableMasquerade {
		tx.Add(&knftables.Set{
			Name:    nftPodCIDRsV4,
			Type:    "ipv4_addr",
			Flags:   []knftables.SetFlag{knftables.IntervalFlag},
			Comment: knftables.PtrTo("pod CIDRs (IPv4)"),
		})
		tx.Flush(&knftables.Set{Name: nftPodCIDRsV4})
		for _, cidr := range v4cidrs {
			tx.Add(&knftables.Element{
				Set: nftPodCIDRsV4,
				Key: []string{cidr.String()},
			})
		}

		tx.Add(&knftables.Set{
			Name:    nftPodCIDRsV6,
			Type:    "ipv6_addr",
			Flags:   []knftables.SetFlag{knftables.IntervalFlag},
			Comment: knftables.PtrTo("pod CIDRs (IPv6)"),
		})
		tx.Flush(&knftables.Set{Name: nftPodCIDRsV6})
		for _, cidr := range v6cidrs {
			tx.Add(&knftables.Element{
				Set: nftPodCIDRsV6,
				Key: []string{cidr.String()},
			})
		}
	}

	// Add all regular chains first (before base chains reference them via jump rules).
	// knftables Fake validates jump targets exist at rule-add time.
	if enableFilter {
		tx.Add(&knftables.Chain{Name: nftFirewallChain})
	}
	if enableNetpol {
		tx.Add(&knftables.Chain{Name: nftNetpolEgressChain})
		tx.Add(&knftables.Chain{Name: nftNetpolIngressChain})
		tx.Add(&knftables.Chain{Name: nftNetpolChain})
	}
	if enableMasquerade {
		tx.Add(&knftables.Chain{Name: nftMasqueradeChain})
	}

	// --- Forward base chain ---
	if enableFilter || enableNetpol {
		tx.Add(&knftables.Chain{
			Name:     nftForwardChain,
			Type:     knftables.PtrTo(knftables.FilterType),
			Hook:     knftables.PtrTo(knftables.ForwardHook),
			Priority: knftables.PtrTo(knftables.FilterPriority),
		})
		tx.Flush(&knftables.Chain{Name: nftForwardChain})

		if enableFilter {
			tx.Add(&knftables.Rule{
				Chain:   nftForwardChain,
				Rule:    "jump " + nftFirewallChain,
				Comment: knftables.PtrTo("global firewall filtering"),
			})
		}
		if enableNetpol {
			tx.Add(&knftables.Rule{
				Chain:   nftForwardChain,
				Rule:    "jump " + nftNetpolChain,
				Comment: knftables.PtrTo("NetworkPolicy enforcement"),
			})
		}
	}

	// --- Postrouting base chain ---
	if enableMasquerade {
		tx.Add(&knftables.Chain{
			Name:     nftPostroutingChain,
			Type:     knftables.PtrTo(knftables.NATType),
			Hook:     knftables.PtrTo(knftables.PostroutingHook),
			Priority: knftables.PtrTo(knftables.SNATPriority),
		})
		tx.Flush(&knftables.Chain{Name: nftPostroutingChain})
		tx.Add(&knftables.Rule{
			Chain:   nftPostroutingChain,
			Rule:    "jump " + nftMasqueradeChain,
			Comment: knftables.PtrTo("masquerade pod traffic"),
		})
	}

	// --- Firewall chain ---
	if enableFilter {
		tx.Flush(&knftables.Chain{Name: nftFirewallChain})

		// Allow established/related
		tx.Add(&knftables.Rule{
			Chain: nftFirewallChain,
			Rule:  "ct state established,related accept",
		})

		// Always allow ICMPv6
		if config.FilterIPv6 {
			tx.Add(&knftables.Rule{
				Chain:   nftFirewallChain,
				Rule:    "meta nfproto ipv6 meta l4proto icmpv6 accept",
				Comment: knftables.PtrTo("allow ICMPv6 (RFC 4890)"),
			})
		}

		// Allow traffic from pod CIDRs via set lookup
		if config.FilterIPv4 {
			tx.Add(&knftables.Rule{
				Chain: nftFirewallChain,
				Rule:  knftables.Concat("ip saddr", "@", nftPodCIDRsV4, "accept"),
			})
		}
		if config.FilterIPv6 {
			tx.Add(&knftables.Rule{
				Chain: nftFirewallChain,
				Rule:  knftables.Concat("ip6 saddr", "@", nftPodCIDRsV6, "accept"),
			})
		}

		// Drop everything else
		tx.Add(&knftables.Rule{
			Chain: nftFirewallChain,
			Rule:  "drop",
		})
	}

	// --- Masquerade chain ---
	if enableMasquerade {
		tx.Flush(&knftables.Chain{Name: nftMasqueradeChain})

		// Skip local destinations
		tx.Add(&knftables.Rule{
			Chain: nftMasqueradeChain,
			Rule:  "fib daddr type local accept",
		})

		// Skip traffic destined to pod CIDRs (no masquerade needed)
		if config.MasqueradeIPv4 {
			tx.Add(&knftables.Rule{
				Chain: nftMasqueradeChain,
				Rule:  knftables.Concat("ip daddr", "@", nftPodCIDRsV4, "accept"),
			})
		}
		if config.MasqueradeIPv6 {
			tx.Add(&knftables.Rule{
				Chain: nftMasqueradeChain,
				Rule:  knftables.Concat("ip6 daddr", "@", nftPodCIDRsV6, "accept"),
			})
		}

		// Masquerade everything else
		tx.Add(&knftables.Rule{
			Chain: nftMasqueradeChain,
			Rule:  "masquerade",
		})
	}

	// --- NetworkPolicy chain ---
	if enableNetpol {
		c.buildNetpolRules(tx)
	}

	return c.nft.Run(ctx, tx)
}

func (c *nftablesManager) buildNetpolRules(tx *knftables.Transaction) {
	// --- Main netpol chain: established/related, then jump to egress + ingress sub-chains ---
	tx.Flush(&knftables.Chain{Name: nftNetpolChain})

	tx.Add(&knftables.Rule{
		Chain: nftNetpolChain,
		Rule:  "ct state established,related accept",
	})
	tx.Add(&knftables.Rule{
		Chain:   nftNetpolChain,
		Rule:    "meta nfproto ipv6 meta l4proto icmpv6 accept",
		Comment: knftables.PtrTo("allow ICMPv6 (RFC 4890)"),
	})
	tx.Add(&knftables.Rule{
		Chain:   nftNetpolChain,
		Rule:    "jump " + nftNetpolEgressChain,
		Comment: knftables.PtrTo("check egress policies"),
	})
	tx.Add(&knftables.Rule{
		Chain:   nftNetpolChain,
		Rule:    "jump " + nftNetpolIngressChain,
		Comment: knftables.PtrTo("check ingress policies"),
	})

	// --- Populate egress and ingress sub-chains ---
	tx.Flush(&knftables.Chain{Name: nftNetpolEgressChain})
	tx.Flush(&knftables.Chain{Name: nftNetpolIngressChain})

	ingressDenyV4 := make(map[netip.Addr]bool)
	ingressDenyV6 := make(map[netip.Addr]bool)
	egressDenyV4 := make(map[netip.Addr]bool)
	egressDenyV6 := make(map[netip.Addr]bool)

	for _, rule := range c.currentPolicies {
		if rule.Action == "deny" {
			for _, podIP := range rule.PodIPs {
				if rule.Direction == "ingress" {
					if podIP.Is4() {
						ingressDenyV4[podIP] = true
					} else {
						ingressDenyV6[podIP] = true
					}
				} else if rule.Direction == "egress" {
					if podIP.Is4() {
						egressDenyV4[podIP] = true
					} else {
						egressDenyV6[podIP] = true
					}
				}
			}
			continue
		}

		// Allow rules use "return" verdict so the packet continues
		// to the next sub-chain check instead of being accepted immediately.
		c.addNetpolAllowRules(tx, rule)
	}

	c.addNetpolDenySets(tx, ingressDenyV4, ingressDenyV6, egressDenyV4, egressDenyV6)
}

func (c *nftablesManager) addNetpolAllowRules(tx *knftables.Transaction, rule NetworkPolicyRule) {
	// Route to the correct sub-chain; use "return" so the packet
	// continues to the next sub-chain instead of being accepted outright.
	chain := nftNetpolIngressChain
	if rule.Direction == "egress" {
		chain = nftNetpolEgressChain
	}

	var v4Allowed, v6Allowed []string

	for _, ip := range rule.AllowedIPs {
		if ip.Is4() {
			v4Allowed = append(v4Allowed, ip.String())
		} else {
			v6Allowed = append(v6Allowed, ip.String())
		}
	}
	for _, cidr := range rule.AllowedCIDRs {
		if cidr.Addr().Is4() {
			v4Allowed = append(v4Allowed, cidr.String())
		} else {
			v6Allowed = append(v6Allowed, cidr.String())
		}
	}

	portMatches := buildPortMatches(rule)

	for _, podIP := range rule.PodIPs {
		isV4 := podIP.Is4()

		var allowed []string
		if isV4 {
			allowed = v4Allowed
		} else {
			allowed = v6Allowed
		}

		if len(allowed) == 0 {
			continue
		}

		var podMatch, peerMatch string
		if isV4 {
			if rule.Direction == "ingress" {
				podMatch = knftables.Concat("ip daddr", podIP.String())
			} else {
				podMatch = knftables.Concat("ip saddr", podIP.String())
			}
		} else {
			if rule.Direction == "ingress" {
				podMatch = knftables.Concat("ip6 daddr", podIP.String())
			} else {
				podMatch = knftables.Concat("ip6 saddr", podIP.String())
			}
		}

		if len(allowed) == 1 {
			if isV4 {
				if rule.Direction == "ingress" {
					peerMatch = knftables.Concat("ip saddr", allowed[0])
				} else {
					peerMatch = knftables.Concat("ip daddr", allowed[0])
				}
			} else {
				if rule.Direction == "ingress" {
					peerMatch = knftables.Concat("ip6 saddr", allowed[0])
				} else {
					peerMatch = knftables.Concat("ip6 daddr", allowed[0])
				}
			}
		} else {
			anonSet := "{ " + strings.Join(allowed, ", ") + " }"
			if isV4 {
				if rule.Direction == "ingress" {
					peerMatch = "ip saddr " + anonSet
				} else {
					peerMatch = "ip daddr " + anonSet
				}
			} else {
				if rule.Direction == "ingress" {
					peerMatch = "ip6 saddr " + anonSet
				} else {
					peerMatch = "ip6 daddr " + anonSet
				}
			}
		}

		base := podMatch + " " + peerMatch

		if len(portMatches) == 0 {
			tx.Add(&knftables.Rule{
				Chain: chain,
				Rule:  base + " return",
			})
		} else {
			for _, pm := range portMatches {
				tx.Add(&knftables.Rule{
					Chain: chain,
					Rule:  base + " " + pm + " return",
				})
			}
		}
	}
}

func (c *nftablesManager) addNetpolDenySets(tx *knftables.Transaction,
	ingressDenyV4, ingressDenyV6 map[netip.Addr]bool,
	egressDenyV4, egressDenyV6 map[netip.Addr]bool,
) {
	// Ingress deny sets
	tx.Add(&knftables.Set{
		Name:    nftNetpolIngressV4,
		Type:    "ipv4_addr",
		Comment: knftables.PtrTo("pods with ingress NetworkPolicy (IPv4)"),
	})
	tx.Flush(&knftables.Set{Name: nftNetpolIngressV4})
	for ip := range ingressDenyV4 {
		tx.Add(&knftables.Element{
			Set: nftNetpolIngressV4,
			Key: []string{ip.String()},
		})
	}

	tx.Add(&knftables.Set{
		Name:    nftNetpolIngressV6,
		Type:    "ipv6_addr",
		Comment: knftables.PtrTo("pods with ingress NetworkPolicy (IPv6)"),
	})
	tx.Flush(&knftables.Set{Name: nftNetpolIngressV6})
	for ip := range ingressDenyV6 {
		tx.Add(&knftables.Element{
			Set: nftNetpolIngressV6,
			Key: []string{ip.String()},
		})
	}

	// Egress deny sets
	tx.Add(&knftables.Set{
		Name:    nftNetpolEgressV4,
		Type:    "ipv4_addr",
		Comment: knftables.PtrTo("pods with egress NetworkPolicy (IPv4)"),
	})
	tx.Flush(&knftables.Set{Name: nftNetpolEgressV4})
	for ip := range egressDenyV4 {
		tx.Add(&knftables.Element{
			Set: nftNetpolEgressV4,
			Key: []string{ip.String()},
		})
	}

	tx.Add(&knftables.Set{
		Name:    nftNetpolEgressV6,
		Type:    "ipv6_addr",
		Comment: knftables.PtrTo("pods with egress NetworkPolicy (IPv6)"),
	})
	tx.Flush(&knftables.Set{Name: nftNetpolEgressV6})
	for ip := range egressDenyV6 {
		tx.Add(&knftables.Element{
			Set: nftNetpolEgressV6,
			Key: []string{ip.String()},
		})
	}

	// Default deny rules in each sub-chain
	if len(ingressDenyV4) > 0 {
		tx.Add(&knftables.Rule{
			Chain:   nftNetpolIngressChain,
			Rule:    knftables.Concat("ip daddr", "@", nftNetpolIngressV4, "drop"),
			Comment: knftables.PtrTo("default deny ingress (IPv4)"),
		})
	}
	if len(ingressDenyV6) > 0 {
		tx.Add(&knftables.Rule{
			Chain:   nftNetpolIngressChain,
			Rule:    knftables.Concat("ip6 daddr", "@", nftNetpolIngressV6, "drop"),
			Comment: knftables.PtrTo("default deny ingress (IPv6)"),
		})
	}
	if len(egressDenyV4) > 0 {
		tx.Add(&knftables.Rule{
			Chain:   nftNetpolEgressChain,
			Rule:    knftables.Concat("ip saddr", "@", nftNetpolEgressV4, "drop"),
			Comment: knftables.PtrTo("default deny egress (IPv4)"),
		})
	}
	if len(egressDenyV6) > 0 {
		tx.Add(&knftables.Rule{
			Chain:   nftNetpolEgressChain,
			Rule:    knftables.Concat("ip6 saddr", "@", nftNetpolEgressV6, "drop"),
			Comment: knftables.PtrTo("default deny egress (IPv6)"),
		})
	}
}

// buildPortMatches groups PortRules by protocol and returns one nftables match
// expression per protocol group. Returns nil when there are no port restrictions.
func buildPortMatches(rule NetworkPolicyRule) []string {
	if len(rule.PortRules) == 0 {
		return nil
	}

	type protoGroup struct {
		ports      []string
		hasAnyPort bool // true if any entry has Port==0 (match all ports)
	}
	groups := make(map[string]*protoGroup)

	for _, pr := range rule.PortRules {
		proto := strings.ToLower(pr.Protocol)
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			continue
		}
		g, ok := groups[proto]
		if !ok {
			g = &protoGroup{}
			groups[proto] = g
		}
		if pr.Port == 0 {
			g.hasAnyPort = true
		} else if pr.EndPort > 0 && pr.EndPort != pr.Port {
			g.ports = append(g.ports, strconv.Itoa(pr.Port)+"-"+strconv.Itoa(pr.EndPort))
		} else {
			g.ports = append(g.ports, strconv.Itoa(pr.Port))
		}
	}

	var matches []string
	for proto, g := range groups {
		if g.hasAnyPort || len(g.ports) == 0 {
			matches = append(matches, "meta l4proto "+proto)
		} else if len(g.ports) == 1 {
			matches = append(matches, knftables.Concat("meta l4proto", proto, "th dport", g.ports[0]))
		} else {
			matches = append(matches, knftables.Concat("meta l4proto", proto, "th dport { "+strings.Join(g.ports, ", ")+" }"))
		}
	}

	return matches
}
