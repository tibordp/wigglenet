package firewall

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/metrics"

	ipt "k8s.io/kubernetes/pkg/util/iptables"

	klog "k8s.io/klog/v2"
)

const (
	filterChain      = ipt.Chain("WIGGLENET-FIREWALL")
	netpolChain      = ipt.Chain("WIGGLENET-NETPOL")
	netpolEgressChain  = ipt.Chain("WIGGLENET-NETPOL-EGR")
	netpolIngressChain = ipt.Chain("WIGGLENET-NETPOL-ING")
	natChain         = ipt.Chain("WIGGLENET-MASQ")

	// Sync iptables every minute
	syncInterval = 1 * time.Minute
)

type ipTables interface {
	EnsureChain(table ipt.Table, chain ipt.Chain) (bool, error)
	EnsureRule(position ipt.RulePosition, table ipt.Table, chain ipt.Chain, args ...string) (bool, error)
	RestoreAll(data []byte, flush ipt.FlushFlag, counters ipt.RestoreCountersFlag) error
}

type iptablesManager struct {
	ip6tables       ipTables
	ip4tables       ipTables
	podCIDRUpdates  chan []netip.Prefix
	policyUpdates   chan []NetworkPolicyRule
	currentPodCIDRs []netip.Prefix
	currentPolicies []NetworkPolicyRule
}

func newIptablesManager(podCIDRUpdates chan []netip.Prefix, policyUpdates chan []NetworkPolicyRule) Manager {
	ip6tables := ipt.New(ipt.ProtocolIPv6)
	ip4tables := ipt.New(ipt.ProtocolIPv4)

	m := iptablesManager{
		ip6tables:       ip6tables,
		ip4tables:       ip4tables,
		podCIDRUpdates:  podCIDRUpdates,
		policyUpdates:   policyUpdates,
		currentPodCIDRs: []netip.Prefix{},
		currentPolicies: []NetworkPolicyRule{},
	}

	return &m
}

func (c *iptablesManager) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	logger.Info("started syncing firewall rules (iptables backend)")
	defer logger.Info("finished syncing firewall rules (iptables backend)")

	timer := time.NewTimer(0)
	for {
		// Sync rules whenever the configuration changes and at least
		// once per minute (to recreate the rules if they are flushed)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(syncInterval)
		case newPodCIDRs := <-c.podCIDRUpdates:
			if !reflect.DeepEqual(newPodCIDRs, c.currentPodCIDRs) {
				logger.Info("received new pod CIDR configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(syncInterval)
				c.currentPodCIDRs = newPodCIDRs
			}
		case newPolicies := <-c.policyUpdates:
			if !reflect.DeepEqual(newPolicies, c.currentPolicies) {
				logger.Info("received new NetworkPolicy configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(syncInterval)
				c.currentPolicies = newPolicies
			}
		}

		start := time.Now()
		err := c.syncRules(ctx)
		if config.EnableMetrics {
			metrics.RecordFirewallSync("iptables", time.Since(start), err)
		}
		if err != nil {
			// Just log the error, we will retry in one minute if transient
			logger.Error(err, "failed to sync firewall rules")
		}
	}
}

func (c *iptablesManager) syncRules(ctx context.Context) error {
	ip4cidrs := make([]netip.Prefix, 0)
	ip6cidrs := make([]netip.Prefix, 0)

	for _, cidr := range c.currentPodCIDRs {
		if cidr.Addr().Is6() {
			ip6cidrs = append(ip6cidrs, cidr)
		} else {
			ip4cidrs = append(ip4cidrs, cidr)
		}
	}

	// Separate policy rules by IP family
	ip4PolicyRules := make([]NetworkPolicyRule, 0)
	ip6PolicyRules := make([]NetworkPolicyRule, 0)

	for _, rule := range c.currentPolicies {
		hasIPv4 := false
		hasIPv6 := false

		for _, ip := range rule.PodIPs {
			if ip.Is4() {
				hasIPv4 = true
			} else {
				hasIPv6 = true
			}
		}

		if hasIPv4 {
			ip4PolicyRules = append(ip4PolicyRules, rule)
		}
		if hasIPv6 {
			ip6PolicyRules = append(ip6PolicyRules, rule)
		}
	}

	// Apply IPv6 filter rules if filtering is enabled OR if NetworkPolicy is enabled
	if config.FilterIPv6 || config.EnableNetworkPolicy {
		if err := c.syncFilterRules(ctx, c.ip6tables, ip6cidrs, ip6PolicyRules, true, config.EnableNetworkPolicy); err != nil {
			return err
		}
	}

	// Apply IPv4 filter rules if filtering is enabled OR if NetworkPolicy is enabled
	if config.FilterIPv4 || config.EnableNetworkPolicy {
		if err := c.syncFilterRules(ctx, c.ip4tables, ip4cidrs, ip4PolicyRules, false, config.EnableNetworkPolicy); err != nil {
			return err
		}
	}

	if config.MasqueradeIPv6 {
		if err := c.syncMasqueradeRules(ctx, c.ip6tables, ip6cidrs); err != nil {
			return err
		}
	}

	if config.MasqueradeIPv4 {
		if err := c.syncMasqueradeRules(ctx, c.ip4tables, ip4cidrs); err != nil {
			return err
		}
	}

	return nil
}

func (c *iptablesManager) syncMasqueradeRules(ctx context.Context, tables ipTables, nonMasqCidrs []netip.Prefix) error {
	_ = ctx // context not needed for this function, but keeping signature consistent
	if _, err := tables.EnsureChain(ipt.TableNAT, natChain); err != nil {
		return err
	}

	if _, err := tables.EnsureRule(ipt.Append, ipt.TableNAT, ipt.ChainPostrouting,
		"-m", "addrtype", "!", "--dst-type", "LOCAL", "-j", string(natChain),
		"-m", "comment",
		"--comment", "masquerade non-LOCAL traffic"); err != nil {
		return err
	}

	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*nat")
	writeLine(lines, "-F", string(natChain))
	writeLine(lines, ipt.MakeChainLine(natChain))
	for _, cidr := range nonMasqCidrs {
		writeRule(lines, ipt.Append, natChain, "-d", cidr.String(), "-j", "RETURN")
	}
	writeRule(lines, ipt.Append, natChain, "-j", "MASQUERADE")
	writeLine(lines, "COMMIT")

	if err := tables.RestoreAll(lines.Bytes(), ipt.NoFlushTables, ipt.NoRestoreCounters); err != nil {
		return err
	}

	return nil
}

func (c *iptablesManager) syncFilterRules(ctx context.Context, tables ipTables, nonFilterCidrs []netip.Prefix, policyRules []NetworkPolicyRule, isIPv6 bool, enableNetworkPolicy bool) error {
	_ = ctx // context not needed for this function, but keeping signature consistent
	// Determine if we need global filtering (based on config) or just NetworkPolicy filtering
	enableGlobalFiltering := (isIPv6 && config.FilterIPv6) || (!isIPv6 && config.FilterIPv4)

	if _, err := tables.EnsureChain(ipt.TableFilter, filterChain); err != nil {
		return err
	}

	if enableNetworkPolicy {
		if _, err := tables.EnsureChain(ipt.TableFilter, netpolChain); err != nil {
			return err
		}
		if _, err := tables.EnsureChain(ipt.TableFilter, netpolEgressChain); err != nil {
			return err
		}
		if _, err := tables.EnsureChain(ipt.TableFilter, netpolIngressChain); err != nil {
			return err
		}
	}

	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*filter")

	// Main filter chain rules (only if global filtering is enabled)
	if enableGlobalFiltering {
		if _, err := tables.EnsureRule(ipt.Prepend, ipt.TableFilter, ipt.ChainForward,
			"-m", "comment", "--comment", "prevent direct ingress traffic to pods",
			"-j", string(filterChain)); err != nil {
			return err
		}

		// Clear filter chain
		writeLine(lines, "-F", string(filterChain))
		writeLine(lines, ipt.MakeChainLine(filterChain))

		writeRule(lines, ipt.Append, filterChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
		if isIPv6 {
			// This is a bit opinionated, but I prefer to always allow ICMPv6 through. This is necesary at least
			// for path MTU discovery, but echo-request is also very useful for diagnostics.
			// https://datatracker.ietf.org/doc/html/rfc4890
			writeRule(lines, ipt.Append, filterChain, "-p", "ipv6-icmp", "-j", "RETURN")
		}

		// Allow traffic from pod CIDRs (original wigglenet behavior)
		for _, cidr := range nonFilterCidrs {
			writeRule(lines, ipt.Append, filterChain, "-s", cidr.String(), "-j", "RETURN")
		}
		writeRule(lines, ipt.Append, filterChain, "-j", "DROP")
	}

	// NetworkPolicy chain rules (set up if NetworkPolicy is enabled)
	if enableNetworkPolicy {
		// Insert at top of FORWARD so we run before KUBE-FORWARD's
		// mark-based ACCEPT rule that would otherwise bypass policy checks.
		if _, err := tables.EnsureRule(ipt.Prepend, ipt.TableFilter, ipt.ChainForward,
			"-m", "comment", "--comment", "NetworkPolicy enforcement",
			"-j", string(netpolChain)); err != nil {
			return err
		}

		// Main netpol chain: established/related, then jump to egress + ingress sub-chains
		writeLine(lines, "-F", string(netpolChain))
		writeLine(lines, ipt.MakeChainLine(netpolChain))

		writeRule(lines, ipt.Append, netpolChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN")
		if isIPv6 {
			writeRule(lines, ipt.Append, netpolChain, "-p", "ipv6-icmp", "-j", "RETURN")
		}
		writeRule(lines, ipt.Append, netpolChain, "-j", string(netpolEgressChain))
		writeRule(lines, ipt.Append, netpolChain, "-j", string(netpolIngressChain))
		writeRule(lines, ipt.Append, netpolChain, "-j", "RETURN")

		// Egress sub-chain
		writeLine(lines, "-F", string(netpolEgressChain))
		writeLine(lines, ipt.MakeChainLine(netpolEgressChain))

		// Ingress sub-chain
		writeLine(lines, "-F", string(netpolIngressChain))
		writeLine(lines, ipt.MakeChainLine(netpolIngressChain))

		for _, rule := range policyRules {
			c.writeNetworkPolicyRules(lines, rule, isIPv6)
		}
	}

	writeLine(lines, "COMMIT")

	if err := tables.RestoreAll(lines.Bytes(), ipt.NoFlushTables, ipt.NoRestoreCounters); err != nil {
		return err
	}

	return nil
}

// iptablesPortGroup holds a protocol and its associated port expressions,
// grouped from the per-port PortRules in a NetworkPolicyRule.
type iptablesPortGroup struct {
	proto    string   // lowercase: "tcp", "udp", "sctp"
	ports    []string // individual port or range expressions ("80", "8000:9000")
	matchAll bool     // true if any entry has Port==0 → match all ports for this proto
}

func groupPortRulesForIPTables(portRules []PortRule) []iptablesPortGroup {
	type acc struct {
		ports    []string
		matchAll bool
	}
	m := make(map[string]*acc)
	// Preserve insertion order of protocols
	var order []string

	for _, pr := range portRules {
		proto := strings.ToLower(pr.Protocol)
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			continue
		}
		a, ok := m[proto]
		if !ok {
			a = &acc{}
			m[proto] = a
			order = append(order, proto)
		}
		if pr.Port == 0 {
			a.matchAll = true
		} else if pr.EndPort > 0 && pr.EndPort != pr.Port {
			a.ports = append(a.ports, strconv.Itoa(pr.Port)+":"+strconv.Itoa(pr.EndPort))
		} else {
			a.ports = append(a.ports, strconv.Itoa(pr.Port))
		}
	}

	var groups []iptablesPortGroup
	for _, proto := range order {
		a := m[proto]
		groups = append(groups, iptablesPortGroup{proto: proto, ports: a.ports, matchAll: a.matchAll})
	}
	return groups
}

func (c *iptablesManager) writeNetworkPolicyRules(lines *bytes.Buffer, rule NetworkPolicyRule, isIPv6 bool) {
	// Pick the correct sub-chain based on direction
	chain := netpolIngressChain
	if rule.Direction == "egress" {
		chain = netpolEgressChain
	}

	if rule.Action == "deny" {
		for _, podIP := range rule.PodIPs {
			if (isIPv6 && podIP.Is4()) || (!isIPv6 && podIP.Is6()) {
				continue
			}
			args := []string{}
			if rule.Direction == "ingress" {
				args = append(args, "-d", podIP.String())
			} else if rule.Direction == "egress" {
				args = append(args, "-s", podIP.String())
			}
			args = append(args, "-j", "DROP")
			writeRule(lines, ipt.Append, chain, args...)
		}
		return
	}

	// Group port rules by protocol
	protoGroups := groupPortRulesForIPTables(rule.PortRules)

	for _, podIP := range rule.PodIPs {
		if (isIPv6 && podIP.Is4()) || (!isIPv6 && podIP.Is6()) {
			continue
		}

		baseArgs := []string{}
		if rule.Direction == "ingress" {
			baseArgs = append(baseArgs, "-d", podIP.String())
		} else if rule.Direction == "egress" {
			baseArgs = append(baseArgs, "-s", podIP.String())
		}

		// Build list of arg sets: one per protocol group, or one empty set if no ports
		var argSets [][]string
		if len(protoGroups) == 0 {
			argSets = append(argSets, append([]string{}, baseArgs...))
		} else {
			for _, pg := range protoGroups {
				args := append([]string{}, baseArgs...)
				args = append(args, "-p", pg.proto)
				if !pg.matchAll && len(pg.ports) > 0 {
					portStr := strings.Join(pg.ports, ",")
					if len(pg.ports) == 1 && !strings.Contains(pg.ports[0], ":") {
						args = append(args, "--dport", portStr)
					} else {
						args = append(args, "-m", "multiport", "--dports", portStr)
					}
				}
				argSets = append(argSets, args)
			}
		}

		// Emit allow rules for each arg set × each allowed peer
		for _, args := range argSets {
			for _, allowedIP := range rule.AllowedIPs {
				if (isIPv6 && allowedIP.Is4()) || (!isIPv6 && allowedIP.Is6()) {
					continue
				}
				ruleArgs := append([]string{}, args...)
				if rule.Direction == "ingress" {
					ruleArgs = append(ruleArgs, "-s", allowedIP.String())
				} else if rule.Direction == "egress" {
					ruleArgs = append(ruleArgs, "-d", allowedIP.String())
				}
				ruleArgs = append(ruleArgs, "-j", "RETURN")
				writeRule(lines, ipt.Append, chain, ruleArgs...)
			}

			for _, allowedCIDR := range rule.AllowedCIDRs {
				if (isIPv6 && allowedCIDR.Addr().Is4()) || (!isIPv6 && allowedCIDR.Addr().Is6()) {
					continue
				}
				ruleArgs := append([]string{}, args...)
				if rule.Direction == "ingress" {
					ruleArgs = append(ruleArgs, "-s", allowedCIDR.String())
				} else if rule.Direction == "egress" {
					ruleArgs = append(ruleArgs, "-d", allowedCIDR.String())
				}
				ruleArgs = append(ruleArgs, "-j", "RETURN")
				writeRule(lines, ipt.Append, chain, ruleArgs...)
			}
		}
	}
}

func writeRule(lines *bytes.Buffer, position ipt.RulePosition, chain ipt.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}
