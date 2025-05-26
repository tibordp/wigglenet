package firewall

import (
	"bytes"
	"context"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	ipt "k8s.io/kubernetes/pkg/util/iptables"
	"k8s.io/utils/exec"

	klog "k8s.io/klog/v2"
)

const (
	filterChain = ipt.Chain("WIGGLENET-FIREWALL")
	netpolChain = ipt.Chain("WIGGLENET-NETPOL")
	natChain    = ipt.Chain("WIGGLENET-MASQ")

	// Sync iptables every minute
	syncInterval = 1 * time.Minute
)

type ipTables interface {
	EnsureChain(table ipt.Table, chain ipt.Chain) (bool, error)
	EnsureRule(position ipt.RulePosition, table ipt.Table, chain ipt.Chain, args ...string) (bool, error)
	RestoreAll(data []byte, flush ipt.FlushFlag, counters ipt.RestoreCountersFlag) error
}

type NetworkPolicyRule struct {
	PodIPs       []net.IP
	AllowedIPs   []net.IP
	AllowedCIDRs []net.IPNet
	Ports        []int
	Protocol     string
	Direction    string
	Action       string // "allow" or "deny"
}

type FirewallConfig struct {
	PodCIDRs    []net.IPNet
	PolicyRules []NetworkPolicyRule
}

func NewConfig(podCIDRs []net.IPNet) FirewallConfig {
	aggregated := util.SummarizeCIDRs(podCIDRs)
	config := FirewallConfig{
		PodCIDRs:    aggregated,
		PolicyRules: []NetworkPolicyRule{},
	}

	return config
}

func NewConfigWithPolicies(podCIDRs []net.IPNet, policyRules []NetworkPolicyRule) FirewallConfig {
	aggregated := util.SummarizeCIDRs(podCIDRs)
	config := FirewallConfig{
		PodCIDRs:    aggregated,
		PolicyRules: policyRules,
	}

	return config
}

type firewallManager struct {
	ip6tables       ipTables
	ip4tables       ipTables
	podCIDRUpdates  chan []net.IPNet
	policyUpdates   chan []NetworkPolicyRule
	currentPodCIDRs []net.IPNet
	currentPolicies []NetworkPolicyRule
}

type Manager interface {
	Run(ctx context.Context)
}

func New(podCIDRUpdates chan []net.IPNet, policyUpdates chan []NetworkPolicyRule) Manager {
	exec := exec.New()
	ip6tables := ipt.New(exec, ipt.ProtocolIPv6)
	ip4tables := ipt.New(exec, ipt.ProtocolIPv4)

	m := firewallManager{
		ip6tables:       ip6tables,
		ip4tables:       ip4tables,
		podCIDRUpdates:  podCIDRUpdates,
		policyUpdates:   policyUpdates,
		currentPodCIDRs: []net.IPNet{},
		currentPolicies: []NetworkPolicyRule{},
	}

	return &m
}

func (c *firewallManager) Run(ctx context.Context) {
	klog.Infof("started syncing firewall rules")
	defer klog.Infof("finished syncing firewall rules")

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
				klog.Infof("received new pod CIDR configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(syncInterval)
				c.currentPodCIDRs = newPodCIDRs
			}
		case newPolicies := <-c.policyUpdates:
			if !reflect.DeepEqual(newPolicies, c.currentPolicies) {
				klog.Infof("received new NetworkPolicy configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(syncInterval)
				c.currentPolicies = newPolicies
			}
		}

		err := c.syncRules()
		if err != nil {
			// Just log the error, we will retry in one minute if transient
			klog.Errorf("failed to sync firewall rules: %v", err)
		}
	}
}

func (c *firewallManager) syncRules() error {
	ip4cidrs := make([]net.IPNet, 0)
	ip6cidrs := make([]net.IPNet, 0)

	for _, cidr := range c.currentPodCIDRs {
		if cidr.IP.To4() == nil {
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
			if ip.To4() != nil {
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
		if err := c.syncFilterRules(c.ip6tables, ip6cidrs, ip6PolicyRules, true, config.EnableNetworkPolicy); err != nil {
			return err
		}
	}

	// Apply IPv4 filter rules if filtering is enabled OR if NetworkPolicy is enabled
	if config.FilterIPv4 || config.EnableNetworkPolicy {
		if err := c.syncFilterRules(c.ip4tables, ip4cidrs, ip4PolicyRules, false, config.EnableNetworkPolicy); err != nil {
			return err
		}
	}

	if config.MasqueradeIPv6 {
		if err := c.syncMasqueradeRules(c.ip6tables, ip6cidrs); err != nil {
			return err
		}
	}

	if config.MasqueradeIPv4 {
		if err := c.syncMasqueradeRules(c.ip4tables, ip4cidrs); err != nil {
			return err
		}
	}

	return nil
}

func (c *firewallManager) syncMasqueradeRules(tables ipTables, nonMasqCidrs []net.IPNet) error {
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

func (c *firewallManager) syncFilterRules(tables ipTables, nonFilterCidrs []net.IPNet, policyRules []NetworkPolicyRule, isIPv6 bool, enableNetworkPolicy bool) error {
	// Determine if we need global filtering (based on config) or just NetworkPolicy filtering
	enableGlobalFiltering := (isIPv6 && config.FilterIPv6) || (!isIPv6 && config.FilterIPv4)

	if _, err := tables.EnsureChain(ipt.TableFilter, filterChain); err != nil {
		return err
	}

	if enableNetworkPolicy {
		if _, err := tables.EnsureChain(ipt.TableFilter, netpolChain); err != nil {
			return err
		}
	}

	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*filter")

	// Main filter chain rules (only if global filtering is enabled)
	if enableGlobalFiltering {
		if _, err := tables.EnsureRule(ipt.Append, ipt.TableFilter, ipt.ChainForward,
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
		// Always hook NetworkPolicy chain directly to FORWARD (independent of global filtering)
		if _, err := tables.EnsureRule(ipt.Append, ipt.TableFilter, ipt.ChainForward,
			"-m", "comment", "--comment", "NetworkPolicy enforcement",
			"-j", string(netpolChain)); err != nil {
			return err
		}

		// Clear NetworkPolicy chain and set up baseline rules
		writeLine(lines, "-F", string(netpolChain))
		writeLine(lines, ipt.MakeChainLine(netpolChain))

		writeRule(lines, ipt.Append, netpolChain, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN")
		if isIPv6 {
			writeRule(lines, ipt.Append, netpolChain, "-p", "ipv6-icmp", "-j", "RETURN")
		}

		// Add NetworkPolicy rules
		for _, rule := range policyRules {
			c.writeNetworkPolicyRules(lines, rule, isIPv6)
		}

		// Default allow for traffic not covered by NetworkPolicies
		writeRule(lines, ipt.Append, netpolChain, "-j", "RETURN")
	}

	writeLine(lines, "COMMIT")

	if err := tables.RestoreAll(lines.Bytes(), ipt.NoFlushTables, ipt.NoRestoreCounters); err != nil {
		return err
	}

	return nil
}

func (c *firewallManager) writeNetworkPolicyRules(lines *bytes.Buffer, rule NetworkPolicyRule, isIPv6 bool) {
	if rule.Action == "deny" {
		// Generate deny rules for specific pods
		for _, podIP := range rule.PodIPs {
			// Skip if IP family doesn't match
			if (isIPv6 && podIP.To4() != nil) || (!isIPv6 && podIP.To4() == nil) {
				continue
			}

			// Build rule arguments for deny
			args := []string{}

			if rule.Direction == "ingress" {
				args = append(args, "-d", podIP.String())
			} else if rule.Direction == "egress" {
				args = append(args, "-s", podIP.String())
			}

			args = append(args, "-j", "DROP")
			writeRule(lines, ipt.Append, netpolChain, args...)
		}
		return
	}

	// Generate allow rules (original logic)
	for _, podIP := range rule.PodIPs {
		// Skip if IP family doesn't match
		if (isIPv6 && podIP.To4() != nil) || (!isIPv6 && podIP.To4() == nil) {
			continue
		}

		// Build rule arguments
		args := []string{}

		if rule.Direction == "ingress" {
			args = append(args, "-d", podIP.String())
		} else if rule.Direction == "egress" {
			args = append(args, "-s", podIP.String())
		}

		// Add protocol if specified
		if rule.Protocol != "" {
			args = append(args, "-p", rule.Protocol)
		}

		// Add port restrictions if specified
		if len(rule.Ports) > 0 && rule.Protocol != "" {
			portStr := ""
			for i, port := range rule.Ports {
				if i > 0 {
					portStr += ","
				}
				portStr += strconv.Itoa(port)
			}
			if strings.ToLower(rule.Protocol) == "tcp" {
				args = append(args, "--dport", portStr)
			} else if strings.ToLower(rule.Protocol) == "udp" {
				args = append(args, "--dport", portStr)
			}
		}

		// Allow traffic from specific IPs
		for _, allowedIP := range rule.AllowedIPs {
			// Skip if IP family doesn't match
			if (isIPv6 && allowedIP.To4() != nil) || (!isIPv6 && allowedIP.To4() == nil) {
				continue
			}

			ruleArgs := append([]string{}, args...)
			if rule.Direction == "ingress" {
				ruleArgs = append(ruleArgs, "-s", allowedIP.String())
			} else if rule.Direction == "egress" {
				ruleArgs = append(ruleArgs, "-d", allowedIP.String())
			}
			ruleArgs = append(ruleArgs, "-j", "RETURN")
			writeRule(lines, ipt.Append, netpolChain, ruleArgs...)
		}

		// Allow traffic from specific CIDRs
		for _, allowedCIDR := range rule.AllowedCIDRs {
			// Skip if IP family doesn't match
			if (isIPv6 && allowedCIDR.IP.To4() != nil) || (!isIPv6 && allowedCIDR.IP.To4() == nil) {
				continue
			}

			ruleArgs := append([]string{}, args...)
			if rule.Direction == "ingress" {
				ruleArgs = append(ruleArgs, "-s", allowedCIDR.String())
			} else if rule.Direction == "egress" {
				ruleArgs = append(ruleArgs, "-d", allowedCIDR.String())
			}
			ruleArgs = append(ruleArgs, "-j", "RETURN")
			writeRule(lines, ipt.Append, netpolChain, ruleArgs...)
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
