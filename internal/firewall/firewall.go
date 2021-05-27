package firewall

import (
	"bytes"
	"net"
	"reflect"
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
	natChain    = ipt.Chain("WIGGLENET-MASQ")

	// Sync iptables every minute
	syncInterval = 1 * time.Minute
)

type ipTables interface {
	EnsureChain(table ipt.Table, chain ipt.Chain) (bool, error)
	EnsureRule(position ipt.RulePosition, table ipt.Table, chain ipt.Chain, args ...string) (bool, error)
	RestoreAll(data []byte, flush ipt.FlushFlag, counters ipt.RestoreCountersFlag) error
}

type FirewallConfig struct {
	PodCIDRs []net.IPNet
}

func NewConfig(podCIDRs []net.IPNet) FirewallConfig {
	aggregated := util.SummarizeCIDRs(podCIDRs)
	config := FirewallConfig{
		PodCIDRs: aggregated,
	}

	return config
}

type firewallManager struct {
	ip6tables      ipTables
	ip4tables      ipTables
	updates        chan FirewallConfig
	firewallConfig FirewallConfig
}

type Manager interface {
	Run(stop chan struct{})
}

func New(updates chan FirewallConfig) Manager {
	exec := exec.New()
	ip6tables := ipt.New(exec, ipt.ProtocolIPv6)
	ip4tables := ipt.New(exec, ipt.ProtocolIPv4)

	m := firewallManager{
		ip6tables: ip6tables,
		ip4tables: ip4tables,
		updates:   updates,
	}

	return &m
}

func (c *firewallManager) Run(stop chan struct{}) {
	klog.Infof("started syncing firewall rules")

	timer := time.NewTimer(0)
	for {
		// Sync rules whenever the configuration changes and at least
		// once per minute (to recreate the rules if they are flushed)
		select {
		case <-stop:
			return
		case <-timer.C:
			timer.Reset(syncInterval)
		case ret := <-c.updates:
			if !reflect.DeepEqual(ret, c.firewallConfig) {
				klog.Infof("received new firewall configuration")
				if !timer.Stop() {
					<-timer.C
				}
				timer.Reset(syncInterval)
				c.firewallConfig = ret
			}
			// Do not reset timer if the received configuration has not changed
			// This is to ensure that we sync the rules from time to time if there
			// are constant changes resulting in no visible firewall changes
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

	for _, cidr := range c.firewallConfig.PodCIDRs {
		if cidr.IP.To4() == nil {
			ip6cidrs = append(ip6cidrs, cidr)
		} else {
			ip4cidrs = append(ip4cidrs, cidr)
		}
	}

	if config.FilterIPv6 {
		if err := c.syncFilterRules(c.ip6tables, ip6cidrs, true); err != nil {
			return err
		}
	}

	if config.FilterIPv4 {
		if err := c.syncFilterRules(c.ip4tables, ip4cidrs, false); err != nil {
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

func (c *firewallManager) syncFilterRules(tables ipTables, nonFilterCidrs []net.IPNet, isIPv6 bool) error {
	if _, err := tables.EnsureChain(ipt.TableFilter, filterChain); err != nil {
		return err
	}

	if _, err := tables.EnsureRule(ipt.Append, ipt.TableFilter, ipt.ChainForward,
		"-m", "comment", "--comment", "prevent direct ingress traffic to pods",
		"-j", string(filterChain)); err != nil {
		return err
	}

	lines := bytes.NewBuffer(nil)
	writeLine(lines, "*filter")
	writeLine(lines, "-F", string(filterChain))
	writeLine(lines, ipt.MakeChainLine(filterChain))
	writeRule(lines, ipt.Append, filterChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN")
	if isIPv6 {
		// This is a bit opinionated, but I prefer to always allow ICMPv6 through. This is necesary at least
		// for path MTU discovery, but echo-request is also very useful for diagnostics.
		// https://datatracker.ietf.org/doc/html/rfc4890
		writeRule(lines, ipt.Append, filterChain, "-p", "ipv6-icmp", "-j", "RETURN")
	}
	for _, cidr := range nonFilterCidrs {
		writeRule(lines, ipt.Append, filterChain, "-s", cidr.String(), "-j", "RETURN")
	}
	writeRule(lines, ipt.Append, filterChain, "-j", "DROP")
	writeLine(lines, "COMMIT")

	if err := tables.RestoreAll(lines.Bytes(), ipt.NoFlushTables, ipt.NoRestoreCounters); err != nil {
		return err
	}

	return nil
}

func writeRule(lines *bytes.Buffer, position ipt.RulePosition, chain ipt.Chain, args ...string) {
	fullArgs := append([]string{string(position), string(chain)}, args...)
	writeLine(lines, fullArgs...)
}

func writeLine(lines *bytes.Buffer, words ...string) {
	lines.WriteString(strings.Join(words, " ") + "\n")
}
