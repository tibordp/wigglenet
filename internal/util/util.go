package util

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/config"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// Conversion helpers for external libraries that still use net.IP/net.IPNet.
// For new code, use netip.Addr.AsSlice() and netip.AddrFromSlice() directly.

// PrefixFromIPNet converts net.IPNet to netip.Prefix
func PrefixFromIPNet(ipnet net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := ipnet.Mask.Size()
	return netip.PrefixFrom(addr.Unmap(), ones), true
}

// PrefixToIPNet converts netip.Prefix to net.IPNet
func PrefixToIPNet(prefix netip.Prefix) net.IPNet {
	addr := prefix.Masked().Addr()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(prefix.Bits(), bits),
	}
}

// PrefixesFromIPNets converts []net.IPNet to []netip.Prefix
func PrefixesFromIPNets(ipnets []net.IPNet) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(ipnets))
	for _, ipnet := range ipnets {
		if prefix, ok := PrefixFromIPNet(ipnet); ok {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

// PrefixesToIPNets converts []netip.Prefix to []net.IPNet
func PrefixesToIPNets(prefixes []netip.Prefix) []net.IPNet {
	ipnets := make([]net.IPNet, len(prefixes))
	for i, prefix := range prefixes {
		ipnets[i] = PrefixToIPNet(prefix)
	}
	return ipnets
}

func SingleHostCIDR(addr netip.Addr) netip.Prefix {
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	prefix := netip.PrefixFrom(addr, bits)
	return prefix.Masked()
}

func GetPodCIDRsFromSpec(ctx context.Context, node *v1.Node) []netip.Prefix {
	logger := klog.FromContext(ctx)
	cidrs := make([]netip.Prefix, 0, len(node.Spec.PodCIDRs))

	if len(node.Spec.PodCIDRs) == 0 && node.Spec.PodCIDR != "" {
		if prefix, err := netip.ParsePrefix(node.Spec.PodCIDR); err == nil {
			cidrs = append(cidrs, prefix)
		} else {
			logger.Info("invalid CIDR prefix for node", "node", node.Name, "cidr", node.Spec.PodCIDR, "error", err)
		}
	} else {
		for _, v := range node.Spec.PodCIDRs {
			if prefix, err := netip.ParsePrefix(v); err == nil {
				cidrs = append(cidrs, prefix)
			} else {
				logger.Info("invalid CIDR prefix for node", "node", node.Name, "cidr", v, "error", err)
			}
		}
	}

	return cidrs
}

func GetPodCIDRsFromAnnotation(node *v1.Node) []netip.Prefix {
	annotationValue := node.Annotations[annotation.PodCidrsAnnotation]
	cidrs, err := annotation.UnmarshalPodCidrs(annotationValue)
	if err != nil {
		return []netip.Prefix{}
	}

	return cidrs
}

var defaultIPv6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
var defaultIPv4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)

func GetDefaultRoutes(podCIDRs []netip.Prefix) []netip.Prefix {
	routes := make([]netip.Prefix, 0)

	var hasIPv4, hasIPv6 bool

	for _, cidr := range podCIDRs {
		if cidr.Addr().Is6() && !hasIPv6 {
			routes = append(routes, defaultIPv6)
			hasIPv6 = true
		} else if cidr.Addr().Is4() && !hasIPv4 {
			routes = append(routes, defaultIPv4)
			hasIPv4 = true
		}
	}

	return routes
}

func GetPodNetworkLocalAddresses(podCIDRs []netip.Prefix) []netip.Addr {
	localAddresses := make([]netip.Addr, 0)
	for _, cidr := range podCIDRs {
		// host-ipam plugin reserves the IP with the host index of 1 to the node
		// itself. We want to make sure the wg interface has the same IP assigned to it
		// so that that internal IP is used as a source in node-to-pod communication
		addr := cidr.Addr()
		if addr.Is4() {
			a := addr.As4()
			a[3] |= 1
			localAddresses = append(localAddresses, netip.AddrFrom4(a))
		} else {
			a := addr.As16()
			a[15] |= 1
			localAddresses = append(localAddresses, netip.AddrFrom16(a))
		}
	}

	return localAddresses
}

func GetInterfaceIPs(ctx context.Context, ifaces string) ([]netip.Addr, error) {
	logger := klog.FromContext(ctx)
	ipAddresses := make([]netip.Addr, 0)

	for _, ifaceName := range strings.Split(ifaces, ",") {
		// Skip empty interface names
		if ifaceName == "" {
			continue
		}

		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			logger.Info("interface not found, skipping", "interface", ifaceName, "error", err)
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPAddr:
				ip = v.IP
			case *net.IPNet:
				ip = v.IP
			default:
				continue
			}

			if netipAddr, ok := netip.AddrFromSlice(ip); ok {
				netipAddr = netipAddr.Unmap()
				if netipAddr.IsGlobalUnicast() {
					ipAddresses = append(ipAddresses, netipAddr)
				}
			}
		}
	}
	return ipAddresses, nil
}

// interfacePrefixesFrom builds the on-link prefix map from raw per-interface
// addresses. Split out from GetInterfacePrefixes so it can be unit-tested
// without touching the host's network configuration. Only global-unicast
// addresses are kept (mirroring GetInterfaceIPs), and the on-link mask is
// preserved so derivation logic can match on prefix length (e.g. a routed /64).
func interfacePrefixesFrom(addrsByIface map[string][]net.Addr) map[string][]netip.Prefix {
	result := make(map[string][]netip.Prefix)
	for name, addrs := range addrsByIface {
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			prefix, ok := PrefixFromIPNet(*ipnet)
			if !ok || !prefix.IsValid() {
				continue
			}
			if !prefix.Addr().IsGlobalUnicast() {
				continue
			}
			result[name] = append(result[name], prefix)
		}
	}

	// Sort within each interface so that derivation (which often takes the
	// first match) is deterministic regardless of kernel enumeration order.
	for name := range result {
		slices.SortFunc(result[name], func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
	}
	return result
}

// GetInterfacePrefixes returns the global-unicast on-link prefixes configured on
// each network interface, keyed by interface name. This is the input to the CEL
// pod-CIDR source, letting an expression derive pod CIDRs from interface state.
func GetInterfacePrefixes(ctx context.Context) (map[string][]netip.Prefix, error) {
	logger := klog.FromContext(ctx)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	addrsByIface := make(map[string][]net.Addr, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			logger.Info("could not list interface addresses, skipping", "interface", iface.Name, "error", err)
			continue
		}
		addrsByIface[iface.Name] = addrs
	}

	return interfacePrefixesFrom(addrsByIface), nil
}

func GetNodeAddresses(node *v1.Node) []netip.Addr {
	ipAddresses := make([]netip.Addr, 0)
	for _, v := range node.Status.Addresses {
		if v.Type == v1.NodeInternalIP || v.Type == v1.NodeExternalIP {
			if addr, err := netip.ParseAddr(v.Address); err == nil {
				ipAddresses = append(ipAddresses, addr)
			}
		}
	}
	return ipAddresses
}

func SelectIP(ips []netip.Addr, family config.IPFamily) *netip.Addr {
	for _, ip := range ips {
		if ip.Is4() && (family == config.IPv4Family || family == config.DualStackFamily) {
			return &ip
		} else if ip.Is6() && (family == config.IPv6Family || family == config.DualStackFamily) {
			return &ip
		}
	}

	return nil
}
