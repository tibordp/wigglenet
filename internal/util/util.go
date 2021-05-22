package util

import (
	"net"
	"os"
	"strconv"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

type IPFamily string

const (
	IPv4Family      IPFamily = "ipv4"
	IPv6Family      IPFamily = "ipv6"
	DualStackFamily IPFamily = "dual"
)

func GetEnvOrDefault(name string, fallback string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	} else {
		return fallback
	}
}

func GetEnvOrDefaultInt(name string, fallback int) int {
	if val, ok := os.LookupEnv(name); ok {
		if i, err := strconv.Atoi(val); err != nil {
			return fallback
		} else {
			return i
		}
	} else {
		return fallback
	}
}

func GetEnvOrDefaultBool(name string, fallback bool) bool {
	if val, ok := os.LookupEnv(name); ok {
		if i, err := strconv.ParseBool(val); err != nil {
			return fallback
		} else {
			return i
		}
	} else {
		return fallback
	}
}

func SingleHostSubnet(ip net.IP) net.IPNet {
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(8*len(ip), 8*len(ip)),
	}
}

func GetPodCIDRs(node *v1.Node) []net.IPNet {
	cidrs := make([]net.IPNet, 0, len(node.Spec.PodCIDRs))
	if len(node.Spec.PodCIDRs) == 0 && node.Spec.PodCIDR != "" {
		if _, route, err := net.ParseCIDR(node.Spec.PodCIDR); err == nil && route != nil {
			cidrs = append(cidrs, *route)
		} else {
			klog.Warningf("invalid CIDR prefix for node %v: %v", node.Name, node.Spec.PodCIDR)
		}
	} else {
		for _, v := range node.Spec.PodCIDRs {
			if _, route, err := net.ParseCIDR(v); err == nil && route != nil {
				cidrs = append(cidrs, *route)
			} else {
				klog.Warningf("invalid CIDR prefix for node %v: %v", node.Name, v)
			}
		}
	}

	return cidrs
}

var defaultIPv6 = net.IPNet{
	IP:   net.IPv6zero,
	Mask: net.IPMask(net.IPv6zero),
}

var defaultIPv4 = net.IPNet{
	IP:   net.IPv4zero,
	Mask: net.IPMask(net.IPv4zero),
}

func GetDefaultRoutes(podCIDRs []net.IPNet) []net.IPNet {
	routes := make([]net.IPNet, 0)

	var hasIPv4 bool = false
	var hasIPv6 bool = false

	for _, cidr := range podCIDRs {
		if cidr.IP.To4() == nil && !hasIPv6 {
			routes = append(routes, defaultIPv6)
			hasIPv6 = true
		} else if !hasIPv4 {
			routes = append(routes, defaultIPv4)
			hasIPv4 = true
		}
	}

	return routes
}

func GetPodNetworkLocalAddresses(podCIDRs []net.IPNet) []net.IP {
	localAddresses := make([]net.IP, 0)
	for _, cidr := range podCIDRs {
		// host-ipam plugin reserves the IP with the host index of 1 to the node
		// itself. We want to make sure the wg interface has the same IP assigned to it
		// so that that internal IP is used as a source in node-to-pod communication
		nodeIp := make(net.IP, len(cidr.IP))
		copy(nodeIp, cidr.IP)
		nodeIp[len(nodeIp)-1] |= 1
		localAddresses = append(localAddresses, nodeIp)
	}

	return localAddresses
}

func GetInterfaceIP(family IPFamily, ifaceName string) (net.IP, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
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

		if ip.IsGlobalUnicast() {
			if ip.To4() == nil && (family == IPv6Family || family == DualStackFamily) {
				return ip, nil
			}

			if ip.To4() != nil && (family == IPv4Family || family == DualStackFamily) {
				return ip, nil
			}
		}
	}

	return nil, nil
}

func GetNodeAddress(node *v1.Node) net.IP {
	for _, v := range node.Status.Addresses {
		if v.Type == v1.NodeInternalIP {
			addr := net.ParseIP(v.Address)
			if addr != nil {
				return addr
			}
		}
	}

	return nil
}
