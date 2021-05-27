package util

import (
	"net"
	"strings"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/config"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

func SingleHostCIDR(ip net.IP) net.IPNet {
	canonical := Canonicalize(ip)
	return net.IPNet{
		IP:   canonical,
		Mask: net.CIDRMask(8*len(canonical), 8*len(canonical)),
	}
}

func GetPodCIDRsFromSpec(node *v1.Node) []net.IPNet {
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

func GetPodCIDRsFromAnnotation(node *v1.Node) []net.IPNet {
	annotationValue := node.Annotations[annotation.PodCidrsAnnotation]
	cidrs, err := annotation.UnmarshalPodCidrs(annotationValue)
	if err != nil {
		return []net.IPNet{}
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

func GetInterfaceIPs(ifaces string) ([]net.IP, error) {
	ipAddresses := make([]net.IP, 0)

	for _, iface := range strings.Split(ifaces, ",") {
		iface, err := net.InterfaceByName(iface)
		if err != nil {
			klog.Warningf("interface %v not found, skipping", iface)
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

			if ip.IsGlobalUnicast() {
				ipAddresses = append(ipAddresses, ip)
			}
		}
	}
	return ipAddresses, nil
}

func GetNodeAddresses(node *v1.Node) []net.IP {
	ipAddresses := make([]net.IP, 0)
	for _, v := range node.Status.Addresses {
		if v.Type == v1.NodeInternalIP || v.Type == v1.NodeExternalIP {
			addr := net.ParseIP(v.Address)
			if addr != nil {
				ipAddresses = append(ipAddresses, addr)
			}
		}
	}
	return ipAddresses
}

func Canonicalize(ip net.IP) net.IP {
	v4 := ip.To4()
	if v4 != nil {
		// we could get ::ffff:a.b.c.d
		return v4
	}
	return ip
}

func SelectIP(ips []net.IP, family config.IPFamily) *net.IP {
	for _, ip := range ips {
		if ip.To4() != nil && (family == config.IPv4Family || family == config.DualStackFamily) {
			return &ip
		} else if ip.To4() == nil && (family == config.IPv6Family || family == config.DualStackFamily) {
			return &ip
		}
	}

	return nil
}
