package util

import (
	"bytes"
	"net"
	"sort"
)

// Representation of an IP address that allows for half-open intervals
// (with overflow bit that represents the top of the address space)
type ipBound struct {
	ip       net.IP
	overflow bool
}

func compare(a ipBound, b ipBound) int {
	if a.overflow != b.overflow {
		if a.overflow {
			return 1
		} else {
			return -1
		}
	}
	return bytes.Compare(a.ip, b.ip)
}

func getNetworkBound(ip net.IP, mask net.IPMask, upper bool) ipBound {
	n := len(ip)
	out := make(net.IP, n)

	var carry bool = true
	for i := n - 1; i >= 0; i-- {
		if !upper {
			out[i] = ip[i] & mask[i]
			carry = false
		} else {
			out[i] = ip[i] | ^mask[i]
			if carry {
				out[i] += 1
				carry = (out[i] == 0)
			}
		}
	}

	return ipBound{
		ip:       out,
		overflow: carry,
	}
}

type marker struct {
	bound ipBound
	upper bool
}

func getMarkers(subnets []net.IPNet, ipv6 bool) []marker {
	markers := make([]marker, 0)
	for _, network := range subnets {
		if network.IP.To4() == nil == ipv6 {
			markers = append(markers,
				marker{
					bound: getNetworkBound(network.IP, network.Mask, true),
					upper: true,
				},
				marker{
					bound: getNetworkBound(network.IP, network.Mask, false),
					upper: false,
				},
			)
		}
	}

	sort.Slice(markers, func(i, j int) bool {
		cmp := compare(markers[i].bound, markers[j].bound)
		if cmp == 0 {
			return !markers[i].upper && markers[j].upper
		}
		return cmp < 0
	})

	return markers
}

func splitSubnets(start, stop ipBound) []net.IPNet {
	results := make([]net.IPNet, 0)
	for {
		for j := 0; j < len(start.ip)*8; j++ {
			mask := net.CIDRMask(j, len(start.ip)*8)
			lower := getNetworkBound(start.ip, mask, false)
			upper := getNetworkBound(start.ip, mask, true)
			if compare(lower, start) == 0 && compare(upper, stop) <= 0 {
				results = append(results, net.IPNet{
					IP:   lower.ip,
					Mask: mask,
				})
				start = upper
				break
			}
		}
		if compare(start, stop) >= 0 {
			break
		}
	}
	return results
}

func aggregate(markers []marker) []net.IPNet {
	results := make([]net.IPNet, 0)

	var count int = 0
	var start ipBound
	for i := 0; i < len(markers); i++ {
		if count == 0 {
			start = markers[i].bound
		}
		if markers[i].upper {
			count -= 1
		} else {
			count += 1
		}
		if count == 0 {
			results = append(results, splitSubnets(start, markers[i].bound)...)
		}
	}

	return results
}

func SummarizeSubnets(subnets []net.IPNet) []net.IPNet {
	markersv6 := getMarkers(subnets, true)
	markersv4 := getMarkers(subnets, false)

	results := make([]net.IPNet, 0)
	results = append(results, aggregate(markersv6)...)
	results = append(results, aggregate(markersv4)...)
	return results
}
