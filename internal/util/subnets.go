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

func getUpperBound(ip net.IP, mask net.IPMask) ipBound {
	n := len(ip)
	out := make(net.IP, n)

	var carry bool = true
	for i := n - 1; i >= 0; i-- {
		out[i] = ip[i] | ^mask[i]
		if carry {
			out[i] += 1
			// Carry if there is overflow
			carry = (out[i] == 0)
		}
	}

	return ipBound{
		ip:       out,
		overflow: carry,
	}
}

func getLowerBound(ip net.IP, mask net.IPMask) ipBound {
	n := len(ip)
	out := make(net.IP, n)

	for i := n - 1; i >= 0; i-- {
		out[i] = ip[i] & mask[i]
	}

	return ipBound{
		ip:       out,
		overflow: false,
	}
}

type marker struct {
	bound ipBound
	upper bool
}

// splitSubnets splits a range of IP addresses into aligned subnets
func splitSubnets(start, stop ipBound) []net.IPNet {
	results := make([]net.IPNet, 0)
	for {
		for j := 0; j < len(start.ip)*8; j++ {
			mask := net.CIDRMask(j, len(start.ip)*8)
			lower := getLowerBound(start.ip, mask)
			upper := getUpperBound(start.ip, mask)
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

func summarizeSubnets(subnets []net.IPNet, ipv6 bool) []net.IPNet {
	markers := make([]marker, 0)
	// convert IP networks into interval endpoints
	for _, network := range subnets {
		if network.IP.To4() == nil == ipv6 {
			markers = append(markers,
				marker{
					bound: getUpperBound(network.IP, network.Mask),
					upper: true,
				},
				marker{
					bound: getLowerBound(network.IP, network.Mask),
					upper: false,
				},
			)
		}
	}

	// sort the endpoints
	sort.Slice(markers, func(i, j int) bool {
		cmp := compare(markers[i].bound, markers[j].bound)
		if cmp == 0 {
			return !markers[i].upper && markers[j].upper
		}
		return cmp < 0
	})

	// calculate the union
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
			// turn the interval back into aligned subnets
			results = append(results, splitSubnets(start, markers[i].bound)...)
		}
	}

	return results
}

// SummarizeSubnets computes the union of subnets by collapsing adjecent subnets into
// ones with a shorter prefix and removes overlapping subnets.
func SummarizeSubnets(subnets []net.IPNet) []net.IPNet {
	results := make([]net.IPNet, 0)
	results = append(results, summarizeSubnets(subnets, true)...)
	results = append(results, summarizeSubnets(subnets, false)...)
	return results
}
