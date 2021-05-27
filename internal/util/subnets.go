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

// splitCIDRs splits a range of IP addresses into aligned cidrs
func splitCIDRs(start, stop ipBound) []net.IPNet {
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

func summarizeCIDRs(cidrs []net.IPNet, ipv6 bool) []net.IPNet {
	markers := make([]marker, 0)
	// convert IP networks into interval endpoints
	for _, network := range cidrs {
		// Do not use .To4() check here. We specifically want to treat
		// ::ffff:a.b.c.d/x as an IPv6 cidr.
		if (len(network.IP) == net.IPv6len) == ipv6 {
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
	var depth int = 0
	var start ipBound
	for i := 0; i < len(markers); i++ {
		if depth == 0 {
			start = markers[i].bound
		}
		if markers[i].upper {
			depth -= 1
		} else {
			depth += 1
		}
		if depth == 0 {
			// turn the interval back into aligned cidrs
			results = append(results, splitCIDRs(start, markers[i].bound)...)
		}
	}

	return results
}

// SummarizeCIDRs computes the union of CIDRs by collapsing adjecent ones into
// a CIDR with a shorter prefix and removes overlapping ones.
func SummarizeCIDRs(cidrs []net.IPNet) []net.IPNet {
	results := make([]net.IPNet, 0)
	results = append(results, summarizeCIDRs(cidrs, true)...)
	results = append(results, summarizeCIDRs(cidrs, false)...)
	return results
}
