package util

import (
	"net/netip"
	"sort"
)

// Representation of an IP address that allows for half-open intervals
// (with overflow bit that represents the top of the address space)
type ipBound struct {
	ip       netip.Addr
	overflow bool
}

func compare(a ipBound, b ipBound) int {
	if a.overflow != b.overflow {
		if a.overflow {
			return 1
		}
		return -1
	}
	return a.ip.Compare(b.ip)
}

// computeUpperBound sets all host bits to 1 and adds 1 (with carry propagation)
// to get the first address after the prefix range.
func computeUpperBound(bytes []byte, hostBits uint) bool {
	carry := true
	lastIdx := len(bytes) - 1

	for i := lastIdx; i >= 0 && carry; i-- {
		shift := hostBits - uint(lastIdx-i)*8
		if shift > 0 && shift < 8 {
			bytes[i] |= byte((1 << shift) - 1)
		} else if shift >= 8 {
			bytes[i] = 0xff
		}

		if carry {
			bytes[i] += 1
			carry = (bytes[i] == 0)
		}
	}

	return carry // overflow
}

func getUpperBound(prefix netip.Prefix) ipBound {
	// Get the last address in the prefix range and add 1
	addr := prefix.Addr()
	bits := prefix.Bits()

	var overflow bool

	if addr.Is4() {
		a := addr.As4()
		hostBits := uint(32 - bits)
		overflow = computeUpperBound(a[:], hostBits)
		addr = netip.AddrFrom4(a)
	} else {
		a := addr.As16()
		hostBits := uint(128 - bits)
		overflow = computeUpperBound(a[:], hostBits)
		addr = netip.AddrFrom16(a)
	}

	return ipBound{
		ip:       addr,
		overflow: overflow,
	}
}

func getLowerBound(prefix netip.Prefix) ipBound {
	// Get the network address (first address in the prefix)
	return ipBound{
		ip:       prefix.Masked().Addr(),
		overflow: false,
	}
}

type marker struct {
	bound ipBound
	upper bool
}

// splitCIDRs splits a range of IP addresses into aligned cidrs
func splitCIDRs(start, stop ipBound) []netip.Prefix {
	results := make([]netip.Prefix, 0)
	maxBits := 32
	if start.ip.Is6() {
		maxBits = 128
	}

	for {
		for j := 0; j <= maxBits; j++ {
			prefix := netip.PrefixFrom(start.ip, j)
			lower := getLowerBound(prefix)
			upper := getUpperBound(prefix)
			if compare(lower, start) == 0 && compare(upper, stop) <= 0 {
				results = append(results, prefix.Masked())
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

func summarizeCIDRs(cidrs []netip.Prefix, ipv6 bool) []netip.Prefix {
	markers := make([]marker, 0)
	// convert IP networks into interval endpoints
	for _, prefix := range cidrs {
		if prefix.Addr().Is6() == ipv6 {
			markers = append(markers,
				marker{
					bound: getUpperBound(prefix),
					upper: true,
				},
				marker{
					bound: getLowerBound(prefix),
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
	results := make([]netip.Prefix, 0)
	var depth int
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
func SummarizeCIDRs(cidrs []netip.Prefix) []netip.Prefix {
	results := make([]netip.Prefix, 0)
	results = append(results, summarizeCIDRs(cidrs, true)...)
	results = append(results, summarizeCIDRs(cidrs, false)...)
	return results
}
