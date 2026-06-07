// Package celipam evaluates a CEL expression that derives a node's pod CIDRs
// from the addresses present on its network interfaces (and node metadata).
//
// It builds on the Kubernetes IP/CIDR CEL library (k8s.io/apiserver/pkg/cel)
// for the familiar cidr()/ip()/masked()/prefixLength()/containsIP verbs, and
// adds a single custom verb that the standard library lacks: carving a subnet
// out of a prefix.
//
//	cidr.subnet(prefixLength, index) -> cidr
//
// e.g. the second /80 of a routed /64:
//
//	interfaces["eth0"].filter(p, p.prefixLength() == 64)[0].subnet(80, 1)
//
// The expression is given two variables:
//
//	interfaces  map(string, list(cidr))   on-link prefixes per interface name
//	node        map(string, dyn)          {name: string, labels: map, annotations: map}
//
// and must evaluate to a cidr or a list(cidr) — the pod CIDRs for this node.
package celipam

import (
	"fmt"
	"math/big"
	"net/netip"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	apiservercel "k8s.io/apiserver/pkg/cel"
	"k8s.io/apiserver/pkg/cel/library"
)

// costLimit bounds the work a single evaluation may do. CEL has no unbounded
// loops (comprehensions are bounded by their input list), so an expression
// always terminates; this is a belt-and-suspenders guard against pathological
// inputs.
const costLimit = 1_000_000

// NodeInfo is the subset of node metadata exposed to the expression.
type NodeInfo struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
}

// Inputs is the data an expression is evaluated against.
type Inputs struct {
	// Interfaces maps interface name to the on-link prefixes configured on it.
	Interfaces map[string][]netip.Prefix
	Node       NodeInfo
}

// Evaluator is a compiled pod-CIDR expression. It is safe for concurrent use.
type Evaluator struct {
	program cel.Program
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cacheEntry{}
)

type cacheEntry struct {
	eval *Evaluator
	err  error
}

// Compile parses and type-checks expression. Results are memoized by source
// text, so repeated calls (e.g. across SetupNode conflict retries) are cheap.
func Compile(expression string) (*Evaluator, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if e, ok := cache[expression]; ok {
		return e.eval, e.err
	}
	eval, err := compile(expression)
	cache[expression] = cacheEntry{eval: eval, err: err}
	return eval, err
}

func compile(expression string) (*Evaluator, error) {
	env, err := cel.NewEnv(
		library.IP(),
		library.CIDR(),
		subnetFunction(),
		cel.Variable("interfaces", cel.MapType(cel.StringType, cel.ListType(apiservercel.CIDRType))),
		cel.Variable("node", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("building CEL environment: %w", err)
	}

	ast, iss := env.Compile(expression)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("compiling pod CIDR expression: %w", iss.Err())
	}

	// The expression must yield a cidr or a list of cidrs. Allow dyn (e.g. a
	// bare ternary) and validate the concrete value at runtime instead.
	out := ast.OutputType()
	cidrList := cel.ListType(apiservercel.CIDRType)
	if !out.IsEquivalentType(apiservercel.CIDRType) &&
		!out.IsEquivalentType(cidrList) &&
		!out.IsEquivalentType(cel.DynType) {
		return nil, fmt.Errorf("pod CIDR expression must evaluate to a cidr or list(cidr), got %s", out)
	}

	program, err := env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return nil, fmt.Errorf("constructing CEL program: %w", err)
	}

	return &Evaluator{program: program}, nil
}

// Evaluate runs the expression against inputs and returns the derived pod
// CIDRs, each masked to its network address.
func (e *Evaluator) Evaluate(inputs Inputs) ([]netip.Prefix, error) {
	out, _, err := e.program.Eval(map[string]any{
		"interfaces": interfacesValue(inputs.Interfaces),
		"node":       nodeValue(inputs.Node),
	})
	if err != nil {
		return nil, fmt.Errorf("evaluating pod CIDR expression: %w", err)
	}

	prefixes, err := toPrefixes(out)
	if err != nil {
		return nil, err
	}

	masked := make([]netip.Prefix, 0, len(prefixes))
	for _, p := range prefixes {
		masked = append(masked, p.Masked())
	}
	return masked, nil
}

// toPrefixes extracts netip.Prefix values from a cidr or list(cidr) result.
func toPrefixes(out ref.Val) ([]netip.Prefix, error) {
	switch v := out.(type) {
	case apiservercel.CIDR:
		return []netip.Prefix{v.Prefix}, nil
	case traits.Lister:
		n, ok := v.Size().(types.Int)
		if !ok {
			return nil, fmt.Errorf("pod CIDR expression returned a list of unknown size")
		}
		prefixes := make([]netip.Prefix, 0, int(n))
		for i := 0; i < int(n); i++ {
			elem := v.Get(types.Int(i))
			c, ok := elem.(apiservercel.CIDR)
			if !ok {
				return nil, fmt.Errorf("pod CIDR expression returned a non-cidr list element of type %s", elem.Type())
			}
			prefixes = append(prefixes, c.Prefix)
		}
		return prefixes, nil
	default:
		return nil, fmt.Errorf("pod CIDR expression must evaluate to a cidr or list(cidr), got %s", out.Type())
	}
}

func interfacesValue(interfaces map[string][]netip.Prefix) ref.Val {
	entries := make(map[ref.Val]ref.Val, len(interfaces))
	for name, prefixes := range interfaces {
		vals := make([]ref.Val, 0, len(prefixes))
		for _, p := range prefixes {
			vals = append(vals, apiservercel.CIDR{Prefix: p})
		}
		entries[types.String(name)] = types.NewRefValList(types.DefaultTypeAdapter, vals)
	}
	return types.NewRefValMap(types.DefaultTypeAdapter, entries)
}

func nodeValue(node NodeInfo) map[string]any {
	return map[string]any{
		"name":        node.Name,
		"labels":      node.Labels,
		"annotations": node.Annotations,
	}
}

// subnetFunction adds cidr.subnet(prefixLength, index) -> cidr to the environment.
func subnetFunction() cel.EnvOption {
	return cel.Function("subnet",
		cel.MemberOverload("cidr_subnet_int_int",
			[]*cel.Type{apiservercel.CIDRType, cel.IntType, cel.IntType},
			apiservercel.CIDRType,
			cel.FunctionBinding(func(args ...ref.Val) ref.Val {
				cidr, ok := args[0].(apiservercel.CIDR)
				if !ok {
					return types.MaybeNoSuchOverloadErr(args[0])
				}
				newLen, ok := args[1].(types.Int)
				if !ok {
					return types.MaybeNoSuchOverloadErr(args[1])
				}
				index, ok := args[2].(types.Int)
				if !ok {
					return types.MaybeNoSuchOverloadErr(args[2])
				}
				res, err := nthSubnet(cidr.Prefix, int(newLen), int(index))
				if err != nil {
					return types.NewErr("subnet: %v", err)
				}
				return apiservercel.CIDR{Prefix: res}
			}),
		),
	)
}

// nthSubnet returns the index-th subnet of length newLen carved from p.
// p is first masked to its network address; newLen must be no shorter than p's
// prefix length and no longer than the address width, and index must fit in the
// newly added bits.
func nthSubnet(p netip.Prefix, newLen, index int) (netip.Prefix, error) {
	p = p.Masked()
	total := p.Addr().BitLen() // 32 for IPv4, 128 for IPv6
	base := p.Bits()

	if newLen < base || newLen > total {
		return netip.Prefix{}, fmt.Errorf("subnet length /%d out of range for /%d prefix", newLen, base)
	}
	if index < 0 {
		return netip.Prefix{}, fmt.Errorf("subnet index %d must be non-negative", index)
	}

	// index must address one of the 2^(newLen-base) subnets.
	subnetBits := uint(newLen - base)
	maxIndex := new(big.Int).Lsh(big.NewInt(1), subnetBits)
	if big.NewInt(int64(index)).Cmp(maxIndex) >= 0 {
		return netip.Prefix{}, fmt.Errorf("subnet index %d out of range for %d subnets of /%d", index, maxIndex, newLen)
	}

	var raw []byte
	addr := p.Addr()
	if addr.Is4() {
		b := addr.As4()
		raw = b[:]
	} else {
		b := addr.As16()
		raw = b[:]
	}

	// Place index into the host field starting at bit position newLen.
	n := new(big.Int).SetBytes(raw)
	n.Or(n, new(big.Int).Lsh(big.NewInt(int64(index)), uint(total-newLen)))

	out := make([]byte, len(raw))
	n.FillBytes(out)

	var na netip.Addr
	if addr.Is4() {
		na = netip.AddrFrom4([4]byte(out))
	} else {
		na = netip.AddrFrom16([16]byte(out))
	}
	return netip.PrefixFrom(na, newLen), nil
}
