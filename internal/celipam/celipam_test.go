package celipam

import (
	"net/netip"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func sampleInputs() Inputs {
	return Inputs{
		Interfaces: map[string][]netip.Prefix{
			// host bits set on purpose: this is the node's actual address + on-link mask
			"eth0": prefixes("2001:db8:abcd:1234::5/64", "10.0.0.5/24"),
			"lo":   prefixes("::1/128"),
		},
		Node: NodeInfo{
			Name:   "node-1",
			Labels: map[string]string{"topology.kubernetes.io/zone": "eu-central"},
		},
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []string
	}{
		{
			name: "hetzner: second /80 of the routed /64",
			expr: `interfaces["eth0"].filter(p, p.prefixLength() == 64 && p.ip().family() == 6)[0].subnet(80, 1)`,
			want: []string{"2001:db8:abcd:1234:1::/80"},
		},
		{
			name: "masked compose",
			expr: `interfaces["eth0"].filter(p, p.ip().family() == 6)[0].masked().subnet(96, 3)`,
			want: []string{"2001:db8:abcd:1234:0:3::/96"},
		},
		{
			name: "ipv4 carve",
			expr: `interfaces["eth0"].filter(p, p.ip().family() == 4)[0].subnet(28, 2)`,
			want: []string{"10.0.0.32/28"},
		},
		{
			name: "both families as a list",
			expr: `[
				interfaces["eth0"].filter(p, p.ip().family() == 6)[0].subnet(80, 1),
				interfaces["eth0"].filter(p, p.ip().family() == 4)[0].subnet(28, 0)
			]`,
			want: []string{"2001:db8:abcd:1234:1::/80", "10.0.0.0/28"},
		},
		{
			name: "node label drives the index",
			expr: `interfaces["eth0"].filter(p, p.prefixLength() == 64)[0].subnet(80, node.labels["topology.kubernetes.io/zone"] == "eu-central" ? 5 : 0)`,
			want: []string{"2001:db8:abcd:1234:5::/80"},
		},
		{
			name: "bare cidr literal masked",
			expr: `cidr("2001:db8::1/64").masked()`,
			want: []string{"2001:db8::/64"},
		},
		{
			name: "unmasked result is masked by the evaluator",
			expr: `interfaces["eth0"].filter(p, p.ip().family() == 6)[0]`,
			want: []string{"2001:db8:abcd:1234::/64"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := Compile(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			got, err := eval.Evaluate(sampleInputs())
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i].String() != tc.want[i] {
					t.Fatalf("element %d: got %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestEvaluateNilMaps(t *testing.T) {
	// A node with no labels/annotations (nil maps) must not panic, and CEL
	// membership tests against them must behave like empty maps.
	in := Inputs{
		Interfaces: map[string][]netip.Prefix{"eth0": prefixes("2001:db8::5/64")},
		Node:       NodeInfo{Name: "node-1"},
	}
	eval, err := Compile(`interfaces["eth0"][0].subnet(80, "zone" in node.labels ? 1 : 0)`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got, err := eval.Evaluate(in)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(got) != 1 || got[0].String() != "2001:db8::/80" {
		t.Fatalf("got %v, want [2001:db8::/80]", got)
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"syntax error", `interfaces["eth0"`},
		{"unknown variable", `bogus["eth0"]`},
		{"wrong output type", `interfaces["eth0"].size()`}, // int, not cidr/list(cidr)
		{"wrong output type string", `"10.0.0.0/24"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile(tc.expr); err == nil {
				t.Fatalf("expected compile error for %q", tc.expr)
			}
		})
	}
}

func TestEvaluateRuntimeErrors(t *testing.T) {
	cases := []struct {
		name string
		expr string
	}{
		{"index out of range", `interfaces["eth0"].filter(p, p.prefixLength() == 64)[0].subnet(65, 2)`},
		{"shorter subnet than parent", `interfaces["eth0"].filter(p, p.ip().family()==6)[0].subnet(48, 0)`},
		{"negative index", `interfaces["eth0"].filter(p, p.prefixLength() == 64)[0].subnet(80, -1)`},
		{"missing interface", `interfaces["doesnotexist"][0]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := Compile(tc.expr)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if _, err := eval.Evaluate(sampleInputs()); err == nil {
				t.Fatalf("expected runtime error for %q", tc.expr)
			}
		})
	}
}

func TestNthSubnet(t *testing.T) {
	cases := []struct {
		parent      string
		newLen, idx int
		want        string
		wantErr     bool
	}{
		{"2001:db8:abcd:1234::/64", 80, 0, "2001:db8:abcd:1234::/80", false},
		{"2001:db8:abcd:1234::/64", 80, 1, "2001:db8:abcd:1234:1::/80", false},
		{"2001:db8:abcd:1234::/64", 80, 65535, "2001:db8:abcd:1234:ffff::/80", false},
		{"2001:db8:abcd:1234::/64", 80, 65536, "", true}, // one past the last /80
		{"10.0.0.0/24", 28, 2, "10.0.0.32/28", false},
		{"10.0.0.0/24", 32, 5, "10.0.0.5/32", false},
		{"10.0.0.5/24", 28, 1, "10.0.0.16/28", false}, // host bits in parent are masked off
		{"10.0.0.0/24", 24, 0, "10.0.0.0/24", false},  // newLen == base
		{"10.0.0.0/24", 20, 0, "", true},              // newLen shorter than base
		{"10.0.0.0/24", 33, 0, "", true},              // beyond address width
	}
	for _, tc := range cases {
		got, err := nthSubnet(netip.MustParsePrefix(tc.parent), tc.newLen, tc.idx)
		if tc.wantErr {
			if err == nil {
				t.Errorf("nthSubnet(%s, %d, %d): expected error, got %s", tc.parent, tc.newLen, tc.idx, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("nthSubnet(%s, %d, %d): unexpected error %v", tc.parent, tc.newLen, tc.idx, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("nthSubnet(%s, %d, %d) = %s, want %s", tc.parent, tc.newLen, tc.idx, got, tc.want)
		}
	}
}
