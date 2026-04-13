package networkpolicy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tibordp/wigglenet/internal/firewall"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2/ktesting"
)

func TestSelectPods(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web", "tier": "frontend"},
			},
			netip.MustParseAddr("10.0.0.2"): {
				IP:        netip.MustParseAddr("10.0.0.2"),
				Namespace: "default",
				Labels:    map[string]string{"app": "db", "tier": "backend"},
			},
			netip.MustParseAddr("10.0.0.3"): {
				IP:        netip.MustParseAddr("10.0.0.3"),
				Namespace: "kube-system",
				Labels:    map[string]string{"app": "web", "tier": "frontend"},
			},
		},
	}

	// Test selecting all pods with app=web
	selector := metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web"},
	}
	selected := c.selectPods(ctx, "default", selector)
	assert.Len(t, selected, 1)
	assert.Equal(t, "10.0.0.1", selected[0].IP.String())

	// Test selecting pods in different namespace
	selected = c.selectPods(ctx, "kube-system", selector)
	assert.Len(t, selected, 1)
	assert.Equal(t, "10.0.0.3", selected[0].IP.String())

	// Test selecting with multiple labels
	selector = metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "web", "tier": "frontend"},
	}
	selected = c.selectPods(ctx, "default", selector)
	assert.Len(t, selected, 1)
	assert.Equal(t, "10.0.0.1", selected[0].IP.String())

	// Test selecting no pods
	selector = metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "nonexistent"},
	}
	selected = c.selectPods(ctx, "default", selector)
	assert.Len(t, selected, 0)
}

func TestBuildIngressRule(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			netip.MustParseAddr("10.0.0.2"): {
				IP:        netip.MustParseAddr("10.0.0.2"),
				Namespace: "default",
				Labels:    map[string]string{"app": "backend"},
			},
		},
		namespaces: map[string]map[string]string{
			"default": {"env": "prod"},
		},
	}

	selectedPods := []PodInfo{
		{IP: netip.MustParseAddr("10.0.0.1"), Namespace: "default", Labels: map[string]string{"app": "web"}},
	}

	// Test basic ingress rule with port
	port80 := intstr.FromInt(80)
	protocolTCP := v1.ProtocolTCP
	ingressRule := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{
				Port:     &port80,
				Protocol: &protocolTCP,
			},
		},
		From: []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "backend"},
				},
			},
		},
	}

	rule := c.buildIngressRule(ctx, selectedPods, ingressRule, "default")
	assert.NotNil(t, rule)
	assert.Equal(t, "ingress", rule.Direction)
	assert.Equal(t, "allow", rule.Action)
	assert.Len(t, rule.PodIPs, 1)
	assert.Equal(t, "10.0.0.1", rule.PodIPs[0].String())
	assert.Len(t, rule.PortRules, 1)
	assert.Equal(t, 80, rule.PortRules[0].Port)
	assert.Equal(t, "TCP", rule.PortRules[0].Protocol)
	assert.Len(t, rule.AllowedIPs, 1)
	assert.Equal(t, "10.0.0.2", rule.AllowedIPs[0].String())
}

func TestBuildEgressRule(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
		},
	}

	selectedPods := []PodInfo{
		{IP: netip.MustParseAddr("10.0.0.1"), Namespace: "default", Labels: map[string]string{"app": "web"}},
	}

	// Test egress rule with CIDR
	egressRule := networkingv1.NetworkPolicyEgressRule{
		To: []networkingv1.NetworkPolicyPeer{
			{
				IPBlock: &networkingv1.IPBlock{
					CIDR: "10.0.0.0/8",
				},
			},
		},
	}

	rule := c.buildEgressRule(ctx, selectedPods, egressRule, "default")
	assert.NotNil(t, rule)
	assert.Equal(t, "egress", rule.Direction)
	assert.Equal(t, "allow", rule.Action)
	assert.Len(t, rule.PodIPs, 1)
	assert.Equal(t, "10.0.0.1", rule.PodIPs[0].String())
	assert.Len(t, rule.AllowedCIDRs, 1)
	assert.Equal(t, "10.0.0.0/8", rule.AllowedCIDRs[0].String())
}

func TestProcessNetworkPolicyPeer(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			netip.MustParseAddr("10.0.0.2"): {
				IP:        netip.MustParseAddr("10.0.0.2"),
				Namespace: "kube-system",
				Labels:    map[string]string{"app": "dns"},
			},
		},
		namespaces: map[string]map[string]string{
			"default":     {"env": "prod"},
			"kube-system": {"name": "kube-system"},
		},
	}

	rule := &firewall.NetworkPolicyRule{
		Direction: "ingress",
	}

	// Test pod selector
	peer := networkingv1.NetworkPolicyPeer{
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"app": "web"},
		},
	}
	c.processNetworkPolicyPeer(ctx, peer, rule, "default")
	assert.Len(t, rule.AllowedIPs, 1)
	assert.Equal(t, "10.0.0.1", rule.AllowedIPs[0].String())

	// Reset rule
	rule.AllowedIPs = []netip.Addr{}

	// Test namespace selector
	peer = networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"name": "kube-system"},
		},
	}
	c.processNetworkPolicyPeer(ctx, peer, rule, "default")
	assert.Len(t, rule.AllowedIPs, 1)
	assert.Equal(t, "10.0.0.2", rule.AllowedIPs[0].String())

	// Reset rule
	rule.AllowedIPs = []netip.Addr{}
	rule.AllowedCIDRs = []netip.Prefix{}

	// Test IP block
	peer = networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{
			CIDR: "192.168.0.0/16",
		},
	}
	c.processNetworkPolicyPeer(ctx, peer, rule, "default")
	assert.Len(t, rule.AllowedCIDRs, 1)
	assert.Equal(t, "192.168.0.0/16", rule.AllowedCIDRs[0].String())
}

func TestGeneratePolicyRulesWithDefaultDeny(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			netip.MustParseAddr("10.0.0.2"): {
				IP:        netip.MustParseAddr("10.0.0.2"),
				Namespace: "default",
				Labels:    map[string]string{"app": "backend"},
			},
			netip.MustParseAddr("2001:db8::1"): {
				IP:        netip.MustParseAddr("2001:db8::1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			netip.MustParseAddr("2001:db8::2"): {
				IP:        netip.MustParseAddr("2001:db8::2"),
				Namespace: "default",
				Labels:    map[string]string{"app": "backend"},
			},
		},
		namespaces: map[string]map[string]string{
			"default": {"env": "prod"},
		},
		netpolIndexer: &fakeIndexer{
			items: []interface{}{
				&networkingv1.NetworkPolicy{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "web-netpol",
						Namespace: "default",
					},
					Spec: networkingv1.NetworkPolicySpec{
						PodSelector: metav1.LabelSelector{
							MatchLabels: map[string]string{"app": "web"},
						},
						PolicyTypes: []networkingv1.PolicyType{
							networkingv1.PolicyTypeIngress,
							networkingv1.PolicyTypeEgress,
						},
						Ingress: []networkingv1.NetworkPolicyIngressRule{
							{
								From: []networkingv1.NetworkPolicyPeer{
									{
										PodSelector: &metav1.LabelSelector{
											MatchLabels: map[string]string{"app": "backend"},
										},
									},
								},
								Ports: []networkingv1.NetworkPolicyPort{
									{
										Port:     &intstr.IntOrString{IntVal: 80},
										Protocol: &[]v1.Protocol{v1.ProtocolTCP}[0],
									},
								},
							},
						},
						Egress: []networkingv1.NetworkPolicyEgressRule{
							{
								To: []networkingv1.NetworkPolicyPeer{
									{
										IPBlock: &networkingv1.IPBlock{
											CIDR: "0.0.0.0/0",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	rules, err := c.generatePolicyRules(ctx)
	assert.NoError(t, err)

	// Should have allow rules + deny rules
	allowRules := make([]firewall.NetworkPolicyRule, 0)
	denyRules := make([]firewall.NetworkPolicyRule, 0)

	for _, rule := range rules {
		if rule.Action == "allow" {
			allowRules = append(allowRules, rule)
		} else if rule.Action == "deny" {
			denyRules = append(denyRules, rule)
		}
	}

	// Should have 2 allow rules (ingress + egress)
	assert.Len(t, allowRules, 2)

	// Should have 4 deny rules (2 pods × 2 directions, covering both IPv4 and IPv6)
	assert.Len(t, denyRules, 4)

	// Check that we have deny rules for both pods and both directions
	podIPsWithIngressDeny := make(map[netip.Addr]bool)
	podIPsWithEgressDeny := make(map[netip.Addr]bool)

	for _, rule := range denyRules {
		assert.Equal(t, "deny", rule.Action)
		for _, podIP := range rule.PodIPs {
			if rule.Direction == "ingress" {
				podIPsWithIngressDeny[podIP] = true
			} else if rule.Direction == "egress" {
				podIPsWithEgressDeny[podIP] = true
			}
		}
	}

	// Both pod IPs should have ingress and egress deny rules
	assert.True(t, podIPsWithIngressDeny[netip.MustParseAddr("10.0.0.1")])
	assert.True(t, podIPsWithIngressDeny[netip.MustParseAddr("2001:db8::1")])
	assert.True(t, podIPsWithEgressDeny[netip.MustParseAddr("10.0.0.1")])
	assert.True(t, podIPsWithEgressDeny[netip.MustParseAddr("2001:db8::1")])
}

func TestBuildIngressRuleMixedProtocols(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			netip.MustParseAddr("10.0.0.2"): {
				IP:        netip.MustParseAddr("10.0.0.2"),
				Namespace: "default",
				Labels:    map[string]string{"app": "backend"},
			},
		},
		namespaces: map[string]map[string]string{
			"default": {"env": "prod"},
		},
	}

	selectedPods := []PodInfo{
		{IP: netip.MustParseAddr("10.0.0.1"), Namespace: "default", Labels: map[string]string{"app": "web"}},
	}

	port80 := intstr.FromInt(80)
	port53 := intstr.FromInt(53)
	protocolTCP := v1.ProtocolTCP
	protocolUDP := v1.ProtocolUDP
	ingressRule := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port80, Protocol: &protocolTCP},
			{Port: &port53, Protocol: &protocolUDP},
		},
		From: []networkingv1.NetworkPolicyPeer{
			{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}}},
		},
	}

	rule := c.buildIngressRule(ctx, selectedPods, ingressRule, "default")
	assert.NotNil(t, rule)
	assert.Len(t, rule.PortRules, 2)
	assert.Equal(t, "TCP", rule.PortRules[0].Protocol)
	assert.Equal(t, 80, rule.PortRules[0].Port)
	assert.Equal(t, "UDP", rule.PortRules[1].Protocol)
	assert.Equal(t, 53, rule.PortRules[1].Port)
}

func TestBuildIngressRuleEndPort(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods: map[netip.Addr]PodInfo{
			netip.MustParseAddr("10.0.0.1"): {
				IP:        netip.MustParseAddr("10.0.0.1"),
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
		},
		namespaces: map[string]map[string]string{
			"default": {"env": "prod"},
		},
	}

	selectedPods := []PodInfo{
		{IP: netip.MustParseAddr("10.0.0.1"), Namespace: "default", Labels: map[string]string{"app": "web"}},
	}

	port8000 := intstr.FromInt(8000)
	endPort := int32(9000)
	protocolTCP := v1.ProtocolTCP
	ingressRule := networkingv1.NetworkPolicyIngressRule{
		Ports: []networkingv1.NetworkPolicyPort{
			{Port: &port8000, Protocol: &protocolTCP, EndPort: &endPort},
		},
	}

	rule := c.buildIngressRule(ctx, selectedPods, ingressRule, "default")
	assert.NotNil(t, rule)
	assert.Len(t, rule.PortRules, 1)
	assert.Equal(t, 8000, rule.PortRules[0].Port)
	assert.Equal(t, 9000, rule.PortRules[0].EndPort)
}

func TestProcessNetworkPolicyPeerIPBlockExcept(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		pods:       map[netip.Addr]PodInfo{},
		namespaces: map[string]map[string]string{},
	}

	rule := &firewall.NetworkPolicyRule{Direction: "ingress"}
	peer := networkingv1.NetworkPolicyPeer{
		IPBlock: &networkingv1.IPBlock{
			CIDR:   "10.0.0.0/8",
			Except: []string{"10.0.5.0/24"},
		},
	}
	c.processNetworkPolicyPeer(ctx, peer, rule, "default")

	// Should have CIDRs covering 10.0.0.0/8 minus 10.0.5.0/24
	assert.NotEmpty(t, rule.AllowedCIDRs)

	// 10.0.4.1 should be covered, 10.0.5.1 should not
	found4 := false
	found5 := false
	for _, cidr := range rule.AllowedCIDRs {
		if cidr.Contains(netip.MustParseAddr("10.0.4.1")) {
			found4 = true
		}
		if cidr.Contains(netip.MustParseAddr("10.0.5.1")) {
			found5 = true
		}
	}
	assert.True(t, found4, "10.0.4.1 should be in the allowed CIDRs")
	assert.False(t, found5, "10.0.5.1 should NOT be in the allowed CIDRs (excepted)")
}

// fakeIndexer implements cache.Indexer interface for testing
type fakeIndexer struct {
	items []interface{}
}

func (f *fakeIndexer) List() []interface{} {
	return f.items
}

func (f *fakeIndexer) Add(obj interface{}) error    { return nil }
func (f *fakeIndexer) Update(obj interface{}) error { return nil }
func (f *fakeIndexer) Delete(obj interface{}) error { return nil }
func (f *fakeIndexer) ListKeys() []string           { return nil }
func (f *fakeIndexer) Get(obj interface{}) (item interface{}, exists bool, err error) {
	return nil, false, nil
}
func (f *fakeIndexer) GetByKey(key string) (item interface{}, exists bool, err error) {
	return nil, false, nil
}
func (f *fakeIndexer) Replace([]interface{}, string) error { return nil }
func (f *fakeIndexer) Resync() error                       { return nil }
func (f *fakeIndexer) Index(indexName string, obj interface{}) ([]interface{}, error) {
	return nil, nil
}
func (f *fakeIndexer) IndexKeys(indexName, indexKey string) ([]string, error) { return nil, nil }
func (f *fakeIndexer) ListIndexFuncValues(indexName string) []string          { return nil }
func (f *fakeIndexer) ByIndex(indexName, indexKey string) ([]interface{}, error) {
	return nil, nil
}
func (f *fakeIndexer) GetIndexers() cache.Indexers                  { return nil }
func (f *fakeIndexer) AddIndexers(newIndexers cache.Indexers) error { return nil }
