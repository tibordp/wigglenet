package networkpolicy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tibordp/wigglenet/internal/firewall"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/klog/v2/ktesting"
)

// TestControllerEndToEndWithFakeClientset drives the controller through its real
// constructor and Run loop against a fake clientset, exercising the
// SharedInformerFactory wiring, event handlers, and the lister-backed
// updatePodsMap / generatePolicyRules path end to end.
func TestControllerEndToEndWithFakeClientset(t *testing.T) {
	_, baseCtx := ktesting.NewTestContext(t)
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()

	pod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", Labels: map[string]string{"app": "web"}},
		Status: v1.PodStatus{
			Phase:  v1.PodRunning,
			PodIPs: []v1.PodIP{{IP: "10.0.0.1"}},
			PodIP:  "10.0.0.1",
		},
	}
	ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
	// Ingress policy selecting app=web with no rules -> default-deny ingress.
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-web", Namespace: "default"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}

	client := fake.NewSimpleClientset(pod, ns, np)
	updates := make(chan []firewall.NetworkPolicyRule, 8)

	ctrl, err := NewController(client, updates)
	require.NoError(t, err)

	go ctrl.Run(ctx)

	select {
	case rules := <-updates:
		var denies []firewall.NetworkPolicyRule
		for _, r := range rules {
			if r.Action == "deny" && r.Direction == "ingress" {
				denies = append(denies, r)
			}
		}
		require.NotEmpty(t, denies, "expected a default-deny ingress rule for the selected pod")

		found := false
		for _, r := range denies {
			for _, ip := range r.PodIPs {
				if ip == netip.MustParseAddr("10.0.0.1") {
					found = true
				}
			}
		}
		assert.True(t, found, "expected deny rule to cover pod IP 10.0.0.1")
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the controller to emit policy rules")
	}
}
