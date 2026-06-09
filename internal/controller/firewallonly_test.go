package controller

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2/ktesting"
)

// FirewallOnly/NativeRouting run with a nil wireguard.Manager; the startup
// reconcile must be a no-op, not a panic.
func TestApplyWireguardConfigurationNilManager(t *testing.T) {
	_, ctx := ktesting.NewTestContext(t)
	c := &controller{
		nodeLister:     listersv1.NewNodeLister(cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})),
		wireguard:      nil,
		podCIDRUpdates: make(chan []netip.Prefix, 1),
	}

	assert.NotPanics(t, func() {
		assert.NoError(t, c.applyWireguardConfiguration(ctx))
	})
}
