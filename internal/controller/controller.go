package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/metrics"
	"github.com/tibordp/wigglenet/internal/util"
	"github.com/tibordp/wigglenet/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller interface {
	Run(ctx context.Context)
}

type controller struct {
	factory        informers.SharedInformerFactory
	nodeLister     listersv1.NodeLister
	queue          workqueue.TypedRateLimitingInterface[string]
	wireguard      wireguard.Manager
	cniwriter      cni.CNIConfigWriter
	podCIDRUpdates chan []netip.Prefix
}

func NewController(clientset kubernetes.Interface, wireguardManager wireguard.Manager, cniwriter cni.CNIConfigWriter, podCIDRUpdates chan []netip.Prefix) (*controller, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0, informers.WithTransform(util.StripManagedFields))
	nodes := factory.Core().V1().Nodes()

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	if _, err := nodes.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if key, err := cache.MetaNamespaceKeyFunc(obj); err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(_, newObj interface{}) {
			if key, err := cache.MetaNamespaceKeyFunc(newObj); err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj); err == nil {
				queue.Add(key)
			}
		},
	}); err != nil {
		return nil, fmt.Errorf("registering node event handler: %w", err)
	}

	return &controller{
		factory:        factory,
		nodeLister:     nodes.Lister(),
		queue:          queue,
		wireguard:      wireguardManager,
		cniwriter:      cniwriter,
		podCIDRUpdates: podCIDRUpdates,
	}, nil
}

// processChanges gets called on any change to a node object as well as additions and removals.
// it computes the new state of the world and adjust the local networking setup accordingly
func (c *controller) processChanges(ctx context.Context, key string) error {
	if err := c.applyWireguardConfiguration(ctx); err != nil {
		return err
	}

	if err := c.applyFirewallRules(); err != nil {
		return err
	}

	if !config.FirewallOnly && key == config.CurrentNodeName {
		if err := c.ensureCNI(ctx); err != nil {
			return err
		}
	}

	return nil
}

// applyFirewallRules calculates the new pod network and sends it to the iptables sync
// goroutine so that pod traffic can be appropriately filtered and masqueraded.
func (c *controller) applyFirewallRules() error {
	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	podCIDRs := make([]netip.Prefix, 0)
	for _, node := range nodes {
		podCIDRs = append(podCIDRs, util.GetPodCIDRsFromAnnotation(node)...)
	}

	// Node listing order is not stable (it comes from the informer cache map),
	// so sort into a canonical order. Otherwise the firewall manager's
	// deep-equality check would see a "change" on every node event and rewrite
	// the whole ruleset needlessly.
	util.SortPrefixes(podCIDRs)

	if config.EnableMetrics {
		metrics.PodCIDRsTotal.Set(float64(len(podCIDRs)))
	}

	// Send pod CIDR updates to firewall manager
	c.podCIDRUpdates <- podCIDRs
	return nil
}

// applyWireguardConfiguration configures the Wireguard network interface and makes
// appropriate changes to the routing table.
func (c *controller) applyWireguardConfiguration(ctx context.Context) error {
	if c.wireguard == nil {
		return nil
	}

	logger := klog.FromContext(ctx)

	nodes, err := c.nodeLister.List(labels.Everything())
	if err != nil {
		return err
	}

	peers := make([]wireguard.Peer, 0)
	localAddresses := make([]netip.Addr, 0)

	for _, node := range nodes {
		if node.Name == config.CurrentNodeName {
			podCIDRs := util.GetPodCIDRsFromAnnotation(node)
			localAddresses = util.GetPodNetworkLocalAddresses(podCIDRs)
		} else {
			if peer := makePeer(ctx, node); peer != nil {
				peers = append(peers, *peer)
			}
		}
	}

	if config.EnableMetrics {
		metrics.PeersTotal.Set(float64(len(peers)))
	}

	wgConfig := wireguard.NewConfig(localAddresses, peers)
	return c.wireguard.ApplyConfiguration(ctx, &wgConfig, logger)
}

// ensureCNI writes the local CNI configuration to /etc/cni/net.d if there were
// relevant changes to pod CIDRs. This can change during the lifetime of the node,
// e.g. if another address family is added to an existing cluster.
func (c *controller) ensureCNI(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	node, err := c.nodeLister.Get(config.CurrentNodeName)
	if err != nil {
		// Node not yet observed in the cache; nothing to write.
		return nil
	}

	podCIDRs := util.GetPodCIDRsFromAnnotation(node)
	if len(podCIDRs) == 0 {
		logger.Info("node does not have PodCIDRs assigned yet", "node", node.Name)
		return nil
	}

	config := cni.CNIConfig{
		PodCIDRs: podCIDRs,
	}

	return c.cniwriter.WriteCNIConfig(ctx, config, logger)
}

func getNodeAddresses(ctx context.Context, node *v1.Node) ([]netip.Addr, error) {
	logger := klog.FromContext(ctx)
	var annotationAddresses []netip.Addr
	err := json.Unmarshal([]byte(node.Annotations[annotation.NodeIpsAnnotation]), &annotationAddresses)
	if annotationAddresses == nil || err != nil {
		logger.Info("invalid node-ips annotation", "node", node.Name, "annotation", node.Annotations[annotation.NodeIpsAnnotation])
		return nil, err
	}

	statusAddresses := util.GetNodeAddresses(node)

	nodeAddresses := make([]netip.Addr, 0)

	for _, coll := range [][]netip.Addr{statusAddresses, annotationAddresses} {
		if coll == nil {
			continue
		}

		for _, entry := range coll {
			nodeAddresses = append(nodeAddresses, entry)
		}
	}

	// Remove duplicates using slices.Compact (requires sorted slice)
	slices.SortFunc(nodeAddresses, func(a, b netip.Addr) int {
		return a.Compare(b)
	})
	nodeAddresses = slices.Compact(nodeAddresses)

	return nodeAddresses, nil
}

func makePeer(ctx context.Context, node *v1.Node) *wireguard.Peer {
	logger := klog.FromContext(ctx)
	publicKeyStr := node.Annotations[annotation.PublicKeyAnnotation]
	if publicKeyStr == "" {
		// If we return here, the node is simply not initialized yet, which is normal,
		// so we don't log anything.
		return nil
	}

	podCIDRs := util.GetPodCIDRsFromAnnotation(node)
	if len(podCIDRs) == 0 {
		logger.Info("node does not have PodCIDRs assigned yet", "node", node.Name)
		return nil
	}

	publicKey, err := wgtypes.ParseKey(publicKeyStr)
	if err != nil {
		logger.Info("invalid public key for node", "node", node.Name, "error", err)
		return nil
	}

	nodeAddresses, err := getNodeAddresses(ctx, node)
	if err != nil || len(nodeAddresses) == 0 {
		logger.Info("could not determine node addresses", "node", node.Name, "error", err)
		return nil
	}

	nodeCidrs := make([]netip.Prefix, 0, len(nodeAddresses))
	for _, nodeAddress := range nodeAddresses {
		nodeCidrs = append(nodeCidrs, util.SingleHostCIDR(nodeAddress))
	}

	peerEndpoint := util.SelectIP(nodeAddresses, config.WireguardIPFamily)
	if peerEndpoint == nil {
		logger.Info("could not determine peer endpoint", "node", node.Name)
		return nil
	}

	peer := &wireguard.Peer{
		Endpoint:  *peerEndpoint,
		NodeCIDRs: nodeCidrs,
		PodCIDRs:  podCIDRs,
		PublicKey: publicKey,
	}

	return peer
}

func (c *controller) Run(ctx context.Context) {
	defer runtime.HandleCrash()
	logger := klog.FromContext(ctx)

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	logger.Info("starting controller")

	c.factory.StartWithContext(ctx)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if err := c.factory.WaitForCacheSyncWithContext(ctx).AsError(); err != nil {
		runtime.HandleErrorWithContext(ctx, err, "timed out waiting for caches to sync")
		return
	}

	// After we have all the nodes in cache, sync the routing state
	if err := c.applyWireguardConfiguration(ctx); err != nil {
		runtime.HandleErrorWithContext(ctx, err, "failed initial wireguard configuration")
	}

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	<-ctx.Done()

	logger.Info("finished controller")
}

func (c *controller) processNextItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	err := c.processChanges(ctx, key)
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	runtime.HandleErrorWithContext(ctx, err, "Error syncing node; requeuing for later retry", "node", key)
	c.queue.AddRateLimited(key)
	return true
}

func (c *controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}
