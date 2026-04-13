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
	"github.com/tibordp/wigglenet/internal/util"
	"github.com/tibordp/wigglenet/internal/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller interface {
	Run(ctx context.Context)
}

type controller struct {
	indexer        cache.Indexer
	queue          workqueue.TypedRateLimitingInterface[string]
	informer       cache.Controller
	wireguard      wireguard.Manager
	cniwriter      cni.CNIConfigWriter
	podCIDRUpdates chan []netip.Prefix
}

func NewController(clientset kubernetes.Interface, wireguardManager wireguard.Manager, cniwriter cni.CNIConfigWriter, podCIDRUpdates chan []netip.Prefix) *controller {
	nodeListWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "nodes", v1.NamespaceAll, fields.Everything())
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())
	indexer, informer := cache.NewTransformingIndexerInformer(nodeListWatcher, &v1.Node{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
		UpdateFunc: func(old interface{}, new interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				queue.Add(key)
			}
		},
	}, cache.Indexers{}, util.StripManagedFields)

	return &controller{
		informer:       informer,
		indexer:        indexer,
		queue:          queue,
		wireguard:      wireguardManager,
		cniwriter:      cniwriter,
		podCIDRUpdates: podCIDRUpdates,
	}
}

// processChanges gets called on any change to a node object as well as additions and removals.
// it computes the new state of the world and adjust the local networking setup accordingly
func (c *controller) processChanges(ctx context.Context, key string) error {
	if !config.FirewallOnly && !config.NativeRouting {
		if err := c.applyWireguardConfiguration(ctx); err != nil {
			return err
		}
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
	podCIDRs := make([]netip.Prefix, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			podCIDRs = append(podCIDRs, util.GetPodCIDRsFromAnnotation(node)...)
		}
	}

	// Send pod CIDR updates to firewall manager
	c.podCIDRUpdates <- podCIDRs
	return nil
}

// applyWireguardConfiguration configures the Wireguard network interface and makes
// appropriate changes to the routing table.
func (c *controller) applyWireguardConfiguration(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	peers := make([]wireguard.Peer, 0)
	localAddresses := make([]netip.Addr, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			if node.Name == config.CurrentNodeName {
				podCIDRs := util.GetPodCIDRsFromAnnotation(node)
				localAddresses = util.GetPodNetworkLocalAddresses(podCIDRs)
			} else {
				peer := makePeer(ctx, node)
				if peer != nil {
					peers = append(peers, *peer)
				}
			}
		}
	}

	config := wireguard.NewConfig(localAddresses, peers)
	return c.wireguard.ApplyConfiguration(ctx, &config, logger)
}

// ensureCNI writes the local CNI configuration to /etc/cni/net.d if there were
// relevant changes to pod CIDRs. This can change during the lifetime of the node,
// e.g. if another address family is added to an existing cluster.
func (c *controller) ensureCNI(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	item, exists, _ := c.indexer.GetByKey(config.CurrentNodeName)
	if node, ok := item.(*v1.Node); exists && ok {
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

	return nil
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

	go c.informer.Run(ctx.Done())

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// After we have all the nodes in cache, sync the routing state
	if err := c.applyWireguardConfiguration(ctx); err != nil {
		runtime.HandleError(err)
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
