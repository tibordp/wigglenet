package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/firewall"
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
	indexer         cache.Indexer
	queue           workqueue.RateLimitingInterface
	informer        cache.Controller
	wireguard       wireguard.Manager
	cniwriter       cni.CNIConfigWriter
	firewallUpdates chan firewall.FirewallConfig
}

func NewController(clientset kubernetes.Interface, wireguardManager wireguard.Manager, cniwriter cni.CNIConfigWriter, firewallUpdates chan firewall.FirewallConfig) *controller {
	nodeListWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "nodes", v1.NamespaceAll, fields.Everything())
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	indexer, informer := cache.NewIndexerInformer(nodeListWatcher, &v1.Node{}, 0, cache.ResourceEventHandlerFuncs{
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
	}, cache.Indexers{})

	return &controller{
		informer:        informer,
		indexer:         indexer,
		queue:           queue,
		wireguard:       wireguardManager,
		cniwriter:       cniwriter,
		firewallUpdates: firewallUpdates,
	}
}

// processChanges gets called on any change to a node object as well as additions and removals.
// it computes the new state of the world and adjust the local networking setup accordingly
func (c *controller) processChanges(key interface{}) error {
	if !config.FirewallOnly && !config.NativeRouting {
		if err := c.applyWireguardConfiguration(); err != nil {
			return err
		}
	}

	if err := c.applyFirewallRules(); err != nil {
		return err
	}

	if !config.FirewallOnly && key == config.CurrentNodeName {
		if err := c.ensureCNI(); err != nil {
			return err
		}
	}

	return nil
}

// applyFirewallRules calculates the new pod network and sends it to the iptables sync
// goroutine so that pod traffic can be appropriately filtered and masqueraded.
func (c *controller) applyFirewallRules() error {
	podCIDRs := make([]net.IPNet, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			podCIDRs = append(podCIDRs, util.GetPodCIDRsFromAnnotation(node)...)
		}
	}

	c.firewallUpdates <- firewall.NewConfig(podCIDRs)
	return nil
}

// applyWireguardConfiguration configures the Wireguard network interface and makes
// appropriate changes to the routing table.
func (c *controller) applyWireguardConfiguration() error {

	peers := make([]wireguard.Peer, 0)
	localAddresses := make([]net.IP, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			if node.Name == config.CurrentNodeName {
				podCIDRs := util.GetPodCIDRsFromAnnotation(node)
				localAddresses = util.GetPodNetworkLocalAddresses(podCIDRs)
			} else {
				peer := makePeer(node)
				if peer != nil {
					peers = append(peers, *peer)
				}
			}
		}
	}

	config := wireguard.NewConfig(localAddresses, peers)
	return c.wireguard.ApplyConfiguration(&config)
}

// ensureCNI writes the local CNI configuration to /etc/cni/net.d if there were
// relevant changes to pod CIDRs. This can change during the lifetime of the node,
// e.g. if another address family is added to an existing cluster.
func (c *controller) ensureCNI() error {
	item, exists, _ := c.indexer.GetByKey(config.CurrentNodeName)
	if node, ok := item.(*v1.Node); exists && ok {
		podCIDRs := util.GetPodCIDRsFromAnnotation(node)

		if len(podCIDRs) == 0 {
			klog.Infof("node %v does not have PodCIDRs assigned yet", node.Name)
			return nil
		}

		config := cni.CNIConfig{
			PodCIDRs: podCIDRs,
		}

		return c.cniwriter.WriteCNIConfig(config)
	}

	return nil
}

func makePeer(node *v1.Node) *wireguard.Peer {
	publicKeyStr := node.Annotations[annotation.PublicKeyAnnotation]
	if publicKeyStr == "" {
		// If we return here, the node is simply not initialized yet, which is normal,
		// so we don't log anything.
		return nil
	}

	podCIDRs := util.GetPodCIDRsFromAnnotation(node)
	if len(podCIDRs) == 0 {
		klog.Warningf("node %v does not have PodCIDRs assigned yet", node.Name)
		return nil
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil || len(publicKey) != wgtypes.KeyLen {
		klog.Warningf("invalid public key for node %v", node.Name)
		return nil
	}

	var nodeAddresses []net.IP
	err = json.Unmarshal([]byte(node.Annotations[annotation.NodeIpsAnnotation]), &nodeAddresses)
	if nodeAddresses == nil || err != nil {
		klog.Warningf("invalid node-ips %v", node.Annotations[annotation.NodeIpsAnnotation])
		return nil
	}

	nodeCidrs := make([]net.IPNet, 0, len(nodeAddresses))
	for _, nodeAddress := range nodeAddresses {
		if nodeAddresses == nil {
			return nil
		}
		nodeCidrs = append(nodeCidrs, util.SingleHostCIDR(nodeAddress))
	}

	peerEndpoint := util.SelectIP(nodeAddresses, config.WireguardIPFamily)
	if peerEndpoint == nil {
		klog.Warningf("could not determine peer endpoint for %v", node.Name)
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

func (c *controller) handleErr(err error, key interface{}) {
	if err == nil {
		c.queue.Forget(key)
		return
	}

	if c.queue.NumRequeues(key) < 5 {
		klog.Infof("error syncing node %v: %v", key, err)
		c.queue.AddRateLimited(key)
		return
	}

	c.queue.Forget(key)
	runtime.HandleError(err)

	klog.Warningf("dropping node %q out of the queue: %v", key, err)
}

func (c *controller) Run(ctx context.Context) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	klog.Info("starting controller")

	go c.informer.Run(ctx.Done())

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// After we have all the nodes in cache, sync the routing state
	if err := c.applyWireguardConfiguration(); err != nil {
		runtime.HandleError(err)
	}

	go wait.Until(c.runWorker, time.Second, ctx.Done())
	<-ctx.Done()

	klog.Info("finished controller")
}

func (c *controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	c.handleErr(c.processChanges(key), key)
	return true
}

func (c *controller) runWorker() {
	for c.processNextItem() {
	}
}
