package controller

import (
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/tibordp/wigglenet/internal/annotations"
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
	Run(stopCh chan struct{})
}

type controller struct {
	indexer         cache.Indexer
	queue           workqueue.RateLimitingInterface
	informer        cache.Controller
	wireguard       wireguard.WireguardManager
	cniwriter       cni.CNIConfigWriter
	firewallUpdates chan firewall.FirewallConfig
}

func NewController(clientset kubernetes.Interface, wireguardManager wireguard.WireguardManager, cniwriter cni.CNIConfigWriter, firewallUpdates chan firewall.FirewallConfig) *controller {
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

func (c *controller) processNextItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}

	defer c.queue.Done(key)

	c.handleErr(c.processChanges(key), key)
	return true
}

func (c *controller) processChanges(key interface{}) error {
	if key == config.CurrentNodeName {
		if err := c.ensureCNI(); err != nil {
			return err
		}
	}

	if err := c.applyNetworkingConfiguration(); err != nil {
		return err
	}

	if err := c.applyFirewall(); err != nil {
		return err
	}

	return nil
}

func (c *controller) applyFirewall() error {
	podCIDRs := make([]net.IPNet, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			podCIDRs = append(podCIDRs, util.GetPodCIDRs(node)...)
		}
	}

	c.firewallUpdates <- firewall.NewConfig(podCIDRs)
	return nil
}

func (c *controller) applyNetworkingConfiguration() error {

	peers := make([]wireguard.Peer, 0)
	localAddresses := make([]net.IP, 0)

	for _, v := range c.indexer.List() {
		if node, ok := v.(*v1.Node); ok {
			if node.Name == config.CurrentNodeName {
				podCIDRs := util.GetPodCIDRs(node)
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

func (c *controller) ensureCNI() error {
	item, exists, _ := c.indexer.GetByKey(config.CurrentNodeName)
	if node, ok := item.(*v1.Node); exists && ok {
		podCIDRs := util.GetPodCIDRs(node)

		if len(podCIDRs) == 0 {
			klog.Infof("node %v does not have PodCIDRs assigned yet", node.Name)
			return nil
		}

		config := cni.CNIConfig{
			PodCIDRs: podCIDRs,
		}

		return c.cniwriter.Write(config)
	}

	return nil
}

func makePeer(node *v1.Node) *wireguard.Peer {
	podCIDRs := util.GetPodCIDRs(node)

	if len(node.Spec.PodCIDRs) == 0 {
		klog.Infof("node %v does not have PodCIDRs assigned yet", node.Name)
		return nil
	}

	nodeAddress := net.ParseIP(node.Annotations[annotations.NodeIpAnnotation])
	if nodeAddress == nil {
		return nil
	}

	publicKeyStr := node.Annotations[annotations.PublicKeyAnnotation]
	if publicKeyStr == "" {
		return nil
	}

	publicKey, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil || len(publicKey) != wgtypes.KeyLen {
		klog.Warningf("invalid public key for node %v", node.Name)
		return nil
	}

	peer := &wireguard.Peer{
		Endpoint:  nodeAddress,
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

// Run begins watching and syncing.
func (c *controller) Run(stopCh chan struct{}) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer c.queue.ShutDown()
	klog.Info("starting controller")

	go c.informer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, c.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// After we have all the nodes in cache, sync the routing state
	if err := c.applyNetworkingConfiguration(); err != nil {
		runtime.HandleError(err)
	}

	go wait.Until(c.runWorker, time.Second, stopCh)

	<-stopCh
	klog.Info("stopping controller")
}

func (c *controller) runWorker() {
	for c.processNextItem() {
	}
}
