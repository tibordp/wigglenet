package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/tibordp/wigglenet/internal/firewall"
	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller interface {
	Run(ctx context.Context)
}

type PodInfo struct {
	IP        netip.Addr
	Namespace string
	Labels    map[string]string
}

type controller struct {
	clientset     kubernetes.Interface
	policyUpdates chan []firewall.NetworkPolicyRule

	// NetworkPolicy informer
	netpolIndexer  cache.Indexer
	netpolInformer cache.Controller

	// Pod informer
	podIndexer  cache.Indexer
	podInformer cache.Controller

	// Namespace informer
	nsIndexer  cache.Indexer
	nsInformer cache.Controller

	queue workqueue.TypedRateLimitingInterface[string]

	// Current state
	pods       map[netip.Addr]PodInfo       // podIP -> PodInfo
	namespaces map[string]map[string]string // namespace -> labels
}

func NewController(clientset kubernetes.Interface, policyUpdates chan []firewall.NetworkPolicyRule) Controller {
	// NetworkPolicy informer
	netpolListWatcher := cache.NewListWatchFromClient(
		clientset.NetworkingV1().RESTClient(),
		"networkpolicies",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	// Pod informer
	podListWatcher := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"pods",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	// Namespace informer
	nsListWatcher := cache.NewListWatchFromClient(
		clientset.CoreV1().RESTClient(),
		"namespaces",
		metav1.NamespaceAll,
		fields.Everything(),
	)

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	// Create indexers and informers
	netpolIndexer, netpolInformer := cache.NewIndexerInformer(
		netpolListWatcher,
		&networkingv1.NetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { queue.Add("networkpolicy") },
			UpdateFunc: func(old, new interface{}) { queue.Add("networkpolicy") },
			DeleteFunc: func(obj interface{}) { queue.Add("networkpolicy") },
		},
		cache.Indexers{},
	)

	podIndexer, podInformer := cache.NewIndexerInformer(
		podListWatcher,
		&v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { queue.Add("pod") },
			UpdateFunc: func(old, new interface{}) { queue.Add("pod") },
			DeleteFunc: func(obj interface{}) { queue.Add("pod") },
		},
		cache.Indexers{},
	)

	nsIndexer, nsInformer := cache.NewIndexerInformer(
		nsListWatcher,
		&v1.Namespace{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    func(obj interface{}) { queue.Add("namespace") },
			UpdateFunc: func(old, new interface{}) { queue.Add("namespace") },
			DeleteFunc: func(obj interface{}) { queue.Add("namespace") },
		},
		cache.Indexers{},
	)

	return &controller{
		clientset:      clientset,
		policyUpdates:  policyUpdates,
		netpolIndexer:  netpolIndexer,
		netpolInformer: netpolInformer,
		podIndexer:     podIndexer,
		podInformer:    podInformer,
		nsIndexer:      nsIndexer,
		nsInformer:     nsInformer,
		queue:          queue,
		pods:           make(map[netip.Addr]PodInfo),
		namespaces:     make(map[string]map[string]string),
	}
}

func (c *controller) Run(ctx context.Context) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("starting NetworkPolicy controller")

	// Start informers
	go c.netpolInformer.Run(ctx.Done())
	go c.podInformer.Run(ctx.Done())
	go c.nsInformer.Run(ctx.Done())

	// Wait for caches to sync
	if !cache.WaitForCacheSync(ctx.Done(),
		c.netpolInformer.HasSynced,
		c.podInformer.HasSynced,
		c.nsInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	// Initial sync
	c.syncState(ctx)

	go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	<-ctx.Done()

	logger.Info("finished NetworkPolicy controller")
}

func (c *controller) runWorker(ctx context.Context) {
	for c.processNextItem(ctx) {
	}
}

func (c *controller) processNextItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.syncState(ctx)
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	runtime.HandleErrorWithContext(ctx, err, "Error syncing NetworkPolicy; requeuing for later retry", "key", key)
	c.queue.AddRateLimited(key)
	return true
}

func (c *controller) syncState(ctx context.Context) error {
	// Update pods map
	c.updatePodsMap()

	// Update namespaces map
	c.updateNamespacesMap()

	// Generate NetworkPolicy rules
	policyRules, err := c.generatePolicyRules(ctx)
	if err != nil {
		return err
	}

	// Send updated policy rules
	c.policyUpdates <- policyRules

	return nil
}

func (c *controller) updatePodsMap() {
	newPods := make(map[netip.Addr]PodInfo)

	for _, obj := range c.podIndexer.List() {
		if pod, ok := obj.(*v1.Pod); ok {
			if pod.Status.Phase == v1.PodRunning {
				// Handle dual-stack: read all pod IPs from status.podIPs
				for _, podIPStatus := range pod.Status.PodIPs {
					if podIPStatus.IP != "" {
						if addr, err := netip.ParseAddr(podIPStatus.IP); err == nil {
							newPods[addr] = PodInfo{
								IP:        addr,
								Namespace: pod.Namespace,
								Labels:    pod.Labels,
							}
						}
					}
				}

				// Fallback to status.podIP for compatibility
				if pod.Status.PodIP != "" {
					if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil {
						newPods[addr] = PodInfo{
							IP:        addr,
							Namespace: pod.Namespace,
							Labels:    pod.Labels,
						}
					}
				}
			}
		}
	}

	c.pods = newPods
}

func (c *controller) updateNamespacesMap() {
	newNamespaces := make(map[string]map[string]string)

	for _, obj := range c.nsIndexer.List() {
		if ns, ok := obj.(*v1.Namespace); ok {
			newNamespaces[ns.Name] = ns.Labels
		}
	}

	c.namespaces = newNamespaces
}

func (c *controller) generatePolicyRules(ctx context.Context) ([]firewall.NetworkPolicyRule, error) {
	var rules []firewall.NetworkPolicyRule

	// Track which pods are affected by policies (by direction)
	affectedPodsIngress := make(map[netip.Addr]bool) // podIP -> true
	affectedPodsEgress := make(map[netip.Addr]bool)  // podIP -> true

	for _, obj := range c.netpolIndexer.List() {
		netpol, ok := obj.(*networkingv1.NetworkPolicy)
		if !ok {
			continue
		}

		// Find pods that this policy applies to
		selectedPods := c.selectPods(ctx, netpol.Namespace, netpol.Spec.PodSelector)

		// Check if this policy affects ingress traffic
		hasIngressPolicy := false
		for _, policyType := range netpol.Spec.PolicyTypes {
			if policyType == networkingv1.PolicyTypeIngress {
				hasIngressPolicy = true
				break
			}
		}

		// Check if this policy affects egress traffic
		hasEgressPolicy := false
		for _, policyType := range netpol.Spec.PolicyTypes {
			if policyType == networkingv1.PolicyTypeEgress {
				hasEgressPolicy = true
				break
			}
		}

		// Process ingress rules (if policy type is Ingress)
		if hasIngressPolicy {
			// Mark these pods as affected by ingress policies
			for _, pod := range selectedPods {
				affectedPodsIngress[pod.IP] = true
			}

			// Generate allow rules for each ingress rule (if any)
			for _, ingressRule := range netpol.Spec.Ingress {
				rule := c.buildIngressRule(ctx, selectedPods, ingressRule, netpol.Namespace)
				if rule != nil {
					rules = append(rules, *rule)
				}
			}
		}

		// Process egress rules (if policy type is Egress)
		if hasEgressPolicy {
			// Mark these pods as affected by egress policies
			for _, pod := range selectedPods {
				affectedPodsEgress[pod.IP] = true
			}

			// Generate allow rules for each egress rule (if any)
			for _, egressRule := range netpol.Spec.Egress {
				rule := c.buildEgressRule(ctx, selectedPods, egressRule, netpol.Namespace)
				if rule != nil {
					rules = append(rules, *rule)
				}
			}
		}
	}

	// Generate default deny rules for affected pods
	for podIP := range affectedPodsIngress {
		rules = append(rules, firewall.NetworkPolicyRule{
			Direction: "ingress",
			PodIPs:    []netip.Addr{podIP},
			Action:    "deny",
		})
	}

	for podIP := range affectedPodsEgress {
		rules = append(rules, firewall.NetworkPolicyRule{
			Direction: "egress",
			PodIPs:    []netip.Addr{podIP},
			Action:    "deny",
		})
	}

	return rules, nil
}

func (c *controller) selectPods(ctx context.Context, namespace string, selector metav1.LabelSelector) []PodInfo {
	logger := klog.FromContext(ctx)
	var selected []PodInfo

	labelSelector, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		logger.Info("invalid label selector", "namespace", namespace, "error", err)
		return selected
	}

	for _, pod := range c.pods {
		if pod.Namespace == namespace && labelSelector.Matches(labels.Set(pod.Labels)) {
			selected = append(selected, pod)
		}
	}

	return selected
}

func (c *controller) buildIngressRule(ctx context.Context, selectedPods []PodInfo, ingressRule networkingv1.NetworkPolicyIngressRule, namespace string) *firewall.NetworkPolicyRule {
	if len(selectedPods) == 0 {
		return nil
	}

	rule := &firewall.NetworkPolicyRule{
		Direction: "ingress",
		PodIPs:    make([]netip.Addr, 0, len(selectedPods)),
		Action:    "allow",
	}

	// Add pod IPs
	for _, pod := range selectedPods {
		rule.PodIPs = append(rule.PodIPs, pod.IP)
	}

	// Process ports
	if len(ingressRule.Ports) > 0 {
		for _, port := range ingressRule.Ports {
			if port.Port != nil {
				portValue := port.Port.IntValue()
				rule.Ports = append(rule.Ports, portValue)
			}
			if port.Protocol != nil {
				rule.Protocol = string(*port.Protocol)
			}
		}
	}

	// Process from rules
	if len(ingressRule.From) > 0 {
		for _, from := range ingressRule.From {
			c.processNetworkPolicyPeer(ctx, from, rule, namespace)
		}
	} else {
		// Empty from means allow from anywhere
		rule.AllowedCIDRs = []netip.Prefix{
			netip.PrefixFrom(netip.IPv4Unspecified(), 0),
			netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		}
	}

	return rule
}

func (c *controller) buildEgressRule(ctx context.Context, selectedPods []PodInfo, egressRule networkingv1.NetworkPolicyEgressRule, namespace string) *firewall.NetworkPolicyRule {
	if len(selectedPods) == 0 {
		return nil
	}

	rule := &firewall.NetworkPolicyRule{
		Direction: "egress",
		PodIPs:    make([]netip.Addr, 0, len(selectedPods)),
		Action:    "allow",
	}

	// Add pod IPs
	for _, pod := range selectedPods {
		rule.PodIPs = append(rule.PodIPs, pod.IP)
	}

	// Process ports
	if len(egressRule.Ports) > 0 {
		for _, port := range egressRule.Ports {
			if port.Port != nil {
				portValue := port.Port.IntValue()
				rule.Ports = append(rule.Ports, portValue)
			}
			if port.Protocol != nil {
				rule.Protocol = string(*port.Protocol)
			}
		}
	}

	// Process to rules
	if len(egressRule.To) > 0 {
		for _, to := range egressRule.To {
			c.processNetworkPolicyPeer(ctx, to, rule, namespace)
		}
	} else {
		// Empty to means allow to anywhere
		rule.AllowedCIDRs = []netip.Prefix{
			netip.PrefixFrom(netip.IPv4Unspecified(), 0),
			netip.PrefixFrom(netip.IPv6Unspecified(), 0),
		}
	}

	return rule
}

func (c *controller) processNetworkPolicyPeer(ctx context.Context, peer networkingv1.NetworkPolicyPeer, rule *firewall.NetworkPolicyRule, currentNamespace string) {
	// Handle podSelector
	if peer.PodSelector != nil {
		targetNamespace := currentNamespace
		if peer.NamespaceSelector != nil {
			// Both pod and namespace selector
			for nsName, nsLabels := range c.namespaces {
				nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
				if err == nil && nsSelector.Matches(labels.Set(nsLabels)) {
					pods := c.selectPods(ctx, nsName, *peer.PodSelector)
					for _, pod := range pods {
						rule.AllowedIPs = append(rule.AllowedIPs, pod.IP)
					}
				}
			}
		} else {
			// Just pod selector in current namespace
			pods := c.selectPods(ctx, targetNamespace, *peer.PodSelector)
			for _, pod := range pods {
				rule.AllowedIPs = append(rule.AllowedIPs, pod.IP)
			}
		}
	} else if peer.NamespaceSelector != nil {
		// Just namespace selector - allow all pods in matching namespaces
		for nsName, nsLabels := range c.namespaces {
			nsSelector, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
			if err == nil && nsSelector.Matches(labels.Set(nsLabels)) {
				for _, pod := range c.pods {
					if pod.Namespace == nsName {
						rule.AllowedIPs = append(rule.AllowedIPs, pod.IP)
					}
				}
			}
		}
	}

	// Handle ipBlock
	if peer.IPBlock != nil {
		prefix, err := netip.ParsePrefix(peer.IPBlock.CIDR)
		if err == nil {
			rule.AllowedCIDRs = append(rule.AllowedCIDRs, prefix)
		}
	}
}
