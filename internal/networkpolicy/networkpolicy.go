package networkpolicy

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/firewall"
	"github.com/tibordp/wigglenet/internal/metrics"
	"github.com/tibordp/wigglenet/internal/util"

	"k8s.io/klog/v2"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	networkinglisters "k8s.io/client-go/listers/networking/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller interface {
	Run(ctx context.Context)
}

// ContainerPort mirrors a relevant subset of v1.ContainerPort for named-port resolution.
type ContainerPort struct {
	Name          string
	ContainerPort int32
	Protocol      string // "TCP", "UDP", "SCTP"
}

type PodInfo struct {
	IP             netip.Addr
	Namespace      string
	Labels         map[string]string
	ContainerPorts []ContainerPort
}

type controller struct {
	policyUpdates chan []firewall.NetworkPolicyRule

	factory      informers.SharedInformerFactory
	netpolLister networkinglisters.NetworkPolicyLister
	podLister    corelisters.PodLister
	nsLister     corelisters.NamespaceLister

	queue workqueue.TypedRateLimitingInterface[string]

	// Current state
	pods       map[netip.Addr]PodInfo       // podIP -> PodInfo
	namespaces map[string]map[string]string // namespace -> labels
}

func NewController(clientset kubernetes.Interface, policyUpdates chan []firewall.NetworkPolicyRule) (Controller, error) {
	factory := informers.NewSharedInformerFactoryWithOptions(clientset, 0, informers.WithTransform(util.StripManagedFields))

	netpols := factory.Networking().V1().NetworkPolicies()
	pods := factory.Core().V1().Pods()
	namespaces := factory.Core().V1().Namespaces()

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	// Every object change in any of the watched resources triggers a full
	// resync, so the handlers collapse onto one queue key per resource type.
	enqueueOn := func(key string) cache.ResourceEventHandlerFuncs {
		return cache.ResourceEventHandlerFuncs{
			AddFunc:    func(interface{}) { queue.Add(key) },
			UpdateFunc: func(interface{}, interface{}) { queue.Add(key) },
			DeleteFunc: func(interface{}) { queue.Add(key) },
		}
	}

	for _, reg := range []struct {
		informer cache.SharedIndexInformer
		key      string
	}{
		{netpols.Informer(), "networkpolicy"},
		{pods.Informer(), "pod"},
		{namespaces.Informer(), "namespace"},
	} {
		if _, err := reg.informer.AddEventHandler(enqueueOn(reg.key)); err != nil {
			return nil, fmt.Errorf("registering %s event handler: %w", reg.key, err)
		}
	}

	return &controller{
		policyUpdates: policyUpdates,
		factory:       factory,
		netpolLister:  netpols.Lister(),
		podLister:     pods.Lister(),
		nsLister:      namespaces.Lister(),
		queue:         queue,
		pods:          make(map[netip.Addr]PodInfo),
		namespaces:    make(map[string]map[string]string),
	}, nil
}

func (c *controller) Run(ctx context.Context) {
	defer runtime.HandleCrash()
	defer c.queue.ShutDown()
	logger := klog.FromContext(ctx)

	logger.Info("starting NetworkPolicy controller")

	c.factory.StartWithContext(ctx)
	if err := c.factory.WaitForCacheSyncWithContext(ctx).AsError(); err != nil {
		runtime.HandleErrorWithContext(ctx, err, "timed out waiting for caches to sync")
		return
	}

	// Initial sync
	if err := c.syncState(ctx); err != nil {
		runtime.HandleErrorWithContext(ctx, err, "initial NetworkPolicy sync failed")
	}

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
	// Refresh the pod and namespace lookup maps from the informer caches.
	if err := c.updatePodsMap(); err != nil {
		return err
	}
	if err := c.updateNamespacesMap(); err != nil {
		return err
	}

	// Generate NetworkPolicy rules
	policyRules, err := c.generatePolicyRules(ctx)
	if err != nil {
		return err
	}

	if config.EnableMetrics {
		ingressCount := 0
		egressCount := 0
		for _, r := range policyRules {
			if r.Direction == "ingress" {
				ingressCount++
			} else {
				egressCount++
			}
		}
		metrics.NetworkPolicyRulesTotal.WithLabelValues("ingress").Set(float64(ingressCount))
		metrics.NetworkPolicyRulesTotal.WithLabelValues("egress").Set(float64(egressCount))
	}

	// Send updated policy rules
	c.policyUpdates <- policyRules

	return nil
}

func (c *controller) updatePodsMap() error {
	podList, err := c.podLister.List(labels.Everything())
	if err != nil {
		return err
	}

	newPods := make(map[netip.Addr]PodInfo)
	for _, pod := range podList {
		if pod.Status.Phase != v1.PodRunning {
			continue
		}

		// Collect container ports for named-port resolution
		var cPorts []ContainerPort
		for _, container := range pod.Spec.Containers {
			for _, cp := range container.Ports {
				proto := "TCP"
				if cp.Protocol != "" {
					proto = string(cp.Protocol)
				}
				cPorts = append(cPorts, ContainerPort{
					Name:          cp.Name,
					ContainerPort: cp.ContainerPort,
					Protocol:      proto,
				})
			}
		}

		// Handle dual-stack: read all pod IPs from status.podIPs
		for _, podIPStatus := range pod.Status.PodIPs {
			if podIPStatus.IP != "" {
				if addr, err := netip.ParseAddr(podIPStatus.IP); err == nil {
					newPods[addr] = PodInfo{
						IP:             addr,
						Namespace:      pod.Namespace,
						Labels:         pod.Labels,
						ContainerPorts: cPorts,
					}
				}
			}
		}

		// Fallback to status.podIP for compatibility
		if pod.Status.PodIP != "" {
			if addr, err := netip.ParseAddr(pod.Status.PodIP); err == nil {
				if _, exists := newPods[addr]; !exists {
					newPods[addr] = PodInfo{
						IP:             addr,
						Namespace:      pod.Namespace,
						Labels:         pod.Labels,
						ContainerPorts: cPorts,
					}
				}
			}
		}
	}

	c.pods = newPods
	return nil
}

func (c *controller) updateNamespacesMap() error {
	nsList, err := c.nsLister.List(labels.Everything())
	if err != nil {
		return err
	}

	newNamespaces := make(map[string]map[string]string)
	for _, ns := range nsList {
		newNamespaces[ns.Name] = ns.Labels
	}

	c.namespaces = newNamespaces
	return nil
}

func (c *controller) generatePolicyRules(ctx context.Context) ([]firewall.NetworkPolicyRule, error) {
	netpols, err := c.netpolLister.List(labels.Everything())
	if err != nil {
		return nil, err
	}

	var rules []firewall.NetworkPolicyRule

	// Track which pods are affected by policies (by direction)
	affectedPodsIngress := make(map[netip.Addr]bool) // podIP -> true
	affectedPodsEgress := make(map[netip.Addr]bool)  // podIP -> true

	for _, netpol := range netpols {
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

	// The rules above are assembled by iterating maps (pods, namespaces, the
	// affected-pod sets), whose order is randomized in Go. Without canonicalizing,
	// the generated slice would differ run-to-run for identical cluster state, so
	// the firewall manager's reflect.DeepEqual change detection would fire on
	// every pod/namespace event and rewrite the entire ruleset. Sort into a
	// stable order so equivalent state compares equal.
	canonicalizeRules(rules)

	return rules, nil
}

// canonicalizeRules sorts a slice of NetworkPolicyRule (and the slices within
// each rule) into a deterministic order, so that identical logical state always
// produces a deep-equal result regardless of map iteration order.
func canonicalizeRules(rules []firewall.NetworkPolicyRule) {
	cmpAddr := func(a, b netip.Addr) int { return a.Compare(b) }

	for i := range rules {
		r := &rules[i]
		slices.SortFunc(r.PodIPs, cmpAddr)
		slices.SortFunc(r.AllowedIPs, cmpAddr)
		util.SortPrefixes(r.AllowedCIDRs)
		slices.SortFunc(r.PortRules, func(a, b firewall.PortRule) int {
			if c := strings.Compare(a.Protocol, b.Protocol); c != 0 {
				return c
			}
			if a.Port != b.Port {
				return a.Port - b.Port
			}
			return a.EndPort - b.EndPort
		})
	}

	slices.SortFunc(rules, func(a, b firewall.NetworkPolicyRule) int {
		return strings.Compare(ruleSortKey(a), ruleSortKey(b))
	})
}

// ruleSortKey builds a stable string key capturing every field of a rule. It
// assumes the rule's inner slices have already been sorted.
func ruleSortKey(r firewall.NetworkPolicyRule) string {
	var sb strings.Builder
	sb.WriteString(r.Direction)
	sb.WriteByte('|')
	sb.WriteString(r.Action)
	sb.WriteByte('|')
	for _, ip := range r.PodIPs {
		sb.WriteString(ip.String())
		sb.WriteByte(',')
	}
	sb.WriteByte('|')
	for _, ip := range r.AllowedIPs {
		sb.WriteString(ip.String())
		sb.WriteByte(',')
	}
	sb.WriteByte('|')
	for _, c := range r.AllowedCIDRs {
		sb.WriteString(c.String())
		sb.WriteByte(',')
	}
	sb.WriteByte('|')
	for _, p := range r.PortRules {
		fmt.Fprintf(&sb, "%s/%d/%d,", p.Protocol, p.Port, p.EndPort)
	}
	return sb.String()
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

// resolveNamedPort looks up a named port against a set of pods' container port
// definitions. Returns the port number, or 0 if unresolvable.
func resolveNamedPort(pods []PodInfo, portName string, protocol string) int {
	for _, pod := range pods {
		for _, cp := range pod.ContainerPorts {
			if cp.Name == portName && cp.Protocol == protocol {
				return int(cp.ContainerPort)
			}
		}
	}
	return 0
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

	for _, pod := range selectedPods {
		rule.PodIPs = append(rule.PodIPs, pod.IP)
	}

	// Process ports — resolve named ports against the selected (target) pods.
	// If the original rule specified ports but none could be resolved,
	// the rule should match nothing (return nil).
	hasNamedPorts := false
	for _, port := range ingressRule.Ports {
		pr := firewall.PortRule{Protocol: "TCP"}
		if port.Protocol != nil {
			pr.Protocol = string(*port.Protocol)
		}
		if port.Port != nil {
			if port.Port.Type == intstr.String {
				hasNamedPorts = true
				pr.Port = resolveNamedPort(selectedPods, port.Port.StrVal, pr.Protocol)
				if pr.Port == 0 {
					continue // unresolvable named port — skip this entry
				}
			} else {
				pr.Port = port.Port.IntValue()
			}
		}
		if port.EndPort != nil {
			pr.EndPort = int(*port.EndPort)
		}
		rule.PortRules = append(rule.PortRules, pr)
	}
	// If all ports were named and none resolved, the rule matches nothing.
	if hasNamedPorts && len(rule.PortRules) == 0 {
		return nil
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

	for _, pod := range selectedPods {
		rule.PodIPs = append(rule.PodIPs, pod.IP)
	}

	// Collect destination pods from peer selectors for named-port resolution.
	var destPods []PodInfo
	for _, to := range egressRule.To {
		if to.PodSelector != nil {
			if to.NamespaceSelector != nil {
				for nsName, nsLabels := range c.namespaces {
					nsSelector, err := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
					if err == nil && nsSelector.Matches(labels.Set(nsLabels)) {
						destPods = append(destPods, c.selectPods(ctx, nsName, *to.PodSelector)...)
					}
				}
			} else {
				destPods = append(destPods, c.selectPods(ctx, namespace, *to.PodSelector)...)
			}
		} else if to.NamespaceSelector != nil {
			for nsName, nsLabels := range c.namespaces {
				nsSelector, err := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
				if err == nil && nsSelector.Matches(labels.Set(nsLabels)) {
					for _, pod := range c.pods {
						if pod.Namespace == nsName {
							destPods = append(destPods, pod)
						}
					}
				}
			}
		}
	}
	// If no specific destination pods (empty to = allow anywhere), resolve
	// named ports against all known pods.
	if len(destPods) == 0 {
		for _, pod := range c.pods {
			destPods = append(destPods, pod)
		}
	}

	// Process ports — resolve named ports against destination pods.
	hasNamedPorts := false
	for _, port := range egressRule.Ports {
		pr := firewall.PortRule{Protocol: "TCP"}
		if port.Protocol != nil {
			pr.Protocol = string(*port.Protocol)
		}
		if port.Port != nil {
			if port.Port.Type == intstr.String {
				hasNamedPorts = true
				pr.Port = resolveNamedPort(destPods, port.Port.StrVal, pr.Protocol)
				if pr.Port == 0 {
					continue
				}
			} else {
				pr.Port = port.Port.IntValue()
			}
		}
		if port.EndPort != nil {
			pr.EndPort = int(*port.EndPort)
		}
		rule.PortRules = append(rule.PortRules, pr)
	}
	if hasNamedPorts && len(rule.PortRules) == 0 {
		return nil
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
			if len(peer.IPBlock.Except) > 0 {
				var excepts []netip.Prefix
				for _, exceptStr := range peer.IPBlock.Except {
					if ep, err := netip.ParsePrefix(exceptStr); err == nil {
						excepts = append(excepts, ep)
					}
				}
				rule.AllowedCIDRs = append(rule.AllowedCIDRs, util.SubtractPrefixes(prefix, excepts)...)
			} else {
				rule.AllowedCIDRs = append(rule.AllowedCIDRs, prefix)
			}
		}
	}
}
