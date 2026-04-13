package internal

import (
	"context"
	"net/netip"

	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/controller"
	"github.com/tibordp/wigglenet/internal/firewall"
	"github.com/tibordp/wigglenet/internal/metrics"
	"github.com/tibordp/wigglenet/internal/networkpolicy"
	"github.com/tibordp/wigglenet/internal/wireguard"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type Wigglenet interface {
	Run(ctx context.Context)
}

func New(ctx context.Context) (Wigglenet, error) {
	kubeconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create separate channels for firewall manager
	podCIDRUpdates := make(chan []netip.Prefix)
	policyUpdates := make(chan []firewall.NetworkPolicyRule)
	firewallManager, err := firewall.New(podCIDRUpdates, policyUpdates)
	if err != nil {
		return nil, err
	}

	var ctrl controller.Controller
	var publicKey []byte

	if config.FirewallOnly {
		ctrl = controller.NewController(clientset, nil, nil, podCIDRUpdates)
	} else if config.NativeRouting {
		cniwriter := cni.NewCNIConfigWriter()
		ctrl = controller.NewController(clientset, nil, cniwriter, podCIDRUpdates)
	} else {
		wg, err := wireguard.NewManager(ctx)
		if err != nil {
			return nil, err
		}

		cniwriter := cni.NewCNIConfigWriter()
		ctrl = controller.NewController(clientset, wg, cniwriter, podCIDRUpdates)
		publicKey = wg.PublicKey()

		if config.EnableMetrics {
			metrics.RegisterWireGuardCollector(wg)
		}
	}

	// Create NetworkPolicy controller if enabled
	var netpolController networkpolicy.Controller
	if config.EnableNetworkPolicy {
		netpolController = networkpolicy.NewController(clientset, policyUpdates)
	}

	if config.EnableMetrics {
		metrics.SetBuildInfo("0.5.0", string(config.FirewallBackendMode))
	}

	// Populate the node annotations
	if err = controller.SetupNode(ctx, clientset.CoreV1().Nodes(), publicKey); err != nil {
		return nil, err
	}

	return &wigglenet{
		controller:       ctrl,
		firewallManager:  firewallManager,
		netpolController: netpolController,
	}, nil
}

type wigglenet struct {
	controller       controller.Controller
	firewallManager  firewall.Manager
	netpolController networkpolicy.Controller
}

func (c *wigglenet) Run(ctx context.Context) {
	wg := wait.Group{}

	wg.StartWithContext(ctx, c.firewallManager.Run)
	wg.StartWithContext(ctx, c.controller.Run)

	// Start NetworkPolicy controller if enabled
	if c.netpolController != nil {
		wg.StartWithContext(ctx, c.netpolController.Run)
	}

	// Start metrics server if enabled
	if config.EnableMetrics {
		var tlsCfg *metrics.TLSConfig
		if config.MetricsTLSCertFile != "" {
			tlsCfg = &metrics.TLSConfig{
				CertFile:     config.MetricsTLSCertFile,
				KeyFile:      config.MetricsTLSKeyFile,
				ClientCAFile: config.MetricsTLSClientCA,
			}
		}
		wg.StartWithContext(ctx, func(ctx context.Context) {
			metrics.Run(ctx, config.MetricsBindAddr, tlsCfg)
		})
	}

	wg.Wait()
}
