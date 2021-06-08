package internal

import (
	"context"

	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/controller"
	"github.com/tibordp/wigglenet/internal/firewall"
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

	firewallUpdates := make(chan firewall.FirewallConfig)
	firewallManager := firewall.New(firewallUpdates)

	var ctrl controller.Controller
	var publicKey []byte

	if config.FirewallOnly {
		ctrl = controller.NewController(clientset, nil, nil, firewallUpdates)
	} else if config.NativeRouting {
		cniwriter := cni.NewCNIConfigWriter()
		ctrl = controller.NewController(clientset, nil, cniwriter, firewallUpdates)
	} else {
		wireguard, err := wireguard.NewManager()
		if err != nil {
			return nil, err
		}

		cniwriter := cni.NewCNIConfigWriter()
		ctrl = controller.NewController(clientset, wireguard, cniwriter, firewallUpdates)
		publicKey = wireguard.PublicKey()
	}

	// Populate the node annotations
	if err = controller.SetupNode(ctx, clientset.CoreV1().Nodes(), publicKey); err != nil {
		return nil, err
	}

	return &wigglenet{
		controller:      ctrl,
		firewallManager: firewallManager,
	}, nil
}

type wigglenet struct {
	controller      controller.Controller
	firewallManager firewall.Manager
}

func (c *wigglenet) Run(ctx context.Context) {
	wg := wait.Group{}

	wg.StartWithContext(ctx, c.firewallManager.Run)
	wg.StartWithContext(ctx, c.controller.Run)

	wg.Wait()
}
