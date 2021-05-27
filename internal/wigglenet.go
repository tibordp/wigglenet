package internal

import (
	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/controller"
	"github.com/tibordp/wigglenet/internal/firewall"
	"github.com/tibordp/wigglenet/internal/wireguard"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Wigglenet interface {
	Run()
}

func New(master, kubeconfig string) (Wigglenet, error) {
	// creates the connection
	kubeconf, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubeconf)
	if err != nil {
		return nil, err
	}

	firewallUpdates := make(chan firewall.FirewallConfig)
	firewallManager := firewall.New(firewallUpdates)

	var ctrl controller.Controller
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

		if err = controller.SetupNode(clientset.CoreV1().Nodes(), wireguard.PublicKey()); err != nil {
			return nil, err
		}

		cniwriter := cni.NewCNIConfigWriter()
		ctrl = controller.NewController(clientset, wireguard, cniwriter, firewallUpdates)
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

func (c *wigglenet) Run() {
	stop := make(chan struct{})
	defer close(stop)

	go c.firewallManager.Run(stop)
	go c.controller.Run(stop)

	// Wait forever
	select {}
}
