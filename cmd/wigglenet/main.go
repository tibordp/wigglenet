package main

import (
	"flag"

	"k8s.io/klog/v2"

	"github.com/tibordp/wigglenet/internal/cni"
	"github.com/tibordp/wigglenet/internal/controller"
	"github.com/tibordp/wigglenet/internal/firewall"
	"github.com/tibordp/wigglenet/internal/wireguard"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var kubeconfig string
var master string

func initializeController() (controller.Controller, chan firewall.FirewallConfig, error) {
	// creates the connection
	config, err := clientcmd.BuildConfigFromFlags(master, kubeconfig)
	if err != nil {
		return nil, nil, err
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, err
	}

	wireguard, err := wireguard.NewWireguardManager()
	if err != nil {
		return nil, nil, err
	}

	if err = controller.SetupNode(clientset.CoreV1().Nodes(), wireguard.PublicKey()); err != nil {
		return nil, nil, err
	}

	cniwriter := cni.CNIConfigWriter{}
	firewallUpdates := make(chan firewall.FirewallConfig, 10)

	return controller.NewController(clientset, wireguard, cniwriter, firewallUpdates), firewallUpdates, nil
}

func main() {
	klog.InitFlags(nil)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()

	controller, firewallUpdates, err := initializeController()
	if err != nil {
		klog.Fatal(err)
	}

	firewallManager := firewall.New(firewallUpdates)

	stop := make(chan struct{})
	defer close(stop)

	go firewallManager.Run(stop)
	go controller.Run(stop)

	// Wait forever
	select {}
}
