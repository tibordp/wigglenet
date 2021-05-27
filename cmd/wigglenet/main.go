package main

import (
	"flag"

	"github.com/tibordp/wigglenet/internal"
	"k8s.io/klog/v2"
)

var kubeconfig string
var master string

func main() {
	klog.InitFlags(nil)

	flag.StringVar(&kubeconfig, "kubeconfig", "", "absolute path to the kubeconfig file")
	flag.StringVar(&master, "master", "", "master url")
	flag.Parse()

	wigglenet, err := internal.New(master, kubeconfig)
	if err != nil {
		klog.Fatal(err)
	}

	wigglenet.Run()
}
