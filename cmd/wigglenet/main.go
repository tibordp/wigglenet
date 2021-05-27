package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"

	wigglenet "github.com/tibordp/wigglenet/internal"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	defer klog.Flush()

	flag.Parse()

	context, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wigglenet, err := wigglenet.New(context)
	if err != nil {
		klog.Fatal(err)
	}

	wigglenet.Run(context)
	klog.Info("gracefully terminated")
}
