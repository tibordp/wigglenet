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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Create logger and add to context
	logger := klog.NewKlogr()
	ctx = klog.NewContext(ctx, logger)

	wigglenet, err := wigglenet.New(ctx)
	if err != nil {
		klog.Fatal(err)
	}

	wigglenet.Run(ctx)
	logger.Info("gracefully terminated")
}
