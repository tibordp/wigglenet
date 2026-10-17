package firewall

import (
	"context"
	"os"

	"github.com/tibordp/wigglenet/internal/config"
	"k8s.io/klog/v2"
)

// Number of consecutive failed syncs after which the node is reported as not ready.
const unreadyThreshold = 3

// readinessTracker maintains config.ReadyFile, which the DaemonSet readiness
// probe checks for. The file is created after the first successful sync and
// removed after unreadyThreshold consecutive failures, so a broken firewall
// stops a rollout instead of going unnoticed.
type readinessTracker struct {
	path     string
	failures int
	ready    bool
}

func newReadinessTracker() readinessTracker {
	return readinessTracker{path: config.ReadyFile}
}

func (r *readinessTracker) record(ctx context.Context, syncErr error) {
	if r.path == "" {
		return
	}
	logger := klog.FromContext(ctx)

	if syncErr == nil {
		r.failures = 0
		if !r.ready {
			if err := os.WriteFile(r.path, nil, 0o644); err != nil {
				logger.Error(err, "failed to create readiness file", "path", r.path)
				return
			}
			r.ready = true
		}
		return
	}

	r.failures++
	if r.ready && r.failures >= unreadyThreshold {
		if err := os.Remove(r.path); err != nil && !os.IsNotExist(err) {
			logger.Error(err, "failed to remove readiness file", "path", r.path)
			return
		}
		r.ready = false
		logger.Info("marking node as not ready after consecutive firewall sync failures", "failures", r.failures)
	}
}
