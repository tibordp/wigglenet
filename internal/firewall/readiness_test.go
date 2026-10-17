package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadinessTracker(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ready")
	r := readinessTracker{path: path}
	syncErr := errors.New("sync failed")

	assertReady := func(expected bool) {
		t.Helper()
		_, err := os.Stat(path)
		assert.Equal(t, expected, err == nil)
	}

	// Not ready until the first successful sync.
	r.record(ctx, syncErr)
	assertReady(false)
	r.record(ctx, nil)
	assertReady(true)

	// Tolerates transient failures.
	for range unreadyThreshold - 1 {
		r.record(ctx, syncErr)
	}
	assertReady(true)
	r.record(ctx, nil)
	assertReady(true)

	// Becomes unready after consecutive failures and recovers on success.
	for range unreadyThreshold {
		r.record(ctx, syncErr)
	}
	assertReady(false)
	r.record(ctx, nil)
	assertReady(true)
}

func TestReadinessTrackerDisabled(t *testing.T) {
	r := readinessTracker{}
	r.record(context.Background(), nil)
	assert.False(t, r.ready)
}
