package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSetBuildInfo verifies the version and backend reach the build_info metric
// as labels (regression guard against the previously hardcoded version string).
func TestSetBuildInfo(t *testing.T) {
	BuildInfo.Reset()
	SetBuildInfo("v1.2.3", "nftables")

	expected := `
# HELP wigglenet_build_info Build information. Always 1.
# TYPE wigglenet_build_info gauge
wigglenet_build_info{firewall_backend="nftables",version="v1.2.3"} 1
`
	require.NoError(t, testutil.CollectAndCompare(BuildInfo, strings.NewReader(expected), "wigglenet_build_info"))
	assert.Equal(t, 1, testutil.CollectAndCount(BuildInfo))
}
