package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/config"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// TestSetupNodePatchesAnnotations verifies that SetupNode mutates the Node via a
// merge Patch touching only the wigglenet annotations, and never issues a full
// Update. This is what allows the ClusterRole to grant `patch` instead of the
// much broader `update` verb on nodes.
func TestSetupNodePatchesAnnotations(t *testing.T) {
	origV4 := config.PodCIDRSourceIPv4
	origV6 := config.PodCIDRSourceIPv6
	origIfaces := config.NodeIPInterfaces
	origNode := config.CurrentNodeName
	defer func() {
		config.PodCIDRSourceIPv4 = origV4
		config.PodCIDRSourceIPv6 = origV6
		config.NodeIPInterfaces = origIfaces
		config.CurrentNodeName = origNode
	}()

	// "none" sources and no interfaces avoid any dependency on host network state.
	config.PodCIDRSourceIPv4 = config.SourceNone
	config.PodCIDRSourceIPv6 = config.SourceNone
	config.NodeIPInterfaces = ""
	config.CurrentNodeName = "test-node"

	client := fake.NewSimpleClientset(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test-node",
			Annotations: map[string]string{"unrelated/keep": "keep-me"},
		},
	})

	publicKey := make([]byte, 32)
	for i := range publicKey {
		publicKey[i] = byte(i)
	}

	err := SetupNode(context.Background(), client.CoreV1().Nodes(), publicKey)
	require.NoError(t, err)

	sawPatch := false
	for _, a := range client.Actions() {
		if a.GetResource().Resource != "nodes" {
			continue
		}
		if a.GetVerb() == "update" {
			t.Fatalf("SetupNode issued an update on nodes; expected patch only")
		}
		if a.GetVerb() == "patch" {
			sawPatch = true
			payload := map[string]any{}
			require.NoError(t, json.Unmarshal(a.(k8stesting.PatchAction).GetPatch(), &payload))
			ann := payload["metadata"].(map[string]any)["annotations"].(map[string]any)
			assert.Contains(t, ann, annotation.PublicKeyAnnotation)
			assert.Contains(t, ann, annotation.NodeIpsAnnotation)
			assert.Contains(t, ann, annotation.PodCidrsAnnotation)
			assert.NotContains(t, ann, "unrelated/keep", "patch must not touch unrelated annotations")
		}
	}
	assert.True(t, sawPatch, "expected a patch action on nodes")

	// The merge patch should have added the wigglenet annotations while leaving
	// the pre-existing unrelated annotation intact.
	node, err := client.CoreV1().Nodes().Get(context.Background(), "test-node", metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, "keep-me", node.Annotations["unrelated/keep"])
	assert.NotEmpty(t, node.Annotations[annotation.PublicKeyAnnotation])
	assert.Contains(t, node.Annotations, annotation.PodCidrsAnnotation)
}

// TestSetupNodeOmitsPublicKeyWhenNil checks that firewall-only / native-routing
// modes (which pass a nil public key) do not write or clear the public-key
// annotation.
func TestSetupNodeOmitsPublicKeyWhenNil(t *testing.T) {
	origV4 := config.PodCIDRSourceIPv4
	origV6 := config.PodCIDRSourceIPv6
	origIfaces := config.NodeIPInterfaces
	origNode := config.CurrentNodeName
	defer func() {
		config.PodCIDRSourceIPv4 = origV4
		config.PodCIDRSourceIPv6 = origV6
		config.NodeIPInterfaces = origIfaces
		config.CurrentNodeName = origNode
	}()

	config.PodCIDRSourceIPv4 = config.SourceNone
	config.PodCIDRSourceIPv6 = config.SourceNone
	config.NodeIPInterfaces = ""
	config.CurrentNodeName = "test-node"

	client := fake.NewSimpleClientset(&v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "test-node"},
	})

	require.NoError(t, SetupNode(context.Background(), client.CoreV1().Nodes(), nil))

	for _, a := range client.Actions() {
		if a.GetResource().Resource == "nodes" && a.GetVerb() == "patch" {
			payload := map[string]any{}
			require.NoError(t, json.Unmarshal(a.(k8stesting.PatchAction).GetPatch(), &payload))
			ann := payload["metadata"].(map[string]any)["annotations"].(map[string]any)
			assert.NotContains(t, ann, annotation.PublicKeyAnnotation,
				"public-key annotation must not be patched when no key is provided")
		}
	}
}
