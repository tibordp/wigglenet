package controller

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/celipam"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/client-go/util/retry"

	klog "k8s.io/klog/v2"

	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func setNodeAddressesAnnotation(ctx context.Context, node *v1.Node) error {
	nodeAddresses, err := util.GetInterfaceIPs(ctx, config.NodeIPInterfaces)
	if err != nil {
		return err
	}

	val, _ := json.Marshal(nodeAddresses)
	node.ObjectMeta.Annotations[annotation.NodeIpsAnnotation] = string(val)

	return nil
}

// podCidrResolver resolves a node's pod CIDRs from the configured per-family
// sources. It memoizes the CEL evaluation so that, when both families use the
// "expression" source, the expression is evaluated only once per node.
type podCidrResolver struct {
	node *v1.Node

	celOnce sync.Once
	celCidr []netip.Prefix
	celErr  error
}

func (r *podCidrResolver) forSource(ctx context.Context, source config.PodCIDRSource, ipv6 bool) ([]netip.Prefix, error) {
	logger := klog.FromContext(ctx)
	podsCidrs := make([]netip.Prefix, 0)

	switch source {
	case config.SourceNone:
		return podsCidrs, nil

	case config.SourceFile:
		file, err := os.Open(config.PodCidrSourceFilename)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if prefix, err := netip.ParsePrefix(scanner.Text()); err == nil {
				if prefix.Addr().Is6() == ipv6 {
					podsCidrs = append(podsCidrs, prefix)
				}
			} else {
				logger.Info("unrecognized CIDR in file, skipping", "cidr", scanner.Text(), "file", config.PodCidrSourceFilename, "error", err)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}
	case config.SourceSpec:
		specPodCidrs := util.GetPodCIDRsFromSpec(ctx, r.node)
		for _, cidr := range specPodCidrs {
			if cidr.Addr().Is6() == ipv6 {
				podsCidrs = append(podsCidrs, cidr)
			}
		}
	case config.SourceExpression:
		celCidrs, err := r.celResult(ctx)
		if err != nil {
			return nil, err
		}
		for _, cidr := range celCidrs {
			if cidr.Addr().Is6() == ipv6 {
				podsCidrs = append(podsCidrs, cidr)
			}
		}
	default:
		return nil, fmt.Errorf("invalid pod CIDR source %v", source)
	}

	// Return an error if we want to have this address family in the cluster but weren't able
	// to find an acceptable CIDR
	if len(podsCidrs) == 0 {
		return nil, fmt.Errorf("could not determine node cidr for ipv6=%v", ipv6)
	}

	return podsCidrs, nil
}

// celResult evaluates the configured CEL pod-CIDR expression once, against this
// node's interface and metadata state, and caches the result.
func (r *podCidrResolver) celResult(ctx context.Context) ([]netip.Prefix, error) {
	r.celOnce.Do(func() {
		r.celCidr, r.celErr = evaluatePodCidrExpression(ctx, r.node)
	})
	return r.celCidr, r.celErr
}

func podCidrExpression() (string, error) {
	if config.PodCidrExpressionPath != "" {
		data, err := os.ReadFile(config.PodCidrExpressionPath)
		if err != nil {
			return "", fmt.Errorf("reading pod CIDR expression from %s: %w", config.PodCidrExpressionPath, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if config.PodCidrExpression != "" {
		return config.PodCidrExpression, nil
	}
	return "", fmt.Errorf("pod CIDR source is %q but neither POD_CIDR_EXPRESSION nor POD_CIDR_EXPRESSION_PATH is set", config.SourceExpression)
}

func evaluatePodCidrExpression(ctx context.Context, node *v1.Node) ([]netip.Prefix, error) {
	logger := klog.FromContext(ctx)

	expression, err := podCidrExpression()
	if err != nil {
		return nil, err
	}

	evaluator, err := celipam.Compile(expression)
	if err != nil {
		return nil, err
	}

	interfaces, err := util.GetInterfacePrefixes(ctx)
	if err != nil {
		return nil, err
	}

	cidrs, err := evaluator.Evaluate(celipam.Inputs{
		Interfaces: interfaces,
		Node: celipam.NodeInfo{
			Name:        node.Name,
			Labels:      node.Labels,
			Annotations: node.Annotations,
		},
	})
	if err != nil {
		// Log the interface prefixes the expression saw to make a failed or
		// empty derivation easier to debug.
		logger.Error(err, "pod CIDR expression evaluation failed", "interfaces", interfaces)
		return nil, err
	}

	logger.Info("derived pod CIDRs from expression", "cidrs", cidrs, "interfaces", interfaces)
	return cidrs, nil
}

func setPodCidrsAnnotation(ctx context.Context, node *v1.Node) error {
	resolver := &podCidrResolver{node: node}

	podCidrs := make([]netip.Prefix, 0)
	if cidrs, err := resolver.forSource(ctx, config.PodCIDRSourceIPv6, true); err != nil {
		return err
	} else {
		podCidrs = append(podCidrs, cidrs...)
	}

	if cidrs, err := resolver.forSource(ctx, config.PodCIDRSourceIPv4, false); err != nil {
		return err
	} else {
		podCidrs = append(podCidrs, cidrs...)
	}

	podCidrs = util.SummarizeCIDRs(podCidrs)
	node.ObjectMeta.Annotations[annotation.PodCidrsAnnotation] = annotation.MarshalPodCidrs(podCidrs)

	return nil
}

// SetupNode sets up the node annotations on each start.
func SetupNode(ctx context.Context, nodeClient clientv1.NodeInterface, publicKey []byte) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := nodeClient.Get(ctx, config.CurrentNodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if node.ObjectMeta.Annotations == nil {
			node.ObjectMeta.Annotations = map[string]string{}
		}

		if publicKey != nil {
			node.ObjectMeta.Annotations[annotation.PublicKeyAnnotation] = base64.StdEncoding.EncodeToString(publicKey)
		}

		if err := setNodeAddressesAnnotation(ctx, node); err != nil {
			return err
		}

		if err := setPodCidrsAnnotation(ctx, node); err != nil {
			return err
		}

		// Patch only the annotations wigglenet owns rather than PUT-ing the whole
		// Node object. This lets the ClusterRole grant `patch` instead of `update`
		// on nodes: `update` lets a token rewrite any field on any node (labels,
		// taints, …), whereas a JSON merge patch here can only set these keys.
		annotations := map[string]string{
			annotation.NodeIpsAnnotation:  node.ObjectMeta.Annotations[annotation.NodeIpsAnnotation],
			annotation.PodCidrsAnnotation: node.ObjectMeta.Annotations[annotation.PodCidrsAnnotation],
		}
		if publicKey != nil {
			annotations[annotation.PublicKeyAnnotation] = node.ObjectMeta.Annotations[annotation.PublicKeyAnnotation]
		}

		patch, err := json.Marshal(map[string]any{
			"metadata": map[string]any{
				"annotations": annotations,
			},
		})
		if err != nil {
			return err
		}

		_, err = nodeClient.Patch(ctx, config.CurrentNodeName, types.MergePatchType, patch, metav1.PatchOptions{})
		return err
	})
}
