package controller

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/util/retry"

	klog "k8s.io/klog/v2"

	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func setNodeAddressesAnnotation(node *v1.Node) error {
	nodeAddresses, err := util.GetInterfaceIPs(config.NodeIPInterfaces)
	if err != nil {
		return err
	}

	val, _ := json.Marshal(nodeAddresses)
	node.ObjectMeta.Annotations[annotation.NodeIpsAnnotation] = string(val)

	return nil
}

func getPodCidrsForSource(node *v1.Node, source config.PodCIDRSource, ipv6 bool) ([]net.IPNet, error) {
	podsCidrs := make([]net.IPNet, 0)

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
			if _, cidr, err := net.ParseCIDR(scanner.Text()); err == nil && cidr != nil {
				if (cidr.IP.To4() == nil) == ipv6 {
					podsCidrs = append(podsCidrs, *cidr)
				}
			} else {
				klog.Infof("unrecognized '%v' in %v skipping", scanner.Text(), config.PodCidrSourceFilename)
			}
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}
	case config.SourceSpec:
		specPodCidrs := util.GetPodCIDRsFromSpec(node)
		for _, cidr := range specPodCidrs {
			if (cidr.IP.To4() == nil) == ipv6 {
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

func setPodCidrsAnnotation(node *v1.Node) error {
	podCidrs := make([]net.IPNet, 0)
	if cidrs, err := getPodCidrsForSource(node, config.PodCIDRSourceIPv6, true); err != nil {
		return err
	} else {
		podCidrs = append(podCidrs, cidrs...)
	}

	if cidrs, err := getPodCidrsForSource(node, config.PodCIDRSourceIPv4, false); err != nil {
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

		if publicKey != nil {
			node.ObjectMeta.Annotations[annotation.PublicKeyAnnotation] = base64.StdEncoding.EncodeToString(publicKey)
		}

		if err := setNodeAddressesAnnotation(node); err != nil {
			return err
		}

		if err := setPodCidrsAnnotation(node); err != nil {
			return err
		}

		_, err = nodeClient.Update(ctx, node, metav1.UpdateOptions{})
		return err
	})
}
