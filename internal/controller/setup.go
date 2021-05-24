package controller

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"

	"github.com/tibordp/wigglenet/internal/annotation"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/util/retry"

	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// SetupNode sets up the node annotations (node IP and Wireguard public key) on first start.
func SetupNode(nodeClient clientv1.NodeInterface, publicKey []byte) error {
	context := context.Background()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := nodeClient.Get(context, config.CurrentNodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		node.ObjectMeta.Annotations[annotation.PublicKeyAnnotation] = base64.StdEncoding.EncodeToString(publicKey)

		// Determine all the node IP addresses
		statusAddresses := util.GetNodeAddresses(node)
		interfaceAddresses, err := util.GetInterfaceIPs(config.NodeIPInterfaces)
		if err != nil {
			return err
		}

		keys := make(map[string]struct{})
		nodeAddresses := make([]net.IP, 0)

		// Remove duplicates
		for _, coll := range [][]net.IP{statusAddresses, interfaceAddresses} {
			for _, entry := range coll {
				if _, value := keys[entry.String()]; !value {
					keys[entry.String()] = struct{}{}
					nodeAddresses = append(nodeAddresses, entry)
				}
			}
		}

		if len(nodeAddresses) == 0 {
			return fmt.Errorf("could not determine node ip")
		}

		val, _ := json.Marshal(nodeAddresses)
		node.ObjectMeta.Annotations[annotation.NodeIpsAnnotation] = string(val)

		_, err = nodeClient.Update(context, node, metav1.UpdateOptions{})
		return err
	})
}
