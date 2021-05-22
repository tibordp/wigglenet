package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"

	"github.com/tibordp/wigglenet/internal/annotations"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/util/retry"

	clientv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

func SetupNode(nodeClient clientv1.NodeInterface, publicKey []byte) error {
	context := context.Background()
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		node, err := nodeClient.Get(context, config.CurrentNodeName, metav1.GetOptions{})
		if err != nil {
			return err
		}

		node.ObjectMeta.Annotations[annotations.PublicKeyAnnotation] = base64.StdEncoding.EncodeToString(publicKey)

		var nodeAddress net.IP
		if config.NodeIPInterface == "" {
			nodeAddress = util.GetNodeAddress(node)
		} else {
			nodeAddress, err = util.GetInterfaceIP(config.NodeIPFamily, config.NodeIPInterface)
			if err != nil {
				return err
			}
		}
		if nodeAddress == nil {
			return fmt.Errorf("could not determine node ip")
		}

		node.ObjectMeta.Annotations[annotations.NodeIpAnnotation] = nodeAddress.String()

		_, err = nodeClient.Update(context, node, metav1.UpdateOptions{})
		return err
	})
}
