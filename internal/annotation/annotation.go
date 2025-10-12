package annotation

import (
	"encoding/json"
	"net/netip"
)

const (
	PublicKeyAnnotation string = "wigglenet/public-key"
	NodeIpsAnnotation   string = "wigglenet/node-ips"
	PodCidrsAnnotation  string = "wigglenet/pod-cidrs"
)

func UnmarshalPodCidrs(annotationValue string) ([]netip.Prefix, error) {
	var podCidrs []netip.Prefix
	if err := json.Unmarshal([]byte(annotationValue), &podCidrs); err != nil {
		return nil, err
	}
	return podCidrs, nil
}

func MarshalPodCidrs(podCidrs []netip.Prefix) string {
	val, _ := json.Marshal(podCidrs)
	return string(val)
}
