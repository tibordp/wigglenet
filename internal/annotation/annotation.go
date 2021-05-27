package annotation

import (
	"encoding/json"
	"net"
)

const (
	PublicKeyAnnotation string = "wigglenet/public-key"
	NodeIpsAnnotation   string = "wigglenet/node-ips"
	PodCidrsAnnotation  string = "wigglenet/pod-cidrs"
)

type jsonableCIDR net.IPNet

func (c *jsonableCIDR) MarshalJSON() ([]byte, error) {
	net := net.IPNet(*c)
	asString := net.String()
	return json.Marshal(&asString)
}

func (c *jsonableCIDR) UnmarshalJSON(data []byte) error {
	var asString string
	if err := json.Unmarshal(data, &asString); err != nil {
		return err
	}
	if _, cidr, err := net.ParseCIDR(asString); err != nil {
		return err
	} else {
		*c = jsonableCIDR(*cidr)
		return nil
	}
}

func UnmarshalPodCidrs(anotationValue string) ([]net.IPNet, error) {
	var jsonablePodCidrs []jsonableCIDR
	if err := json.Unmarshal([]byte(anotationValue), &jsonablePodCidrs); err != nil {
		return nil, err
	}

	podCidrs := make([]net.IPNet, len(jsonablePodCidrs))
	for i, podCidr := range jsonablePodCidrs {
		podCidrs[i] = net.IPNet(podCidr)
	}

	return podCidrs, nil
}

func MarshalPodCidrs(podCidrs []net.IPNet) string {
	jsonablePodCidrs := make([]jsonableCIDR, len(podCidrs))
	for i, podCidr := range podCidrs {
		jsonablePodCidrs[i] = jsonableCIDR(podCidr)
	}

	val, _ := json.Marshal(jsonablePodCidrs)
	return string(val)
}
