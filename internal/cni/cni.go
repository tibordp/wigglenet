package cni

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"reflect"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	"k8s.io/klog/v2"
)

type CNIConfig struct {
	PodCIDRs []net.IPNet
}

// NetConfList is a CNI chaining configuration
type PtpNetConf struct {
	Name         string          `json:"name,omitempty"`
	Type         string          `json:"type,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	IPAM         IPAMConfig      `json:"ipam,omitempty"`
	DNS          cniTypes.DNS    `json:"dns"`
}

type PortMapNetConf struct {
	Name         string          `json:"name,omitempty"`
	Type         string          `json:"type,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
}

type NetConfList struct {
	CNIVersion string `json:"cniVersion,omitempty"`

	Name         string        `json:"name,omitempty"`
	DisableCheck bool          `json:"disableCheck,omitempty"`
	Plugins      []interface{} `json:"plugins,omitempty"`
}

type IPAMConfig struct {
	Type       string            `json:"type"`
	Routes     []*cniTypes.Route `json:"routes"`
	DataDir    string            `json:"dataDir"`
	ResolvConf string            `json:"resolvConf"`
	Ranges     []RangeSet        `json:"ranges"`
}

type RangeSet []Range

type Range struct {
	RangeStart net.IP         `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   net.IP         `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     cniTypes.IPNet `json:"subnet"`
	Gateway    net.IP         `json:"gateway,omitempty"`
}

type CNIConfigWriter struct {
	lastConfig CNIConfig
}

func (c *CNIConfigWriter) Write(inputs CNIConfig) error {
	if reflect.DeepEqual(inputs, c.lastConfig) {
		return nil
	}

	klog.Infof("applying new CNI configuration: %v", inputs)

	f, err := os.Create(config.CniConfigPath + ".temp")
	if err != nil {
		return err
	}

	if err := writeCNIConfig(f, inputs); err != nil {
		f.Close()
		os.Remove(f.Name())
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(f.Name(), config.CniConfigPath); err != nil {
		return err
	}

	c.lastConfig = inputs
	return nil
}

func writeCNIConfig(w io.Writer, data CNIConfig) error {
	routes := make([]*cniTypes.Route, 0)
	for _, route := range util.GetDefaultRoutes(data.PodCIDRs) {
		routes = append(routes, &cniTypes.Route{
			Dst: route,
		})
	}

	ranges := make([]RangeSet, 0)
	for _, subnet := range data.PodCIDRs {
		ranges = append(ranges, RangeSet{
			Range{
				Subnet: cniTypes.IPNet(subnet),
			},
		})
	}

	cniConfig := NetConfList{
		CNIVersion: "0.3.1",
		Name:       "wigglenet",
		Plugins: []interface{}{
			&PtpNetConf{
				Type: "ptp",
				IPAM: IPAMConfig{
					Type:    "host-local",
					DataDir: "/run/cni-ipam-state",
					Routes:  routes,
					Ranges:  ranges,
				},
			},
			&PortMapNetConf{
				Type: "portmap",
				Capabilities: map[string]bool{
					"portMappings": true,
				},
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cniConfig)
}
