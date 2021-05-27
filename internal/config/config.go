package config

import (
	"os"
	"strconv"
)

type PodCIDRSource string

const (
	SourceNone PodCIDRSource = "none"
	SourceSpec PodCIDRSource = "spec"
	SourceFile PodCIDRSource = "file"
)

type IPFamily string

const (
	IPv4Family      IPFamily = "ipv4"
	IPv6Family      IPFamily = "ipv6"
	DualStackFamily IPFamily = "dual"
)

var (
	CurrentNodeName string = os.Getenv("NODE_NAME")

	// Wireguard network settings
	WGLinkName         string = GetEnvOrDefault("WIGGLENET_IFACE_NAME", "wigglenet")
	WGPort             int    = GetEnvOrDefaultInt("WIGGLENET_WG_PORT", 24601)
	PrivateKeyFilename string = GetEnvOrDefault("WIGGLENET_PRIVKEY_PATH", "/etc/wigglenet/private.key")

	// Which IP family to use for the tunnel (relevant for dual-stack clusters)
	WireguardIPFamily IPFamily = IPFamily(GetEnvOrDefault("WG_IP_FAMILY", "dual"))

	// CNI settings
	CniConfigPath string = GetEnvOrDefault("CNI_CONFIG_PATH", "/etc/cni/net.d/10-wigglenet.conflist")

	// Firewall settings
	MasqueradeIPv4 bool = GetEnvOrDefaultBool("MASQUERADE_IPV4", true)
	FilterIPv4     bool = GetEnvOrDefaultBool("FILTER_IPV4", false)
	MasqueradeIPv6 bool = GetEnvOrDefaultBool("MASQUERADE_IPV6", true)
	FilterIPv6     bool = GetEnvOrDefaultBool("FILTER_IPV6", false)

	// Auto detection of node IP. Take addresses from these comma-separated to be used as node's IP
	// addresses. This option is mainly to work around limitations of kubelet and many cloud controllers
	// that only set a single IP for dual-stack nodes.
	NodeIPInterfaces string = GetEnvOrDefault("NODE_IP_INTERFACES", "")

	// Do not install Wireguard and CNI configuration, instead only install firewall rules
	FirewallOnly bool = GetEnvOrDefaultBool("FIREWALL_ONLY", false)

	// Native routing. Wireguard tunnel will not be used for the specified address families
	NativeRoutingIPv6 bool = GetEnvOrDefaultBool("NATIVE_ROUTING_IPV6", false)
	NativeRoutingIPv4 bool = GetEnvOrDefaultBool("NATIVE_ROUTING_IPV4", false)

	NativeRouting = NativeRoutingIPv4 && NativeRoutingIPv6 // Completely disable Wireguard functionality if both are set

	// Where to take the node's pod CIDRs from per address family
	PodCIDRSourceIPv4 PodCIDRSource = PodCIDRSource(GetEnvOrDefault("POD_CIDR_SOURCE_IPV4", string(SourceSpec)))
	PodCIDRSourceIPv6 PodCIDRSource = PodCIDRSource(GetEnvOrDefault("POD_CIDR_SOURCE_IPV6", string(SourceSpec)))

	// Where to take the pod CIDRs from, if mode is "file"
	PodCidrSourceFilename string = os.Getenv("POD_CIDR_SOURCE_PATH")
)

func GetEnvOrDefault(name string, fallback string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	} else {
		return fallback
	}
}

func GetEnvOrDefaultInt(name string, fallback int) int {
	if val, ok := os.LookupEnv(name); ok {
		if i, err := strconv.Atoi(val); err != nil {
			return fallback
		} else {
			return i
		}
	} else {
		return fallback
	}
}

func GetEnvOrDefaultBool(name string, fallback bool) bool {
	if val, ok := os.LookupEnv(name); ok {
		if i, err := strconv.ParseBool(val); err != nil {
			return fallback
		} else {
			return i
		}
	} else {
		return fallback
	}
}
