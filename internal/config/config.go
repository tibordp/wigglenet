package config

import (
	"os"

	"github.com/tibordp/wigglenet/internal/util"
)

var (
	CurrentNodeName string = os.Getenv("NODE_NAME")

	// Wireguard network settings
	WGLinkName         string = util.GetEnvOrDefault("WIGGLENET_IFACE_NAME", "wigglenet")
	WGPort             int    = util.GetEnvOrDefaultInt("WIGGLENET_WG_PORT", 24601)
	PrivateKeyFilename string = util.GetEnvOrDefault("WIGGLENET_PRIVKEY_PATH", "/etc/wigglenet/private.key")

	// CNI settings
	CniConfigPath string = util.GetEnvOrDefault("CNI_CONFIG_PATH", "/etc/cni/net.d/10-wigglenet.conflist")

	// Firewall settings
	MasqueradeIPv4 bool = util.GetEnvOrDefaultBool("MASQUERADE_IPV4", true)
	FilterIPv4     bool = util.GetEnvOrDefaultBool("FILTER_IPV4", false)
	MasqueradeIPv6 bool = util.GetEnvOrDefaultBool("MASQUERADE_IPV6", true)
	FilterIPv6     bool = util.GetEnvOrDefaultBool("FILTER_IPV6", false)

	// Auto detection of node IP
	NodeIPInterface string        = util.GetEnvOrDefault("NODE_IP_INTERFACE", "")
	NodeIPFamily    util.IPFamily = util.IPFamily(util.GetEnvOrDefault("NODE_IP_FAMILY", "dual"))

	// Do not install Wireguard and CNI configuration, instead only install firewall rules
	FirewallOnly  bool = util.GetEnvOrDefaultBool("FIREWALL_ONLY", false)
	NativeRouting bool = util.GetEnvOrDefaultBool("NATIVE_ROUTING", false)
)
