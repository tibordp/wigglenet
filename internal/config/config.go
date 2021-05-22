package config

import (
	"os"

	"github.com/tibordp/wigglenet/internal/util"
)

var CurrentNodeName string = os.Getenv("NODE_NAME")

// Wireguard network settings
var WGLinkName string = util.GetEnvOrDefault("PSYLLIUM_IFACE_NAME", "wigglenet")
var WGPort int = util.GetEnvOrDefaultInt("PSYLLIUM_WG_PORT", 24601)
var PrivateKeyFilename string = util.GetEnvOrDefault("PSYLLIUM_PRIVKEY_PATH", "/etc/wigglenet/private.key")

// CNI settings
var CniConfigPath string = util.GetEnvOrDefault("CNI_CONFIG_PATH", "/etc/cni/net.d/10-wigglenet.conflist")

// Firewall settings
var MasqueradeIPv4 bool = util.GetEnvOrDefaultBool("MASQUERADE_IPV4", true)
var FilterIPv4 bool = util.GetEnvOrDefaultBool("FILTER_IPV4", false)
var MasqueradeIPv6 bool = util.GetEnvOrDefaultBool("MASQUERADE_IPV6", true)
var FilterIPv6 bool = util.GetEnvOrDefaultBool("FILTER_IPV6", false)

// Auto detection of node IP
var NodeIPInterface string = util.GetEnvOrDefault("NODE_IP_INTERFACE", "")
var NodeIPFamily util.IPFamily = util.IPFamily(util.GetEnvOrDefault("NODE_IP_FAMILY", "dual"))
