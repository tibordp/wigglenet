package wireguard

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sort"

	"k8s.io/klog/v2"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/tibordp/wigglenet/internal/config"
	"github.com/tibordp/wigglenet/internal/util"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type wireguardLink struct {
	netlink.LinkAttrs
}

func (wg *wireguardLink) Attrs() *netlink.LinkAttrs {
	return &wg.LinkAttrs
}

func (wg *wireguardLink) Type() string {
	return "wireguard"
}

type WireguardManager interface {
	ApplyConfiguration(config *WireguardConfig) error
	PublicKey() []byte
}

type wireguardManager struct {
	link              netlink.Link
	wgctrl            wgctrl.Client
	privateKey        wgtypes.Key
	publicKey         wgtypes.Key
	lastAppliedConfig *WireguardConfig
}

type WireguardConfig struct {
	Addresses []net.IP
	Peers     []Peer
}

func NewConfig(addresses []net.IP, peers []Peer) WireguardConfig {
	config := WireguardConfig{
		Addresses: addresses,
		Peers:     peers,
	}
	config.canonicalize()
	return config
}

func (c *WireguardConfig) canonicalize() {
	// Sort the peers so that the slice of peers will not change
	// under deep comparison.
	sort.Slice(c.Addresses, func(i, j int) bool {
		return bytes.Compare(c.Addresses[i], c.Addresses[j]) < 0
	})
	sort.Slice(c.Peers, func(i, j int) bool {
		return bytes.Compare(c.Peers[i].PublicKey, c.Peers[j].PublicKey) < 0
	})
}

type Peer struct {
	Endpoint  net.IP
	PodCIDRs  []net.IPNet
	PublicKey []byte
}

func (c *wireguardManager) PublicKey() []byte {
	return c.publicKey[:]
}

func getPeerSubnets(peers []Peer) []net.IPNet {
	routes := make([]net.IPNet, 0)
	for _, peer := range peers {
		routes = append(routes, peer.PodCIDRs...)
	}
	return util.SummarizeSubnets(routes)
}

func (c *wireguardManager) reconcileRoutes(addresses []net.IP, peersSubnets []net.IPNet) error {
	// Find all directly attached routes to the wireguard interface
	existingRoutes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{LinkIndex: c.link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}

	redundant := make(map[string]netlink.Route)
	for _, route := range existingRoutes {
		redundant[route.Dst.String()] = route
	}

	missing := make([]netlink.Route, 0)
	for _, cidr := range peersSubnets {
		if _, ok := redundant[cidr.String()]; ok {
			delete(redundant, cidr.String())
		} else {
			cidr := cidr
			missing = append(missing, netlink.Route{
				Dst:       &cidr,
				LinkIndex: c.link.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
			})
		}
	}

	// We need to add a host-scoped route for the local address too,
	// otherwise we will not be able to use the local IPv6 address as a source IP
	// until a veth is attached. This is weird and for IPv4 it's not needed,
	// but the ptp plugin does it too, so I guess it's necessary.
	for _, address := range addresses {
		cidr := util.SingleHostSubnet(address)
		if _, ok := redundant[cidr.String()]; ok {
			delete(redundant, cidr.String())
		} else {
			cidr := cidr
			missing = append(missing, netlink.Route{
				Dst:       &cidr,
				LinkIndex: c.link.Attrs().Index,
				Scope:     netlink.SCOPE_HOST,
			})
		}
	}

	for _, v := range missing {
		klog.Infof("adding route %v", v)
		if err := netlink.RouteAdd(&v); err != nil {
			return err
		}
	}

	for _, v := range redundant {
		klog.Infof("removing route %v", v)
		if netlink.RouteDel(&v); err != nil {
			return err
		}
	}

	return nil
}

func (c *wireguardManager) reconcileAddresses(addresses []net.IP) error {
	existingAddresses, err := netlink.AddrList(c.link, nl.FAMILY_ALL)
	if err != nil {
		return err
	}

	redundant := make(map[string]netlink.Addr)
	for _, addr := range existingAddresses {
		redundant[addr.IPNet.String()] = addr
	}

	missing := make([]netlink.Addr, 0)
	for _, desiredAddr := range addresses {
		desiredAddr := desiredAddr
		ipNet := util.SingleHostSubnet(desiredAddr)
		if _, ok := redundant[ipNet.String()]; ok {
			delete(redundant, ipNet.String())
		} else {
			missing = append(missing, netlink.Addr{
				IPNet: &ipNet,
			})
		}
	}

	for _, v := range missing {
		klog.Infof("adding address %v", v)
		if err := netlink.AddrAdd(c.link, &v); err != nil {
			return err
		}
	}

	for _, v := range redundant {
		klog.Infof("removing address %v", v)
		if netlink.AddrDel(c.link, &v); err != nil {
			return err
		}
	}

	return nil
}

func (c *wireguardManager) applyPeerConfiguration(peers []Peer) error {
	peerConfigs := make([]wgtypes.PeerConfig, len(peers))
	for i, v := range peers {
		peerConfigs[i].AllowedIPs = v.PodCIDRs
		peerConfigs[i].Endpoint = &net.UDPAddr{IP: v.Endpoint, Port: config.WGPort}
		key, err := wgtypes.NewKey(v.PublicKey)
		if err != nil {
			return err
		}
		peerConfigs[i].PublicKey = key
	}

	if err := c.wgctrl.ConfigureDevice(config.WGLinkName, wgtypes.Config{
		PrivateKey:   &c.privateKey,
		ListenPort:   &config.WGPort,
		ReplacePeers: true,
		Peers:        peerConfigs,
	}); err != nil {
		return err
	}

	return nil
}

func (c *wireguardManager) ApplyConfiguration(config *WireguardConfig) error {
	if reflect.DeepEqual(config, c.lastAppliedConfig) {
		return nil
	}

	klog.Infof("applying new Wireguard configuration")

	if err := c.applyPeerConfiguration(config.Peers); err != nil {
		return err
	}

	if err := c.reconcileAddresses(config.Addresses); err != nil {
		return err
	}

	peersSubnets := getPeerSubnets(config.Peers)
	if err := c.reconcileRoutes(config.Addresses, peersSubnets); err != nil {
		return err
	}

	c.lastAppliedConfig = config
	return nil
}

func ensureWgLink() (netlink.Link, error) {
	link, err := netlink.LinkByName(config.WGLinkName)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		klog.Infof("device %q does not exist, creating it", config.WGLinkName)
		newLink := wireguardLink{LinkAttrs: netlink.LinkAttrs{Name: config.WGLinkName}}
		if err := netlink.LinkAdd(&newLink); err != nil {
			return nil, err
		}
		link, _ = netlink.LinkByName(config.WGLinkName)
	} else if err != nil {
		return nil, err
	} else if link.Type() != "wireguard" {
		return nil, fmt.Errorf("interface %q is not of wireguard type", config.WGLinkName)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, err
	}

	return link, nil
}

func ensurePrivateKey() (*wgtypes.Key, error) {
	privateKey := wgtypes.Key{}

	file, err := os.Open(config.PrivateKeyFilename)
	if os.IsNotExist(err) {
		klog.Infof("wireguard private key not found, generating a new one")
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		file, err = os.OpenFile(config.PrivateKeyFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return nil, err
		}
		defer file.Close()

		encoder := base64.NewEncoder(base64.StdEncoding, file)

		if _, err := encoder.Write(privateKey[:]); err != nil {
			return nil, err
		}
		if err := encoder.Close(); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		defer file.Close()

		decoder := base64.NewDecoder(base64.StdEncoding, file)

		if len, err := io.ReadAtLeast(decoder, privateKey[:], wgtypes.KeyLen); err != nil {
			return nil, err
		} else if len != wgtypes.KeyLen {
			return nil, fmt.Errorf("key of invalid length %d", len)
		}
	}

	return &privateKey, nil
}

func NewWireguardManager() (WireguardManager, error) {
	privateKey, err := ensurePrivateKey()
	if err != nil {
		return nil, err
	}

	client, err := wgctrl.New()
	if err != nil {
		return nil, err
	}

	link, err := ensureWgLink()
	if err != nil {
		return nil, err
	}

	controller := wireguardManager{
		wgctrl:     *client,
		privateKey: *privateKey,
		link:       link,
		publicKey:  privateKey.PublicKey(),
	}

	return &controller, nil
}
