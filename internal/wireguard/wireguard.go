package wireguard

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
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

type Manager interface {
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
	Addresses []netip.Addr
	Peers     []Peer
}

func NewConfig(addresses []netip.Addr, peers []Peer) WireguardConfig {
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
		return c.Addresses[i].Compare(c.Addresses[j]) < 0
	})
	sort.Slice(c.Peers, func(i, j int) bool {
		return c.Peers[i].PublicKey.String() < c.Peers[j].PublicKey.String()
	})
}

type Peer struct {
	Endpoint  netip.Addr
	NodeCIDRs []netip.Prefix
	PodCIDRs  []netip.Prefix
	PublicKey wgtypes.Key
}

func (c *wireguardManager) PublicKey() []byte {
	return c.publicKey[:]
}

func getPeerCIDRs(peers []Peer) []netip.Prefix {
	routes := make([]netip.Prefix, 0)
	for _, peer := range peers {
		for _, cidr := range peer.PodCIDRs {
			isIPv6 := cidr.Addr().Is6()
			if (isIPv6 && !config.NativeRoutingIPv6) || (!isIPv6 && !config.NativeRoutingIPv4) {
				routes = append(routes, peer.PodCIDRs...)
			}
		}
	}
	return util.SummarizeCIDRs(routes)
}

func (c *wireguardManager) reconcileRoutes(addresses []netip.Addr, peersCIDRs []netip.Prefix) error {
	// Find all directly attached routes to the wireguard interface
	existingRoutes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{LinkIndex: c.link.Attrs().Index}, netlink.RT_FILTER_OIF)
	if err != nil {
		return err
	}

	redundant := make(map[netip.Prefix]netlink.Route)
	for _, route := range existingRoutes {
		if prefix, ok := util.PrefixFromIPNet(*route.Dst); ok {
			redundant[prefix] = route
		}
	}

	missing := make([]netlink.Route, 0)
	for _, cidr := range peersCIDRs {
		if _, ok := redundant[cidr]; ok {
			delete(redundant, cidr)
		} else {
			netlinkCIDR := util.PrefixToIPNet(cidr)
			missing = append(missing, netlink.Route{
				Dst:       &netlinkCIDR,
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
		cidr := util.SingleHostCIDR(address)
		if _, ok := redundant[cidr]; ok {
			delete(redundant, cidr)
		} else {
			netlinkCIDR := util.PrefixToIPNet(cidr)
			missing = append(missing, netlink.Route{
				Dst:       &netlinkCIDR,
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
		if err := netlink.RouteDel(&v); err != nil {
			return err
		}
	}

	return nil
}

func (c *wireguardManager) reconcileAddresses(addresses []netip.Addr) error {
	existingAddresses, err := netlink.AddrList(c.link, nl.FAMILY_ALL)
	if err != nil {
		return err
	}

	redundant := make(map[netip.Prefix]netlink.Addr)
	for _, addr := range existingAddresses {
		if prefix, ok := util.PrefixFromIPNet(*addr.IPNet); ok {
			redundant[prefix] = addr
		}
	}

	missing := make([]netlink.Addr, 0)
	for _, desiredAddr := range addresses {
		cidr := util.SingleHostCIDR(desiredAddr)
		if _, ok := redundant[cidr]; ok {
			delete(redundant, cidr)
		} else {
			ipNet := util.PrefixToIPNet(cidr)
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
		if err := netlink.AddrDel(c.link, &v); err != nil {
			return err
		}
	}

	return nil
}

func peerNeedsUpdate(existingPeer *wgtypes.PeerConfig, peer *Peer) bool {
	if len(existingPeer.AllowedIPs) != len(peer.NodeCIDRs)+len(peer.PodCIDRs) {
		return true
	}

	for i := range peer.PodCIDRs {
		existingPrefix, ok := util.PrefixFromIPNet(existingPeer.AllowedIPs[i])
		if !ok || existingPrefix != peer.PodCIDRs[i] {
			return true
		}
	}

	for i := range peer.NodeCIDRs {
		existingPrefix, ok := util.PrefixFromIPNet(existingPeer.AllowedIPs[len(peer.PodCIDRs)+i])
		if !ok || existingPrefix != peer.NodeCIDRs[i] {
			return true
		}
	}

	if existingPeer.Endpoint == nil {
		return true
	}

	endpointAddr, _ := netip.AddrFromSlice(existingPeer.Endpoint.IP)
	if endpointAddr.Unmap() != peer.Endpoint || existingPeer.Endpoint.Port != config.WGPort {
		return true
	}

	return false
}

func createPeerChangeset(existingPeers []wgtypes.Peer, desiredPeers []Peer) []wgtypes.PeerConfig {
	changeset := make(map[wgtypes.Key]wgtypes.PeerConfig)
	for _, peer := range existingPeers {
		changeset[peer.PublicKey] = wgtypes.PeerConfig{
			PublicKey:         peer.PublicKey,
			Remove:            true,
			AllowedIPs:        peer.AllowedIPs,
			Endpoint:          peer.Endpoint,
			ReplaceAllowedIPs: true,
		}
	}

	for _, peer := range desiredPeers {
		var peerConfig wgtypes.PeerConfig
		var ok bool
		if peerConfig, ok = changeset[peer.PublicKey]; ok {
			if !peerNeedsUpdate(&peerConfig, &peer) {
				delete(changeset, peer.PublicKey)
				continue
			}
			peerConfig.Remove = false
			peerConfig.UpdateOnly = true
		} else {
			peerConfig = wgtypes.PeerConfig{}
		}

		peerConfig.PublicKey = peer.PublicKey
		peerConfig.Endpoint = &net.UDPAddr{IP: peer.Endpoint.AsSlice(), Port: config.WGPort}
		peerConfig.AllowedIPs = util.PrefixesToIPNets(peer.PodCIDRs)
		peerConfig.AllowedIPs = append(peerConfig.AllowedIPs, util.PrefixesToIPNets(peer.NodeCIDRs)...)

		changeset[peer.PublicKey] = peerConfig
	}

	peerConfigs := make([]wgtypes.PeerConfig, 0)
	for _, v := range changeset {
		if v.Remove {
			klog.Infof("removing peer %v", v.PublicKey.String())
		} else if v.UpdateOnly {
			klog.Infof("updating peer %v", v.PublicKey.String())
		} else {
			klog.Infof("adding peer %v", v.PublicKey.String())
		}
		peerConfigs = append(peerConfigs, v)
	}

	return peerConfigs
}

func (c *wireguardManager) reconcileWireguardPeers(peers []Peer) error {
	device, err := c.wgctrl.Device(c.link.Attrs().Name)
	if err != nil {
		return err
	}

	peerConfigs := createPeerChangeset(device.Peers, peers)

	if len(peerConfigs) > 0 {
		if err := c.wgctrl.ConfigureDevice(device.Name, wgtypes.Config{
			PrivateKey: &c.privateKey,
			ListenPort: &config.WGPort,
			Peers:      peerConfigs,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (c *wireguardManager) ApplyConfiguration(config *WireguardConfig) error {
	if reflect.DeepEqual(config, c.lastAppliedConfig) {
		return nil
	}

	klog.Infof("applying new Wireguard configuration")
	if err := c.reconcileWireguardPeers(config.Peers); err != nil {
		return err
	}

	if err := c.reconcileAddresses(config.Addresses); err != nil {
		return err
	}

	peersCIDRs := getPeerCIDRs(config.Peers)
	if err := c.reconcileRoutes(config.Addresses, peersCIDRs); err != nil {
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

		// Private key should only be readable by root
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

func NewManager() (Manager, error) {
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
