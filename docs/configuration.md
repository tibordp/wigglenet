# Configuration

## Pod network selection

In the default configuration Wigglenet uses the networks specified in `.spec.podCIDRs` (or `.spec.podCIDR`) for each node. These CIDRs are allocated by kube-controller-manager from the cluster-wide pod network specified in the `--pod-network-cidr` in case cluster was provisioned with kubeadm. 

This approach of having a single prefix for the whole cluster works in many cases well for IPv4 clusters, since pod networks almost always consist of RFC1918 addresses. In the case of IPv6, however, use of public addresses is generally preferred even for private networks. This [presents a problem](https://github.com/kubernetes/kubernetes/issues/57130), since it can be hard to foresee what IPv6 network will be available to each node at the time of cluster creation.

AWS provides a /56 network for each VPC, which can be used as the basis for `--pod-network-cidr` but some cloud providers such as Hetzner and Digital Ocean provide a routable IPv6 network to each instance which is dynamically assigned at instance creation and cannot be customized, which precludes use of `--pod-network-cidr` other than ::/0 (which wouldn't work anyway).

Wigglenet does not rely on a single contiguous pod network and it supports different ways of selecting the source per address family. This is controlled by `POD_CIDR_SOURCE_IPV4` and `POD_CIDR_SOURCE_IPV6` environment variables, which can take the following values:

- `none` - Wigglenet will not assign pods addresses of this family
- `spec` - use the relevant networks from `.spec.podCIDR` (default for both IPv4 and IPv6)
- `file` - read the prefixes from a file specified by `POD_CIDR_SOURCE_PATH` environment variable. File format is one network in CIDR format per line.

A use case for `file` mode is to have a [cloud-init](https://cloudinit.readthedocs.io/en/latest/) script determine the instance's routed IPv6 prefix and write it to a predetermined file on the host filesystem. Since the mode is independently selectable for each address family, this allows for additional flexibility for dynamic clusters where nodes are constantly joining and leaving.

kube-controller-manager can be used to automatically assign RFC1918 IPv4 node subnets and IPv6 ones can be determined by the method above, e.g.:

```
kind: ClusterConfiguration
apiVersion: kubeadm.k8s.io/v1beta2
networking:
    # This will not actually be a single-stack cluster, as Wigglenet
    # will assign an additional IPv6 subnet to each node
    podSubnet: "10.96.0.0/16"

    # Despite what I said above, services should still use an ULA subnet as
    # their IPs are never used as a source address and only have meaning
    # in context of each individual node.
    serviceSubnet: fd00::/112,172.16.0.0/16
```

In the future Wireguard may provide additional modes, such as automatic network discovery based on uplink network interface or other metadata provided by the cloud provider.

## Firewall configuration

Masquerading can be switched on or off per address family by `MASQUERADE_IPV4` and `MASQUERADE_IPV6` environment variables. If Wireguard is set up to hand out public IPv6 addresses to pods, masquerading should be turned off for IPv6.

There are two additional options that control the firewall rules: `FILTER_IPV4` and `FILTER_IPV6`. If set to true, Wireguard will install basic stateful firewall rules for that address family preventing direct connectivity to pods from outside the cluster (egress traffic is not affected and neither are workloads exposed through NodePort and LoadBalancer services).

## Firewall only mode and native routing

Wigglenet can run in a firewall-only mode by passing `FIREWALL_ONLY=1` environment variable. Running in this mode will not provision a Wireguard tunnel and CNI configuration, but will only filter and masquerade traffic, similar to [ip-masq-agent](https://github.com/kubernetes-sigs/ip-masq-agent). Unlike `ip-masq-agent`, Wigglenet will automatically determine all the pod CIDRs that should not be masqueraded or filtered by watching Node objects, allowing for flexible subnetting.

Native routing is configured (`NATIVE_ROUTING_IPV4=1` / `NATIVE_ROUTING_IPV6=1`). Run in this mode, native routing will only be used for the selected address family instead of the Wireguard overlay. This assumes that there is something outside of the cluster that knows how to route packets for pods to the appropriate node, as generally the pod-to-pod traffic will be forwarded along the default route on each node.

## Node address selection

Wigglenet needs to be aware of the node's host address(es) in order to know where to terminate the Wireguard tunnel. In addition, node addresses need to be set as an allowed source IP in order to allow communication between the host and a pod running on another node. 

By default, Wigglenet takes all the `ExternalIP` and `InternalIP` entries from the Node object and then uses the first one as the tunnel endpoint. Some cloud providers may not populate the fields correctly (e.g. only put IPv4 address there, even though the cluster is dual-stack). To work around this, Wigglenet can be configured to additionaly take the node addresses from the network interfaces. The `NODE_IP_INTERFACES` environment variable takes a comma-separated list of interfaces to consider as sources of node addresses. Only global unicast addresses will be considered (this includes RFC1918 and ULA addresses, but excludes link-local and multicast addresses).

To force the Wireguard tunnel to use an address of a particular family as the endpoint, pass `WG_IP_FAMILY={ipv4,ipv6,dualstack}` (`dualstack` is the default).
