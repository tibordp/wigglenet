# Wigglenet

Wigglenet is a network plugin for Kubernetes geared towards dual-stack clusters. Wigglenet seeks to achieve the following goals in order:

- Simplicity and minimalism
- Support idiosyncratic IPv6 allocation strategies of various cloud providers (preferably without resorting to ULA addresses / NAT)
- Being a viable network plugin for small to medium sized production clusters

Note that the last goal is not achieved yet. Wigglenet should be considered experimental and only used in non-critical clusters for the time being.

## Introduction

Wigglenet uses the standard [`ptp`](https://www.cni.dev/plugins/current/main/ptp/) CNI plugin with [`host-local` IPAM](https://www.cni.dev/plugins/current/ipam/host-local/) to allocate IP addresses to pods based on the node subnets. Wigglenet also establishes an overlay network using [Wireguard](https://www.wireguard.com/). In addition to encapsulation, this also provides hassle-free encryption of pod-to-pod traffic.

Wigglenet runs as a daemonset on every node and does the following things:
- Initializes each new node on startup, sets up the Wireguard interface and writes the CNI configuration
- Runs a controller on each node that adjusts the Wireguard peer configuration, local routing table and iptables rules for filtering and masquerading as nodes come and go

## Installation

To install Wigglenet on a dual-stack cluster with the default settings:

```shell
kubectl apply -f https://raw.githubusercontent.com/tibordp/wigglenet/v0.1.0/deploy/manifest.yaml
```

For customization and other configuration options see notes below and [the manifest](./deploy/manifest.yaml) for full reference.

## Configuration

### Pod network selection

In the default configuration Wigglenet uses the networks specified in `.spec.podCIDRs` (or `.spec.podCIDR`) for each node. These CIDRs are allocated by kube-controller-manager from the cluster-wide pod network specified in the `--pod-network-cidr` in case cluster was provisioned with kubeadm. 

This approach of having a single prefix for the whole cluster works in many cases well for IPv4 clusters, since pod networks almost always consist of RFC1918 addresses. In the case of IPv6, however, use of public addresses is generally preferred even for private networks. This presents a problem, since it can be hard to foresee what IPv6 network will be available to each node at the time of cluster creation.

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
    # This will not actually be a single-stack cluster, as Wireguard
    # will assign an additional IPv6 subnet to each node
    podSubnet: "10.96.0.0/16"

    # Despite what I said above, services should still use an ULA subnet as
    # their IPs are never used as a source address and only have meaning
    # in context of each individual node.
    serviceSubnet: fd00::/112,172.16.0.0/16
```

In the future Wireguard may provide additional modes, such as automatic network discovery based on uplink network interface or other metadata provided by the cloud provider.

### Firewall configuration

Masquerading can be switched on or off per address family by `MASQUERADE_IPV4` and `MASQUERADE_IPV6` environment variables. If Wireguard is set up to hand out public IPv6 addresses to pods, masquerading should be turned off for IPv6.

There are two additional options that control the firewall rules: `FILTER_IPV4` and `FILTER_IPV6`. If set to true, Wireguard will install basic stateful firewall rules for that address family preventing direct connectivity to pods from outside the cluster (egress traffic is not affected and neither are workloads exposed through NodePort and LoadBalancer services).

### Firewall only mode and native routing

Wigglenet can run in a firewall-only mode by passing `FIREWALL_ONLY=1` environment variable. Running in this mode will not provision a Wireguard tunnel and CNI configuration, but will only filter and masquerade traffic, similar to [ip-masq-agent](https://github.com/kubernetes-sigs/ip-masq-agent). Unlike `ip-masq-agent`, Wigglenet will automatically determine all the pod CIDRs that should not be masqueraded or filtered by watching Node objects, allowing for flexible subnetting.

Native routing is configured (`NATIVE_ROUTING_IPV4=1` / `NATIVE_ROUTING_IPV6=1`). Run in this mode, native routing will only be used for the selected address family instead of the Wireguard overlay. This assumes that there is something outside of the cluster that knows how to route packets for pods to the appropriate node, as generally the pod-to-pod traffic will be forwarded along the default route on each node.

## Limitations

- Wigglenet does not currently support `NetworkPolicy`
- Host-to-host traffic does not pass through the Wireguard tunnel, so it is not encrypted. This is not a major issue as services using host networking generally use TLS, but there are some notable exceptions (e.g. the default configuration for Prometheus node-exporter).

## Contributing

Feedback, bug reports and pull requests are most welcome! Build and test with:

```
go mod download
go build ./...
go test ./...
```

See [Makefile](./Makefile) and [example manifests](./testing) for experimenting with Wigglenet locally using kind.


## Acknowledgements

Wigglenet is inspired by [kindnet](https://github.com/kubernetes-sigs/kind/tree/main/images/kindnetd), the default network plugin for [kind](https://kind.sigs.k8s.io/).
