# Wigglenet

Wigglenet is a simple network plugin for Kubernetes. Wigglenet seeks to achieve the following goals in order:

- Simplicity and minimalism
- IPv6 and dual-stack support on par with or better than IPv4-only
- Being a practical network plugin for real-world clusters, both on-prem and cloud-hosted

## Description

Wigglenet uses the standard [`ptp`](https://www.cni.dev/plugins/current/main/ptp/) CNI plugins with [`host-local` IPAM](https://www.cni.dev/plugins/current/ipam/host-local/) to allocate IP addresses to pods based on the node. Wigglenet also establishes an overlay network using [Wireguard](https://www.wireguard.com/). In addition to encapsulation, this also provides hassle-free encryption of node-to-pod, pod-to-node and pod-to-pod traffic.

Wigglenet runs as a daemonset on every node and does the following things:
- Initializes each new node on startup (generates a Wireguard private key) and writes the CNI configuration
- Runs a controller that adjusts the Wireguard peer configuration and routing table on each node as the network topology changes
- Sets up masquerade and filtering iptables rules 

## Installation

To install Wigglenet with the default settings:

```shell
kubectl apply -f https://raw.githubusercontent.com/tibordp/wigglenet/master/deploy/manifest.yaml
```

See the comments in the manifest for configuration options.

## Allocate public IPv6 addreses to pods

Wigglenet expects that each `Node` object have `.spec.PodCIDRs` set, but does not require that they be drawn from a specific contiguous supernet. In most cases, the node CIDRs are allocated automatically by kube-controller-manager (e.g. from the prefixes in `--pod-network-cidr` passed to kubeadm). However, if `--pod-network-cidr` is not set or if `--allocate-node-cidrs false` is passed to kube-controller-manager, the `PodCIDRs` will have to be set on each node either manually or through some other mechanism.

This is specifically relevant as some cloud providers such as DigitalOcean and Hetzner provide a public IPv6 prefix to each server, but they are randomly allocated and do not form a coherent supernet that can be configured in advance (setting ::/0 as `--pod-network-cidr` is not a good idea) 
 
If nodes have their `.spec.PodCIDRs` configured out-of-band or through another plugin, Wigglenet be used to provide public IPv6 addresses to pods. To facilitate this use-case, Wigglenet can set up stateful ingress filtering instead of masquerading to prevent pods being directly exposed to the Internet through their IPv6 addresses (see [example](./deploy/manifest_public_ipv6.yaml))

In the future Wigglenet may automatically configure `.spec.PodCIDRs` for nodes based on configurable criteria (e.g. the IP address on the uplink network interface)

## Firewall only / Native routing

Wigglenet can run in a firewall-only mode by passing `FIREWALL_ONLY=1` environment variable. Running in this mode will not provision a Wireguard tunnel and CNI configuration, but will only filter and masquerade traffic, similar to [ip-masq-agent](https://github.com/kubernetes-sigs/ip-masq-agent). Unlike `ip-masq-agent`, Wigglenet will automatically determine all the pod CIDRs that should not be masqueraded or filtered by watching Nodes allowing for flexible subnetting.

Native routing (`NATIVE_ROUTING=1`) is similar. Run in this mode, Wireguard will place CNI configuration file on all nodes and sync the firewall rules, but will not create the Wireguard overlay and routing rules. This assumes that there is something outside of the cluster that knows how to route packets for pods to the appropriate node.

## Limitations

- Wigglenet does not currently support `NetworkPolicy`

## Acknowledgements

Wigglenet is inspired by [kindnet](https://github.com/kubernetes-sigs/kind/tree/main/images/kindnetd), the default network plugin for [kind](https://kind.sigs.k8s.io/).
