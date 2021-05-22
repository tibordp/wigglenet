# Wigglenet

Wigglenet is a simple network plugin for Kubernetes. Wigglenet seeks to achieve the following goals:

- IPv6 and dual-stack not being a mere afterthought
- Simplicity and minimalism
- Being a practical network plugin for real-world clusters

## Description

Wigglenet uses the standard [`ptp`](https://www.cni.dev/plugins/current/main/ptp/) CNI plugins with [`host-local` IPAM](https://www.cni.dev/plugins/current/ipam/host-local/) to allocate IP addresses to pods based on the node. Wigglenet also establishes an overlay network using [Wireguard](https://www.wireguard.com/). In addition to encapsulation, this also provides automatic encryption of node-to-pod, pod-to-node and pod-to-pod traffic.

Wigglenet runs as a daemonset on every node and does the following things:
- Initializes each new node on startup (generates a Wireguard private key) and writes the CNI configuration
- Runs a controller that adjusts the Wireguard peer configuration and routing table on each node as the network topology changes
- Sets up masquerade and filtering iptables rules 

## Pods using public IPv6 addreses

Wigglenet expects that each node have `.spec.PodCIDRs` set, but does not require that they be drawn from a specific contiguous supernet. In most cases, the node CIDRs are allocated automatically by kube-controller-manager (e.g. from the networks in `--pod-network-cidr` passed to kubeadm). However, if `--pod-network-cidr` is not set or if `--allocate-node-cidrs false` is passed to kube-controller-manager, the `PodCIDRs` will have to be set on each node either manually or through some other mechanism.

This is specifically relevant as some cloud providers such as DigitalOcean and Hetzner provide a public IPv6 prefix to each server and Wigglenet can be used to provide public IPv6 addresses to pods. To facilitate this use-case, Wigglenet can optionally set up ingress filtering to prevent pods being directly exposed to the Internet through their IPv6 addresses (see [example](./deploy/manifest_no_masq_ipv6.yaml))

## Installation

To install Wigglenet with the default settings (masquerade all outgoing IPv4 and IPv6 traffic)

```shell
kubectl apply -f https://raw.githubusercontent.com/tibordp/wigglenet/master/deploy/manifest.yaml
```

## Limitations

- Wigglenet does not currently support `NetworkPolicy`

## Acknowledgements

Wigglenet is loosely based on and borrows some code from [kindnet](https://github.com/aojea/kindnet/blob/master/cmd/kindnetd/cni.go), the default network plugin for [kind](https://kind.sigs.k8s.io/).
