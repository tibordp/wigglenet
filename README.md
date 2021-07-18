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

Wigglenet explicitely supports and encourages allocation of public IPv6 addresses to pods and offers a variety of pod network selection methods. See [Pod network selection](./docs/configuration.md#pod-network-selection) for details.

## Installation

To install Wigglenet on a dual-stack cluster with the default settings:

```shell
kubectl apply -f https://raw.githubusercontent.com/tibordp/wigglenet/v0.2.2/deploy/manifest.yaml
```

The default configuration should work out of the box for a cluster created with kubeadm using [the official dual-stack tutorial](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/dual-stack-support/). It will enable masquerading for both IPv6 and IPv4 addresses. 

Use the following manifest if the cluster is single-stack (IPv6 only):

```shell
kubectl apply -f https://raw.githubusercontent.com/tibordp/wigglenet/v0.2.2/deploy/ipv6_only.yaml
```

## Configuration

For configuration options see [the docs](./docs/configuration.md)

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

See [Makefile](./Makefile) and [example manifests](./testing) for experimenting with Wigglenet locally using [kind](https://kind.sigs.k8s.io/). For example:

```bash
# Create a dual-stuck kind cluster with default settings
make kind-default

# Build Docker image and load it to all the nodes
make image

# Install Wigglenet
make deploy
```

## Acknowledgements

Wigglenet is inspired by [kindnet](https://github.com/kubernetes-sigs/kind/tree/main/images/kindnetd), kind's default network plugin.
