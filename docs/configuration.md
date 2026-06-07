# Configuration

## Pod network selection

In the default configuration Wigglenet uses the networks specified in `.spec.podCIDRs` (or `.spec.podCIDR`) for each node. These CIDRs are allocated by kube-controller-manager from the cluster-wide pod network specified in the `--pod-network-cidr` in case cluster was provisioned with kubeadm. 

This approach of having a single prefix for the whole cluster works in many cases well for IPv4 clusters, since pod networks almost always consist of RFC1918 addresses. In the case of IPv6, however, use of public addresses is generally preferred even for private networks. This [presents a problem](https://github.com/kubernetes/kubernetes/issues/57130), since it can be hard to foresee what IPv6 network will be available to each node at the time of cluster creation.

AWS provides a /56 network for each VPC, which can be used as the basis for `--pod-network-cidr` but some cloud providers such as Hetzner and Digital Ocean provide a routable IPv6 network to each instance which is dynamically assigned at instance creation and cannot be customized, which precludes use of `--pod-network-cidr` other than ::/0 (which wouldn't work anyway).

Wigglenet does not rely on a single contiguous pod network and it supports different ways of selecting the source per address family. This is controlled by `POD_CIDR_SOURCE_IPV4` and `POD_CIDR_SOURCE_IPV6` environment variables, which can take the following values:

- `none` - Wigglenet will not assign pods addresses of this family
- `spec` - use the relevant networks from `.spec.podCIDR` (default for both IPv4 and IPv6)
- `file` - read the prefixes from a file specified by `POD_CIDR_SOURCE_PATH` environment variable. File format is one network in CIDR format per line.
- `expression` - derive the prefixes from the node's network interfaces and metadata using a [CEL](https://cel.dev/) expression (see [Expression-based pod CIDR derivation](#expression-based-pod-cidr-derivation) below)

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

### Expression-based pod CIDR derivation

For environments where the pod prefix has to be computed from the node's own networking — a common case with providers that route a fixed prefix (e.g. a `/64`) to each instance — the `expression` source lets you express that derivation inline, without a host-side setup script. The expression is written in [CEL](https://cel.dev/) (the [Common Expression Language](https://github.com/google/cel-spec/blob/master/doc/langdef.md), also used by Kubernetes for admission policies and validation rules), evaluated once per node at startup against the interfaces present on the host, and the result is used as that node's pod CIDR(s).

Provide the expression either inline via `POD_CIDR_EXPRESSION`, or from a file via `POD_CIDR_EXPRESSION_PATH` (which takes precedence and is convenient to mount from a ConfigMap). The expression must evaluate to a `cidr` or a `list(cidr)`; results are masked to their network address and split by address family, so the same expression can serve both `POD_CIDR_SOURCE_IPV4=expression` and `POD_CIDR_SOURCE_IPV6=expression`.

#### Inputs

The expression has access to two variables:

- `interfaces` — `map(string, list(cidr))`, keyed by interface name. Each entry is the list of global-unicast on-link prefixes configured on that interface, carrying the host address and the on-link mask (so `p.ip()` is the node's address and `p.prefixLength()` is the on-link prefix length, e.g. `64`). Link-local and loopback addresses are excluded, and the list is sorted (IPv4 before IPv6) for deterministic indexing.
- `node` — `map(string, dyn)` with `node.name` (string), `node.labels` and `node.annotations` (`map(string, string)`). This allows label- or annotation-driven derivation, e.g. carving a different subnet per zone.

#### Functions

In addition to the standard [Kubernetes CEL IP/CIDR library](https://kubernetes.io/docs/reference/using-api/cel/#cidr-library) (`cidr()`, `ip()`, `.masked()`, `.prefixLength()`, `.ip()`, `.containsIP()`, `.containsCIDR()`, `.family()`, …) and the [CEL macros](https://github.com/google/cel-spec/blob/master/doc/langdef.md#macros) such as `filter`, `map` and `exists`, Wigglenet adds one verb:

- `<cidr>.subnet(prefixLength, index)` — the `index`-th subnet of length `prefixLength` carved from the prefix (after masking it to its network address). `prefixLength` must be no shorter than the prefix's own length and no longer than the address width, and `index` must fall within the `2^(prefixLength - len)` available subnets; otherwise evaluation fails. For example `cidr("2001:db8:abcd:1234::/64").subnet(80, 1)` is `2001:db8:abcd:1234:1::/80`.

Note that `filter` returns a `list(cidr)` (not a single element) and `subnet` is only defined on a single `cidr`, so use `[0]` to pick one element before calling `subnet`, or `map` to carve a subnet out of every match.

#### Examples

**Hetzner-style: the second `/80` of the routed `/64` on `eth0`.** Equivalent to `next(islice(net.subnets(16), 1, None))` over the on-link prefix:

```yaml
env:
  - name: POD_CIDR_SOURCE_IPV6
    value: expression
  - name: POD_CIDR_EXPRESSION
    value: |
      interfaces["eth0"]
        .filter(p, p.ip().family() == 6 && p.prefixLength() == 64)[0]
        .subnet(80, 1)
```

**Dual-stack from a single expression.** Both families set to `expression`; return a `list(cidr)` mixing an IPv6 `/80` carved from the routed `/64` and an IPv4 `/26` carved from the on-link `/24`:

```yaml
env:
  - name: POD_CIDR_SOURCE_IPV4
    value: expression
  - name: POD_CIDR_SOURCE_IPV6
    value: expression
  - name: POD_CIDR_EXPRESSION
    value: |
      [
        interfaces["eth0"].filter(p, p.ip().family() == 6 && p.prefixLength() == 64)[0].subnet(80, 1),
        interfaces["eth0"].filter(p, p.ip().family() == 4 && p.prefixLength() == 24)[0].subnet(26, 0)
      ]
```

**Label-driven index.** Carve a different `/80` per zone, so prefixes never collide across failure domains:

```yaml
env:
  - name: POD_CIDR_SOURCE_IPV6
    value: expression
  - name: POD_CIDR_EXPRESSION
    value: |
      interfaces["eth0"].filter(p, p.prefixLength() == 64)[0].subnet(
        80,
        node.labels["topology.kubernetes.io/zone"] == "eu-central" ? 1 : 2
      )
```

**Mounting from a ConfigMap.** Keep the expression out of the manifest and point `POD_CIDR_EXPRESSION_PATH` at a mounted file:

```yaml
env:
  - name: POD_CIDR_SOURCE_IPV6
    value: expression
  - name: POD_CIDR_EXPRESSION_PATH
    value: /etc/wigglenet/pod-cidr.cel
volumeMounts:
  - name: pod-cidr-expression
    mountPath: /etc/wigglenet
    readOnly: true
# ...
volumes:
  - name: pod-cidr-expression
    configMap:
      name: wigglenet-pod-cidr
```

#### Notes

- The expression is compiled and type-checked at startup; a malformed expression or one that does not yield a `cidr`/`list(cidr)` makes the pod fail loudly rather than start with a wrong configuration.
- If the expression yields no prefix for an address family that is configured to use `expression`, startup fails for that node, the same as the other sources.
- When only one family uses `expression`, prefixes of the other family in the result are ignored — that family is taken from its own configured source.

## Firewall backend

Wigglenet supports two firewall backends, controlled by the `FIREWALL_BACKEND` environment variable:

- `nftables` (default) - uses nftables via the `nft` command. This is the recommended backend for modern kernels (4.x+). It uses a single `inet` family table (`wigglenet`) that handles both IPv4 and IPv6 rules together, nftables sets for efficient CIDR matching, and atomic transactions for rule updates.
- `iptables` - uses the legacy iptables/ip6tables commands. This backend maintains separate IPv4 and IPv6 rule sets and requires the `/run/xtables.lock` host path mount for safe concurrent access.

When using the `iptables` backend, the `/run/xtables.lock` volume mount is required to prevent concurrent iptables access issues. This mount can be omitted when using the `nftables` backend.

## Firewall configuration

Masquerading can be switched on or off per address family by `MASQUERADE_IPV4` and `MASQUERADE_IPV6` environment variables. If Wireguard is set up to hand out public IPv6 addresses to pods, masquerading should be turned off for IPv6.

There are two additional options that control the firewall rules: `FILTER_IPV4` and `FILTER_IPV6`. If set to true, Wigglenet will install basic stateful firewall rules for that address family preventing direct connectivity to pods from outside the cluster (egress traffic is not affected and neither are workloads exposed through NodePort and LoadBalancer services).

## NetworkPolicy support

NetworkPolicy enforcement can be controlled via the `ENABLE_NETWORK_POLICY` environment variable (default: true). When enabled, Wigglenet will watch for Kubernetes NetworkPolicy resources and enforce them using the selected firewall backend (nftables or iptables).

**Important**: NetworkPolicy rules are applied independently of the `FILTER_IPV4` and `FILTER_IPV6` settings. This means:
- If `FILTER_IPV4=0` but you have NetworkPolicies, IPv4 policy rules will still be enforced
- If `FILTER_IPV6=0` but you have NetworkPolicies, IPv6 policy rules will still be enforced
- NetworkPolicies control pod-to-pod traffic, while FILTER settings control external-to-pod traffic

NetworkPolicy support requires additional RBAC permissions:
- `pods` (get, list, watch) - to map pod IPs to labels and namespaces
- `namespaces` (get, list, watch) - for namespace selector rules
- `networkpolicies.networking.k8s.io` (get, list, watch) - to watch NetworkPolicy resources

These permissions are included in the default deployment manifests. If NetworkPolicy support is disabled (`ENABLE_NETWORK_POLICY=0`), these permissions are not required but can be safely left in place.

## Flowtable (fastpath)

When using the nftables backend, Wigglenet can offload established connections to an nftables [flowtable](https://wiki.nftables.org/wiki-nftables/index.php/Flowtables) for improved forwarding performance. After a connection has exchanged a configurable number of packets, subsequent packets bypass the full netfilter evaluation and are forwarded directly in the kernel fast path.

This is controlled by three environment variables:

- `ENABLE_FLOWTABLE` (default: `0`) - enable flowtable offloading
- `FLOWTABLE_DEVICES` - comma-separated list of network interfaces to include in the flowtable (e.g. `eth0,wigglenet`). This is required when flowtable is enabled.
- `FLOWTABLE_PACKET_THRESHOLD` (default: `128`) - number of packets in an established connection before offloading. Lower values offload sooner (better throughput for long flows), higher values keep flows in the normal path longer.

**Requirements**: Linux kernel 4.16+ with the `nf_flow_table` module. Only supported with the `nftables` firewall backend.

**Interaction with NetworkPolicy**: The flowtable offload rule runs before firewall and NetworkPolicy evaluation in the forward chain. This means:

- New connections are always subject to full policy evaluation for the first N packets
- Once offloaded, flows bypass NetworkPolicy checks entirely
- If a NetworkPolicy changes after a flow is offloaded, the existing flow will not be re-evaluated until it times out or the flowtable is flushed

This is the same semantic as the existing `ct state established,related accept` rules — connections that were allowed at establishment time continue to be forwarded. For most workloads this is the desired behavior and provides a significant throughput improvement.

## Firewall only mode and native routing

Wigglenet can run in a firewall-only mode by passing `FIREWALL_ONLY=1` environment variable. Running in this mode will not provision a Wireguard tunnel and CNI configuration, but will only filter and masquerade traffic, similar to [ip-masq-agent](https://github.com/kubernetes-sigs/ip-masq-agent). Unlike `ip-masq-agent`, Wigglenet will automatically determine all the pod CIDRs that should not be masqueraded or filtered by watching Node objects, allowing for flexible subnetting.

Native routing is configured (`NATIVE_ROUTING_IPV4=1` / `NATIVE_ROUTING_IPV6=1`). Run in this mode, native routing will only be used for the selected address family instead of the Wireguard overlay. This assumes that there is something outside of the cluster that knows how to route packets for pods to the appropriate node, as generally the pod-to-pod traffic will be forwarded along the default route on each node.

## Metrics

Wigglenet can optionally expose Prometheus metrics and a health endpoint. This is controlled by the following environment variables:

- `ENABLE_METRICS` (default: `0`) - enable the metrics HTTP server
- `METRICS_BIND_ADDR` (default: `:9091`) - address to bind the metrics server
- `METRICS_TLS_CERT_FILE` - path to TLS server certificate (enables HTTPS)
- `METRICS_TLS_KEY_FILE` - path to TLS server private key
- `METRICS_TLS_CLIENT_CA_FILE` - path to CA certificate for client verification (enables mTLS)

When enabled, the following endpoints are available:

- `/metrics` - Prometheus metrics in text format
- `/healthz` - simple health check (returns 200 OK)

**Exposed metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `wigglenet_build_info` | Gauge | `version`, `firewall_backend` | Build information (always 1) |
| `wigglenet_firewall_sync_total` | Counter | `backend`, `status` | Total firewall rule sync attempts |
| `wigglenet_firewall_sync_duration_seconds` | Histogram | `backend` | Duration of firewall sync operations |
| `wigglenet_pod_cidrs_total` | Gauge | | Current pod CIDRs tracked across all nodes |
| `wigglenet_peers_total` | Gauge | | Current WireGuard peers configured |
| `wigglenet_network_policy_rules_total` | Gauge | `direction` | Generated NetworkPolicy firewall rules |
| `wigglenet_peer_last_handshake_seconds` | Gauge | `public_key`, `endpoint` | Seconds since last WireGuard handshake |
| `wigglenet_peer_receive_bytes_total` | Counter | `public_key`, `endpoint` | Bytes received from WireGuard peer |
| `wigglenet_peer_transmit_bytes_total` | Counter | `public_key`, `endpoint` | Bytes transmitted to WireGuard peer |

The WireGuard peer metrics (`wigglenet_peer_*`) are read directly from the kernel on each Prometheus scrape, so they are always fresh. These metrics are only available when WireGuard is active (not in firewall-only or native routing modes).

Since Wigglenet runs with `hostNetwork: true`, there is no Service needed for scraping. A `PodMonitor` resource (for prometheus-operator / kube-prometheus-stack) is the most appropriate way to configure scraping. See `deploy/manifest-metrics.yaml` for a complete example including the PodMonitor.

A sample Grafana dashboard is available at `docs/grafana-dashboard.json`.

**Securing the metrics endpoint**: Since Wigglenet runs with `hostNetwork: true`, the metrics port is bound on the host's network interfaces and accessible to anything that can reach the node. There are several options to secure it:

1. **kube-rbac-proxy sidecar** (recommended) — bind metrics on localhost and front it with [kube-rbac-proxy](https://github.com/brancz/kube-rbac-proxy), which authenticates scrape requests using Kubernetes TokenReview/SubjectAccessReview. This is the same approach used by node-exporter and kube-state-metrics. See `deploy/manifest-metrics.yaml` for a complete example.

2. **mTLS** — set `METRICS_TLS_CERT_FILE`, `METRICS_TLS_KEY_FILE`, and `METRICS_TLS_CLIENT_CA_FILE` to require client certificate authentication. This should use a dedicated private CA (not a public CA), as any certificate signed by the CA will be accepted. Certificates are automatically reloaded when the files change on disk (e.g. after Secret rotation by kubelet or cert-manager), with no pod restart required. Prometheus supports client certificates via `tlsConfig.cert`/`tlsConfig.keySecret`/`tlsConfig.ca` in ServiceMonitor.

3. **Localhost binding** — set `METRICS_BIND_ADDR=127.0.0.1:9091` to restrict access to localhost only. Simple but limits how Prometheus can scrape.

## Node address selection

Wigglenet needs to be aware of the node's host address(es) in order to know where to terminate the Wireguard tunnel. In addition, node addresses need to be set as an allowed source IP in order to allow communication between the host and a pod running on another node. 

By default, Wigglenet takes all the `ExternalIP` and `InternalIP` entries from the Node object and then uses the first one as the tunnel endpoint. Some cloud providers may not populate the fields correctly (e.g. only put IPv4 address there, even though the cluster is dual-stack). To work around this, Wigglenet can be configured to additionaly take the node addresses from the network interfaces. The `NODE_IP_INTERFACES` environment variable takes a comma-separated list of interfaces to consider as sources of node addresses. Only global unicast addresses will be considered (this includes RFC1918 and ULA addresses, but excludes link-local and multicast addresses).

To force the Wireguard tunnel to use an address of a particular family as the endpoint, pass `WG_IP_FAMILY={ipv4,ipv6,dualstack}` (`dualstack` is the default).
