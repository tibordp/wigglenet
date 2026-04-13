#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-kind}"
CLUSTER_CONFIG="${CLUSTER_CONFIG:-testing/cluster.yaml}"
TIMEOUT="${TIMEOUT:-300}"
FIREWALL_BACKEND="${FIREWALL_BACKEND:-nftables}"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "\n${GREEN}==>${NC} $1"
}

# Cleanup function
cleanup() {
    if [ "${SKIP_CLEANUP:-false}" != "true" ]; then
        log_step "Cleaning up kind cluster"
        kind delete cluster --name "${CLUSTER_NAME}" 2>/dev/null || true
    else
        log_warn "Skipping cleanup (SKIP_CLEANUP=true)"
    fi
}

# Trap to ensure cleanup on exit
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_step "Checking prerequisites"

    local missing=()

    for cmd in kind kubectl docker; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required commands: ${missing[*]}"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Create kind cluster
create_cluster() {
    log_step "Creating kind cluster"

    if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_warn "Cluster ${CLUSTER_NAME} already exists, deleting it"
        kind delete cluster --name "${CLUSTER_NAME}"
    fi

    kind create cluster --name "${CLUSTER_NAME}" --config "${CLUSTER_CONFIG}"

    log_info "Cluster created (nodes won't be Ready until CNI is installed)"
}

# Build and load image
build_and_load_image() {
    log_step "Building and loading wigglenet image"

    docker build -t wigglenet .
    kind load docker-image wigglenet --name "${CLUSTER_NAME}"

    log_info "Image loaded successfully"
}

# Deploy wigglenet
deploy_wigglenet() {
    log_step "Deploying wigglenet"

    sed 's|ghcr.io/tibordp/wigglenet:.*|wigglenet|g' ./deploy/manifest.yaml \
        | sed 's/Always/Never/g' \
        | sed "s/value: \"nftables\"/value: \"${FIREWALL_BACKEND}\"/g" \
        | kubectl --context="kind-${CLUSTER_NAME}" apply -f -

    log_info "Waiting for wigglenet pods to be ready"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready \
        -n kube-system pods -l app=wigglenet --timeout="${TIMEOUT}s"

    log_info "Waiting for nodes to become ready (now that CNI is installed)"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready nodes --all --timeout="${TIMEOUT}s"

    # Give it a few extra seconds to fully initialize
    sleep 5
}

# Verify firewall rules are installed
verify_firewall_rules() {
    log_step "Verifying firewall rules (backend: ${FIREWALL_BACKEND})"

    local node="${CLUSTER_NAME}-control-plane"

    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        local found=false
        for family in iptables ip6tables; do
            local chains=$(docker exec "$node" $family-save -t filter 2>/dev/null || echo "")
            if echo "$chains" | grep -q "WIGGLENET-NETPOL"; then
                log_info "✓ WIGGLENET-NETPOL chain found in $family/filter"
                found=true
            fi
        done
        if [ "$found" = false ]; then
            log_error "No WIGGLENET-NETPOL chains found in iptables"
            return 1
        fi
    else
        # nftables backend — check for wigglenet table
        local rules=$(docker exec "$node" nft list table inet wigglenet 2>/dev/null || echo "")
        if echo "$rules" | grep -q "chain netpol"; then
            log_info "✓ nftables table 'wigglenet' with netpol chain found"
        else
            log_error "nftables wigglenet table or netpol chain not found"
            return 1
        fi
    fi
}

# Create test pods
create_test_pods() {
    log_step "Creating test pods"

    # Get available worker nodes
    local workers=$(kubectl --context="kind-${CLUSTER_NAME}" get nodes -l '!node-role.kubernetes.io/control-plane' -o name | head -n2)
    local worker1=$(echo "$workers" | sed -n 1p | sed 's|node/||')
    local worker2=$(echo "$workers" | sed -n 2p | sed 's|node/||')

    if [ -z "$worker2" ]; then
        log_warn "Only one worker node available, using control-plane as second node"
        worker2=$(kubectl --context="kind-${CLUSTER_NAME}" get nodes -o name | head -n1 | sed 's|node/||')
    fi

    log_info "Scheduling pods on nodes: $worker1 and $worker2"

    # Create client pod on first worker
    kubectl --context="kind-${CLUSTER_NAME}" run test-pod1 \
        --image=nicolaka/netshoot:latest \
        --overrides="{\"spec\":{\"nodeName\":\"$worker1\"}}" \
        --command -- sleep 3600

    # Create server pod (nginx) on second worker with readiness probe
    kubectl --context="kind-${CLUSTER_NAME}" run test-pod2 \
        --image=nginx:alpine \
        --overrides="{\"spec\":{\"nodeName\":\"$worker2\",\"containers\":[{\"name\":\"test-pod2\",\"image\":\"nginx:alpine\",\"readinessProbe\":{\"httpGet\":{\"path\":\"/\",\"port\":80},\"initialDelaySeconds\":1,\"periodSeconds\":1}}]}}"

    log_info "Waiting for test pods to be ready"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready pod/test-pod1 --timeout="${TIMEOUT}s"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready pod/test-pod2 --timeout="${TIMEOUT}s"
}

# Helper function to test HTTP connectivity to a target IP
test_http_connectivity() {
    local context="$1"
    local source_pod="$2"
    local namespace="$3"
    local target_ip="$4"
    local description="$5"
    local required="$6"  # "true" or "false"

    local url
    if echo "$target_ip" | grep -q ':'; then
        # IPv6 address - needs brackets
        url="http://[$target_ip]"
    else
        # IPv4 address
        url="http://$target_ip"
    fi

    local ns_flag=""
    if [ -n "$namespace" ]; then
        ns_flag="-n $namespace"
    fi

    log_info "Testing $description: $source_pod -> $target_ip"
    if kubectl --context="$context" exec $ns_flag "$source_pod" -- curl -s --max-time 2 "$url" > /dev/null 2>&1; then
        log_info "✓ $description connectivity successful"
        return 0
    else
        if [ "$required" = "true" ]; then
            log_error "✗ $description connectivity failed"
            return 1
        else
            log_warn "⚠ $description connectivity failed (may be expected in some environments)"
            return 0
        fi
    fi
}

# Test pod-to-pod connectivity
test_connectivity() {
    log_step "Testing pod-to-pod connectivity"

    local context="kind-${CLUSTER_NAME}"

    # Get pod IPs
    local pod2_ips=$(kubectl --context="$context" get pod test-pod2 -o jsonpath='{.status.podIPs[*].ip}')
    log_info "test-pod2 IPs: $pod2_ips"

    # Test pod-to-pod connectivity for both IPv4 and IPv6
    local tested_any=false
    for ip in $pod2_ips; do
        if echo "$ip" | grep -q ':'; then
            test_http_connectivity "$context" "test-pod1" "" "$ip" "IPv6 HTTP (pod-to-pod)" "true" || return 1
            tested_any=true
        else
            test_http_connectivity "$context" "test-pod1" "" "$ip" "IPv4 HTTP (pod-to-pod)" "true" || return 1
            tested_any=true
        fi
    done

    if [ "$tested_any" = false ]; then
        log_error "No IP addresses found for test-pod2"
        return 1
    fi

    # Test external connectivity for both IPv4 and IPv6
    log_info "Testing external connectivity from test-pod1"
    test_http_connectivity "$context" "test-pod1" "" "ipv4.google.com" "IPv4 HTTP (external)" "false"
    test_http_connectivity "$context" "test-pod1" "" "ipv6.google.com" "IPv6 HTTP (external)" "false"
}

# Check for errors in wigglenet logs
check_wigglenet_logs() {
    log_step "Checking wigglenet logs for errors"

    local context="kind-${CLUSTER_NAME}"
    local pods=$(kubectl --context="$context" get pods -n kube-system -l app=wigglenet -o name)

    local found_errors=false
    for pod in $pods; do
        log_info "Checking logs for $pod"
        local errors=$(kubectl --context="$context" logs -n kube-system "$pod" 2>&1 | grep -i "error" | grep -v "HandleError" || true)

        if [ -n "$errors" ]; then
            log_error "Found errors in $pod:"
            echo "$errors"
            found_errors=true
        fi
    done

    if [ "$found_errors" = false ]; then
        log_info "✓ No errors found in wigglenet logs"
    else
        return 1
    fi
}

# Test NetworkPolicy enforcement
test_network_policy() {
    log_step "Testing NetworkPolicy enforcement"

    local context="kind-${CLUSTER_NAME}"

    # Create test namespace
    log_info "Creating test namespace"
    kubectl --context="$context" create namespace netpol-test

    # Create three pods: client, allowed-server, denied-server
    log_info "Creating test pods for NetworkPolicy"

    # Client pod
    kubectl --context="$context" run client -n netpol-test \
        --image=nicolaka/netshoot:latest \
        --labels="app=client" \
        --command -- sleep 3600

    # Allowed server pod - nginx with readiness probe
    kubectl --context="$context" run allowed-server -n netpol-test \
        --image=nginx:alpine \
        --labels="app=server,role=allowed" \
        --overrides='{"spec":{"containers":[{"name":"allowed-server","image":"nginx:alpine","readinessProbe":{"httpGet":{"path":"/","port":80},"initialDelaySeconds":1,"periodSeconds":1}}]}}'

    # Denied server pod - nginx with readiness probe
    kubectl --context="$context" run denied-server -n netpol-test \
        --image=nginx:alpine \
        --labels="app=server,role=denied" \
        --overrides='{"spec":{"containers":[{"name":"denied-server","image":"nginx:alpine","readinessProbe":{"httpGet":{"path":"/","port":80},"initialDelaySeconds":1,"periodSeconds":1}}]}}'

    log_info "Waiting for NetworkPolicy test pods to be ready"
    kubectl --context="$context" wait --for=condition=Ready pod/client -n netpol-test --timeout="${TIMEOUT}s"
    kubectl --context="$context" wait --for=condition=Ready pod/allowed-server -n netpol-test --timeout="${TIMEOUT}s"
    kubectl --context="$context" wait --for=condition=Ready pod/denied-server -n netpol-test --timeout="${TIMEOUT}s"

    # Get pod IPs (all IPs for dual-stack)
    local allowed_ips=$(kubectl --context="$context" get pod allowed-server -n netpol-test -o jsonpath='{.status.podIPs[*].ip}')
    local denied_ips=$(kubectl --context="$context" get pod denied-server -n netpol-test -o jsonpath='{.status.podIPs[*].ip}')

    log_info "allowed-server IPs: $allowed_ips"
    log_info "denied-server IPs: $denied_ips"

    # Test connectivity before NetworkPolicy (should work for all IPs)
    log_info "Testing connectivity before NetworkPolicy (baseline)"
    for ip in $allowed_ips; do
        local family="IPv4"
        echo "$ip" | grep -q ':' && family="IPv6"
        test_http_connectivity "$context" "client" "netpol-test" "$ip" "$family baseline (allowed-server)" "true" || return 1
    done

    for ip in $denied_ips; do
        local family="IPv4"
        echo "$ip" | grep -q ':' && family="IPv6"
        test_http_connectivity "$context" "client" "netpol-test" "$ip" "$family baseline (denied-server)" "true" || return 1
    done

    # Apply NetworkPolicy that allows client->allowed-server but denies client->denied-server
    log_info "Applying NetworkPolicy to restrict access"
    cat <<EOF | kubectl --context="$context" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-only-to-allowed-server
  namespace: netpol-test
spec:
  podSelector:
    matchLabels:
      app: server
      role: allowed
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: client
    ports:
    - protocol: TCP
      port: 80
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-to-denied-server
  namespace: netpol-test
spec:
  podSelector:
    matchLabels:
      app: server
      role: denied
  policyTypes:
  - Ingress
  # Empty ingress rules = deny all
EOF

    # Wait a bit for policy to be enforced
    log_info "Waiting for NetworkPolicy to be enforced"
    sleep 5

    # Test connectivity after NetworkPolicy
    log_info "Testing connectivity after NetworkPolicy"

    # Should still reach allowed-server (for all IP families)
    for ip in $allowed_ips; do
        local family="IPv4"
        echo "$ip" | grep -q ':' && family="IPv6"
        test_http_connectivity "$context" "client" "netpol-test" "$ip" "$family after policy (allowed-server)" "true" || return 1
    done

    # Should NOT reach denied-server (for all IP families)
    for ip in $denied_ips; do
        local family="IPv4"
        echo "$ip" | grep -q ':' && family="IPv6"

        log_info "Testing $family after policy (denied-server): client -> $ip"
        local url="http://$ip"
        if echo "$ip" | grep -q ':'; then
            url="http://[$ip]"
        fi

        if kubectl --context="$context" exec -n netpol-test client -- curl -s --max-time 2 "$url" > /dev/null 2>&1; then
            log_error "✗ $family: Can still reach denied-server (policy not enforced)"
            return 1
        else
            log_info "✓ $family: Cannot reach denied-server (policy denies correctly)"
        fi
    done

    log_info "✓ NetworkPolicy enforcement working correctly for all IP families"
}

# Cleanup NetworkPolicy test resources
cleanup_network_policy_test() {
    log_step "Cleaning up NetworkPolicy test resources"

    kubectl --context="kind-${CLUSTER_NAME}" delete namespace netpol-test --ignore-not-found=true --wait=false
}

# Cleanup test pods
cleanup_test_pods() {
    log_step "Cleaning up test pods"

    kubectl --context="kind-${CLUSTER_NAME}" delete pod test-pod1 test-pod2 --ignore-not-found=true --wait=false
}

# Main execution
main() {
    log_info "Starting wigglenet E2E test"
    log_info "Cluster: ${CLUSTER_NAME}, Config: ${CLUSTER_CONFIG}, Timeout: ${TIMEOUT}s, Backend: ${FIREWALL_BACKEND}"

    check_prerequisites
    create_cluster
    build_and_load_image
    deploy_wigglenet
    verify_firewall_rules
    create_test_pods
    test_connectivity
    test_network_policy
    check_wigglenet_logs
    cleanup_test_pods
    cleanup_network_policy_test

    log_step "All tests passed! ✓"
    log_info "Run 'SKIP_CLEANUP=true $0' to keep the cluster for manual inspection"
}

# Run main
main "$@"
