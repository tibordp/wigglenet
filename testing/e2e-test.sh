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
        | kubectl --context="kind-${CLUSTER_NAME}" apply -f -

    log_info "Waiting for wigglenet pods to be ready"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready \
        -n kube-system pods -l app=wigglenet --timeout="${TIMEOUT}s"

    log_info "Waiting for nodes to become ready (now that CNI is installed)"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready nodes --all --timeout="${TIMEOUT}s"

    # Give it a few extra seconds to fully initialize
    sleep 5
}

# Check iptables/nftables backend consistency
check_iptables_backend() {
    log_step "Checking iptables/nftables backend consistency"

    local nodes=$(kubectl --context="kind-${CLUSTER_NAME}" get nodes -o name | sed 's|node/||')
    local first_node=$(echo "$nodes" | head -n1)
    local backend=""

    for node in $nodes; do
        local node_backend=$(docker exec "${CLUSTER_NAME}-${node}" iptables --version | grep -oE '(nf_tables|legacy)')

        if [ -z "$backend" ]; then
            backend="$node_backend"
            log_info "Detected iptables backend: $backend"
        elif [ "$backend" != "$node_backend" ]; then
            log_error "Inconsistent iptables backend: $first_node uses $backend but $node uses $node_backend"
            return 1
        fi
    done

    log_info "All nodes using consistent backend: $backend"
}

# Verify iptables chains exist
verify_iptables_chains() {
    log_step "Verifying iptables chains"

    local node="${CLUSTER_NAME}-control-plane"
    local missing_chains=()

    # Check for WIGGLENET chains in filter and nat tables
    for family in iptables ip6tables; do
        for table in filter nat; do
            log_info "Checking $family table $table on $node"

            local chains=$(docker exec "$node" $family-save -t "$table" 2>/dev/null || echo "")

            if echo "$chains" | grep -q "KUBE-" && echo "$chains" | grep -q "WIGGLENET-"; then
                log_info "✓ Both KUBE-* and WIGGLENET-* chains found in $family/$table"
            elif echo "$chains" | grep -q "KUBE-"; then
                log_warn "⚠ Found KUBE-* but no WIGGLENET-* chains in $family/$table"
            fi
        done
    done
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

    # Create pod on first worker
    kubectl --context="kind-${CLUSTER_NAME}" run test-pod1 \
        --image=nicolaka/netshoot:latest \
        --overrides="{\"spec\":{\"nodeName\":\"$worker1\"}}" \
        --command -- sleep 3600

    # Create pod on second worker
    kubectl --context="kind-${CLUSTER_NAME}" run test-pod2 \
        --image=nicolaka/netshoot:latest \
        --overrides="{\"spec\":{\"nodeName\":\"$worker2\"}}" \
        --command -- sleep 3600

    log_info "Waiting for test pods to be ready"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready pod/test-pod1 --timeout="${TIMEOUT}s"
    kubectl --context="kind-${CLUSTER_NAME}" wait --for=condition=Ready pod/test-pod2 --timeout="${TIMEOUT}s"
}

# Test pod-to-pod connectivity
test_connectivity() {
    log_step "Testing pod-to-pod connectivity"

    local context="kind-${CLUSTER_NAME}"

    # Get pod IPs
    local pod1_ips=$(kubectl --context="$context" get pod test-pod1 -o jsonpath='{.status.podIPs[*].ip}')
    local pod2_ips=$(kubectl --context="$context" get pod test-pod2 -o jsonpath='{.status.podIPs[*].ip}')

    log_info "test-pod1 IPs: $pod1_ips"
    log_info "test-pod2 IPs: $pod2_ips"

    # Test IPv4 connectivity (pod1 -> pod2)
    local pod2_ipv4=$(echo "$pod2_ips" | tr ' ' '\n' | grep -v ':' | head -n1)
    if [ -n "$pod2_ipv4" ]; then
        log_info "Testing IPv4: test-pod1 -> test-pod2 ($pod2_ipv4)"
        if kubectl --context="$context" exec test-pod1 -- ping -c 3 -W 2 "$pod2_ipv4" > /dev/null 2>&1; then
            log_info "✓ IPv4 connectivity successful"
        else
            log_error "✗ IPv4 connectivity failed"
            return 1
        fi
    else
        log_warn "No IPv4 address found for test-pod2"
    fi

    # Test IPv6 connectivity (pod1 -> pod2)
    local pod2_ipv6=$(echo "$pod2_ips" | tr ' ' '\n' | grep ':' | head -n1)
    if [ -n "$pod2_ipv6" ]; then
        log_info "Testing IPv6: test-pod1 -> test-pod2 ($pod2_ipv6)"
        if kubectl --context="$context" exec test-pod1 -- ping -c 3 -W 2 "$pod2_ipv6" > /dev/null 2>&1; then
            log_info "✓ IPv6 connectivity successful"
        else
            log_error "✗ IPv6 connectivity failed"
            return 1
        fi
    else
        log_warn "No IPv6 address found for test-pod2"
    fi

    # Test external connectivity
    log_info "Testing external connectivity from test-pod1"
    if kubectl --context="$context" exec test-pod1 -- ping -c 3 -W 2 8.8.8.8 > /dev/null 2>&1; then
        log_info "✓ External IPv4 connectivity successful"
    else
        log_warn "⚠ External IPv4 connectivity failed (may be expected in some environments)"
    fi
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

# Cleanup test pods
cleanup_test_pods() {
    log_step "Cleaning up test pods"

    kubectl --context="kind-${CLUSTER_NAME}" delete pod test-pod1 test-pod2 --ignore-not-found=true --wait=false
}

# Main execution
main() {
    log_info "Starting wigglenet E2E test"
    log_info "Cluster: ${CLUSTER_NAME}, Config: ${CLUSTER_CONFIG}, Timeout: ${TIMEOUT}s"

    check_prerequisites
    create_cluster
    build_and_load_image
    deploy_wigglenet
    check_iptables_backend
    verify_iptables_chains
    create_test_pods
    test_connectivity
    check_wigglenet_logs
    cleanup_test_pods

    log_step "All tests passed! ✓"
    log_info "Run 'SKIP_CLEANUP=true $0' to keep the cluster for manual inspection"
}

# Run main
main "$@"
