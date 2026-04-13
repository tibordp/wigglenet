# This makefile just has useful shortcuts for testing locally with kind. If you want to build the
# project itself, do so via the go toolchain or Dockerfile.

.PHONY: image kind-default kind-no-podcidr kind-v4-only patch-ipv6-cidr deploy restart logs \
	cyclonus-install cyclonus-prep cyclonus-quick cyclonus-ipblock-except cyclonus-end-port \
	cyclonus-sctp cyclonus-named-port cyclonus-full

kind-default:
	kind create cluster --config testing/cluster.yaml

kind-no-podcidr:
	kind create cluster --config testing/cluster_no_podcidr.yaml

kind-v4-only:
	kind create cluster --config testing/cluster_v4_only.yaml

kind-v6-singlestack:
	kind create cluster --config testing/cluster_v6_singlestack.yaml

image:
	docker build -t wigglenet .
	kind load docker-image wigglenet

# Patch manifest to use local Docker image instead of one from Dockerhub
deploy:
	sed 's\ghcr.io/tibordp/wigglenet:.*\wigglenet\g' ./deploy/manifest.yaml \
		| sed 's/Always/Never/g' \
		| kubectl --context=kind-kind apply -f -

restart:
	kubectl --context=kind-kind delete pod -n kube-system -l app=wigglenet

logs:
	kubectl --context=kind-kind logs -n kube-system -l app=wigglenet

PATCH_COMMAND=mkdir -p /etc/wigglenet && tee /etc/wigglenet/cidrs.txt

patch-ipv6-cidr:
	echo "2001:db8:0:1::/64" | docker exec -i kind-control-plane sh -c "$(PATCH_COMMAND)"
	echo "2001:db8:0:2::/64" | docker exec -i kind-worker sh -c "$(PATCH_COMMAND)"
	echo "2001:db8:0:3::/64" | docker exec -i kind-worker2 sh -c "$(PATCH_COMMAND)"
	echo "2001:db8:0:4::/64" | docker exec -i kind-worker3 sh -c "$(PATCH_COMMAND)"

get-rules:
	docker exec -i kind-control-plane sh -c "iptables-save -t filter"
	docker exec -i kind-control-plane sh -c "ip6tables-save -t filter"

# ----- NetworkPolicy conformance testing with Cyclonus -----
#
# Cyclonus (github.com/mattfenwick/cyclonus) generates K8s NetworkPolicy
# scenarios and probes pod-to-pod connectivity to verify policy enforcement.
# The full default suite (`cyclonus-full`) runs ~110 test cases and takes
# multiple hours; the targeted suites below run in 1-5 minutes and are meant
# for fix-and-iterate workflows.
#
# Cyclonus's generated test cases reference pods x/a x/b x/c y/a y/b y/c z/a z/b z/c
# by name, so we cannot shrink the pod/namespace set — only the *speed knobs*
# can be tuned for fast iteration. The big wins:
#   - one server port instead of two (halves probes)
#   - one server protocol instead of three (cuts probes ~3x; TCP only)
#   - short perturbation wait + short probe timeout
#   - retries=0
#
# Common knobs (override on the command line):
#   CYCLONUS_CONTEXT      kube context to test against     (default: kind-kind)
#   CYCLONUS_PROTOCOLS    server protocols                 (default: TCP)
#   CYCLONUS_PORT         server port                      (default: 80)
#   CYCLONUS_WAIT         seconds to wait after policy add (default: 3)
#   CYCLONUS_TIMEOUT      seconds per probe attempt        (default: 2)
#   CYCLONUS_RETRIES      probe retries on failure         (default: 0)

CYCLONUS_CONTEXT    ?= kind-kind
CYCLONUS_PROTOCOLS  ?= TCP
CYCLONUS_PORT       ?= 80
CYCLONUS_WAIT       ?= 3
CYCLONUS_TIMEOUT    ?= 2
CYCLONUS_RETRIES    ?= 0

CYCLONUS_FAST_FLAGS = \
	--context=$(CYCLONUS_CONTEXT) \
	--server-protocol=$(CYCLONUS_PROTOCOLS) \
	--server-port=$(CYCLONUS_PORT) \
	--perturbation-wait-seconds=$(CYCLONUS_WAIT) \
	--job-timeout-seconds=$(CYCLONUS_TIMEOUT) \
	--retries=$(CYCLONUS_RETRIES) \
	--noisy=true

cyclonus-install:
	go install github.com/mattfenwick/cyclonus/cmd/cyclonus@latest

# Cyclonus's generated test cases reference x, y, z by name; create them.
cyclonus-prep:
	@for ns in x y z; do \
		kubectl --context=$(CYCLONUS_CONTEXT) get ns $$ns >/dev/null 2>&1 \
			|| kubectl --context=$(CYCLONUS_CONTEXT) create ns $$ns; \
	done

# Quick smoke test: a small subset of policy types covering the common cases.
# Runs in ~1-2 minutes. Use this as the default fast feedback loop.
cyclonus-quick: cyclonus-prep
	cyclonus generate $(CYCLONUS_FAST_FLAGS) \
		--include=conflict,allow-all,deny-all,ingress,egress,ip-block-no-except

# Targeted suites for verifying specific spec features / fixes.
cyclonus-ipblock-except: cyclonus-prep
	cyclonus generate $(CYCLONUS_FAST_FLAGS) --include=ip-block-with-except

cyclonus-end-port: cyclonus-prep
	cyclonus generate $(CYCLONUS_FAST_FLAGS) --include=end-port

cyclonus-sctp: cyclonus-prep
	cyclonus generate $(CYCLONUS_FAST_FLAGS) --include=sctp \
		--server-protocol=TCP,SCTP

cyclonus-named-port: cyclonus-prep
	cyclonus generate $(CYCLONUS_FAST_FLAGS) --include=named-port

# Full conformance suite — slow (multiple hours), uses the cyclonus defaults.
# Run this for nightly / pre-release validation, not in a fast iteration loop.
cyclonus-full: cyclonus-prep
	cyclonus generate \
		--context=$(CYCLONUS_CONTEXT) \
		--noisy=true \
		--perturbation-wait-seconds=10 \
		--pod-creation-timeout-seconds=120
