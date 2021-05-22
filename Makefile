.PHONY: cluster build restart install logs

cluster:
	kind create cluster --config testing/cluster.yaml

build:
	docker build -t wigglenet .
	kind load docker-image wigglenet

restart:
	kubectl delete pod -n kube-system -l app=wigglenet

logs:
	kubectl logs -n kube-system daemonset/wigglenet

install:
	kubectl apply -f manifest.yaml