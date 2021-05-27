.PHONY: image kind-default kind-no-podcidr kind-v4-only patch-ipv6-cidr

kind-default:
	kind create cluster --config testing/cluster.yaml

kind-no-podcidr:
	kind create cluster --config testing/cluster_no_podcidr.yaml

kind-v4-only:
	kind create cluster --config testing/cluster_v4_only.yaml

image: 
	docker build -t wigglenet .
	kind load docker-image wigglenet

patch-ipv6-cidr:
	echo "2001:db8:0:1::/64" | docker exec -i kind-control-plane tee -a /etc/wigglenet/cidrs.txt
	echo "2001:db8:0:2::/64" | docker exec -i kind-worker tee -a /etc/wigglenet/cidrs.txt
	echo "2001:db8:0:3::/64" | docker exec -i kind-worker2 tee -a /etc/wigglenet/cidrs.txt
	echo "2001:db8:0:4::/64" | docker exec -i kind-worker3 tee -a /etc/wigglenet/cidrs.txt