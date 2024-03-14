module github.com/tibordp/wigglenet

go 1.22

require (
	github.com/containernetworking/cni v1.1.2
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.9.0
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/crypto v0.21.0 // indirect
	golang.org/x/net v0.22.0 // indirect
	golang.org/x/oauth2 v0.18.0 // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/term v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	k8s.io/api v0.29.2
	k8s.io/apimachinery v0.29.2
	k8s.io/client-go v1.5.2
	k8s.io/klog/v2 v2.120.1
	k8s.io/kubernetes v1.29.2
	k8s.io/utils v0.0.0-20240310230437-4693a0247e57
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.12.0 // indirect
	github.com/go-openapi/jsonpointer v0.21.0 // indirect
	github.com/go-openapi/jsonreference v0.21.0 // indirect
	github.com/go-openapi/swag v0.23.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.29.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.29.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.29.0
	k8s.io/apiserver => k8s.io/apiserver v0.29.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.29.0
	k8s.io/client-go => k8s.io/client-go v0.29.0
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.29.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.29.0
	k8s.io/code-generator => k8s.io/code-generator v0.29.0
	k8s.io/component-base => k8s.io/component-base v0.29.0
	k8s.io/component-helpers => k8s.io/component-helpers v0.29.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.29.0
	k8s.io/cri-api => k8s.io/cri-api v0.29.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.29.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.29.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.29.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.29.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.29.0
	k8s.io/kubectl => k8s.io/kubectl v0.29.0
	k8s.io/kubelet => k8s.io/kubelet v0.29.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.29.0
	k8s.io/metrics => k8s.io/metrics v0.29.0
	k8s.io/mount-utils => k8s.io/mount-utils v0.29.0
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.29.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.29.0
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.29.0
)
