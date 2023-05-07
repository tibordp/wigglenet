module github.com/tibordp/wigglenet

go 1.20

require (
	github.com/containernetworking/cni v1.1.2
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/stretchr/testify v1.8.2
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/crypto v0.8.0 // indirect
	golang.org/x/net v0.9.0 // indirect
	golang.org/x/oauth2 v0.7.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/term v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
	k8s.io/api v0.27.1
	k8s.io/apimachinery v0.27.1
	k8s.io/client-go v1.5.2
	k8s.io/klog/v2 v2.100.1
	k8s.io/kubernetes v1.27.1
	k8s.io/utils v0.0.0-20230505201702-9f6742963106
	sigs.k8s.io/yaml v1.3.0 // indirect
)

require golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.10.2 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gnostic v0.6.9 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sync v0.2.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20230325221338-052af4a8072b // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/kube-openapi v0.0.0-20230501164219-8b0f38b5fd1f // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)

replace (
	k8s.io/api => k8s.io/api v0.27.0
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.27.0
	k8s.io/apimachinery => k8s.io/apimachinery v0.27.0
	k8s.io/apiserver => k8s.io/apiserver v0.27.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.27.0
	k8s.io/client-go => k8s.io/client-go v0.27.0
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.27.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.27.0
	k8s.io/code-generator => k8s.io/code-generator v0.27.0
	k8s.io/component-base => k8s.io/component-base v0.27.0
	k8s.io/component-helpers => k8s.io/component-helpers v0.27.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.27.0
	k8s.io/cri-api => k8s.io/cri-api v0.27.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.27.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.27.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.27.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.27.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.27.0
	k8s.io/kubectl => k8s.io/kubectl v0.27.0
	k8s.io/kubelet => k8s.io/kubelet v0.27.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.27.0
	k8s.io/metrics => k8s.io/metrics v0.27.0
	k8s.io/mount-utils => k8s.io/mount-utils v0.27.0
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.27.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.27.0
	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.27.0
)
