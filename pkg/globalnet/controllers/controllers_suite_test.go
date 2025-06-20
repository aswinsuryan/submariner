/*
SPDX-License-Identifier: Apache-2.0

Copyright Contributors to the Submariner project.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers_test

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	fakeDynClient "github.com/submariner-io/admiral/pkg/fake"
	"github.com/submariner-io/admiral/pkg/ipam"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/slices"
	"github.com/submariner-io/admiral/pkg/syncer/test"
	testutil "github.com/submariner-io/admiral/pkg/test"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cni"
	"github.com/submariner-io/submariner/pkg/globalnet/constants"
	"github.com/submariner-io/submariner/pkg/globalnet/controllers"
	"github.com/submariner-io/submariner/pkg/packetfilter"
	fakePF "github.com/submariner-io/submariner/pkg/packetfilter/fake"
	routeAgent "github.com/submariner-io/submariner/pkg/routeagent_driver/constants"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	k8stesting "k8s.io/client-go/testing"
	mcsv1a1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

const (
	namespace                 = "submariner"
	localCIDR                 = "169.254.1.0/24"
	globalEgressIPName        = "east-region"
	globalIngressIPName       = "nginx-ingress-ip"
	kubeProxyIPTableChainName = "KUBE-SVC-Y7DIXXI5PNAUV7FB"
	serviceName               = "nginx"
	cniInterfaceIP            = "169.254.1.50"
	globalCIDR                = "242.10.1.0/24"
	globalIP1                 = "242.10.1.100"
	globalIP2                 = "242.10.1.101"
	globalIP3                 = "242.10.1.102"
	ipv6IP                    = "fc00:2001::6757"
)

func init() {
	kzerolog.AddFlags(nil)

	_ = submarinerv1.AddToScheme(scheme.Scheme)
	_ = mcsv1a1.AddToScheme(scheme.Scheme)
}

var _ = BeforeSuite(func() {
	kzerolog.InitK8sLogging()

	cni.HostInterfaces = func() ([]cni.HostInterface, error) {
		return []cni.HostInterface{{
			Name: "veth0",
			Addr: cniInterfaceIP + "/24",
		}}, nil
	}
})

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Globalnet Controllers Suite")
}

type testDriverBase struct {
	controller               controllers.Interface
	restMapper               meta.RESTMapper
	dynClient                *dynamicfake.FakeDynamicClient
	scheme                   *runtime.Scheme
	pFilter                  *fakePF.PacketFilter
	pool                     *ipam.IPPool
	localSubnets             []string
	globalCIDR               string
	hostName                 string
	globalEgressIPs          dynamic.ResourceInterface
	clusterGlobalEgressIPs   dynamic.ResourceInterface
	globalIngressIPs         dynamic.ResourceInterface
	services                 dynamic.ResourceInterface
	serviceExports           dynamic.ResourceInterface
	endpoints                dynamic.ResourceInterface
	pods                     dynamic.NamespaceableResourceInterface
	gateways                 dynamic.ResourceInterface
	watches                  *fakeDynClient.WatchReactor
	expectInstantiationError bool
}

func newTestDriverBase() *testDriverBase {
	t := &testDriverBase{
		restMapper: test.GetRESTMapperFor(&submarinerv1.Endpoint{}, &corev1.Service{}, &corev1.Pod{}, &corev1.Endpoints{},
			&submarinerv1.GlobalEgressIP{}, &submarinerv1.ClusterGlobalEgressIP{}, &submarinerv1.GlobalIngressIP{},
			&submarinerv1.Gateway{}, &mcsv1a1.ServiceExport{}),
		scheme:                   runtime.NewScheme(),
		pFilter:                  fakePF.New(),
		globalCIDR:               globalCIDR,
		localSubnets:             []string{},
		expectInstantiationError: false,
	}
	Expect(mcsv1a1.AddToScheme(t.scheme)).To(Succeed())
	Expect(submarinerv1.AddToScheme(t.scheme)).To(Succeed())
	Expect(corev1.AddToScheme(t.scheme)).To(Succeed())

	t.dynClient = dynamicfake.NewSimpleDynamicClient(t.scheme)
	fakeDynClient.AddBasicReactors(&t.dynClient.Fake)

	t.globalEgressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.GlobalEgressIP{})).
		Namespace(namespace)

	t.globalIngressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.GlobalIngressIP{})).
		Namespace(namespace)

	t.clusterGlobalEgressIPs = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.ClusterGlobalEgressIP{}))

	t.pods = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &corev1.Pod{}))

	t.endpoints = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &corev1.Endpoints{})).Namespace(namespace)

	t.services = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &corev1.Service{})).Namespace(namespace)

	t.serviceExports = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &mcsv1a1.ServiceExport{})).Namespace(namespace)

	t.gateways = t.dynClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.Gateway{})).Namespace(namespace)

	var err error

	t.hostName, err = os.Hostname()
	Expect(err).To(Succeed())

	return t
}

func (t *testDriverBase) afterEach() {
	if t.controller != nil {
		t.controller.Stop()
	}
}

func (t *testDriverBase) initChains() {
	for _, chain := range []string{
		constants.SmGlobalnetIngressChain,
		constants.SmGlobalnetEgressChain,
		constants.SmGlobalnetEgressChainForPods,
		constants.SmGlobalnetEgressChainForHeadlessSvcPods,
		constants.SmGlobalnetEgressChainForHeadlessSvcEPs,
		constants.SmGlobalnetEgressChainForNamespace,
		constants.SmGlobalnetEgressChainForCluster,
		routeAgent.SmPostRoutingChain,
		constants.SmGlobalnetMarkChain,
	} {
		Expect(t.pFilter.CreateChainIfNotExists(packetfilter.TableTypeNAT, &packetfilter.Chain{
			Name: chain,
		})).To(Succeed())
	}
}

func (t *testDriverBase) verifyIPsReservedInPool(ips ...string) {
	if t.pool == nil {
		return
	}

	for _, ip := range ips {
		Expect(t.pool.Reserve(ip)).To(HaveOccurred(), "IP %s was not reserved", ip)
	}
}

func (t *testDriverBase) awaitIPsReleasedFromPool(ips ...string) {
	Eventually(func() error {
		return t.pool.Reserve(ips...)
	}, 3*time.Second).Should(Succeed())
}

func (t *testDriverBase) createGlobalEgressIP(egressIP *submarinerv1.GlobalEgressIP) {
	test.CreateResource(t.globalEgressIPs, egressIP)
}

func (t *testDriverBase) createClusterGlobalEgressIP(egressIP *submarinerv1.ClusterGlobalEgressIP) {
	test.CreateResource(t.clusterGlobalEgressIPs, egressIP)
}

func (t *testDriverBase) createGlobalIngressIP(ingressIP *submarinerv1.GlobalIngressIP) {
	test.CreateResource(t.globalIngressIPs, ingressIP)
}

//nolint:unparam // `name` always receives `globalEgressIPName`
func (t *testDriverBase) awaitGlobalEgressIPStatusAllocated(name string, expNumIPS int) {
	t.awaitEgressIPStatusAllocated(t.globalEgressIPs, name, expNumIPS)
}

func (t *testDriverBase) awaitClusterGlobalEgressIPStatusAllocated(expNumIPS int) {
	t.awaitEgressIPStatusAllocated(t.clusterGlobalEgressIPs, constants.ClusterGlobalEgressIPName, expNumIPS)
}

func (t *testDriverBase) createPod(p *corev1.Pod) *corev1.Pod {
	return test.CreateResource(t.pods.Namespace(p.Namespace), p)
}

func (t *testDriverBase) deletePod(p *corev1.Pod) {
	Expect(t.pods.Namespace(p.Namespace).Delete(context.TODO(), p.Name, metav1.DeleteOptions{})).To(Succeed())
}

func (t *testDriverBase) createEndpoints(ep *corev1.Endpoints) *corev1.Endpoints {
	test.CreateResource(t.endpoints, ep)
	return ep
}

func (t *testDriverBase) deleteEndpoints(ep *corev1.Endpoints) {
	err := t.endpoints.Delete(context.TODO(), ep.Name, metav1.DeleteOptions{})
	Expect(err).To(Succeed())
}

func (t *testDriverBase) updateEndpoints(ep *corev1.Endpoints) *corev1.Endpoints {
	test.UpdateResource(t.endpoints, ep)
	return ep
}

func (t *testDriverBase) createService(service *corev1.Service) *corev1.Service {
	test.CreateResource(t.services, service)
	return service
}

func (t *testDriverBase) createServiceExport(s *corev1.Service) {
	test.CreateResource(t.serviceExports, &mcsv1a1.ServiceExport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.GetName(),
			Namespace: s.GetNamespace(),
		},
	})
}

func (t *testDriverBase) createPFilterChain(table packetfilter.TableType, chain string) {
	_ = t.pFilter.CreateChainIfNotExists(table, &packetfilter.Chain{
		Name: chain,
	})
}

func (t *testDriverBase) getGlobalIngressIPStatus(name string) *submarinerv1.GlobalIngressIPStatus {
	status := &submarinerv1.GlobalIngressIPStatus{}
	getStatus(t.globalIngressIPs, name, status)

	return status
}

func (t *testDriverBase) createGateway(name, globalIP string) *submarinerv1.Gateway {
	gateway := &submarinerv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	addAnnotation(gateway, constants.SmGlobalIP, globalIP)

	return test.CreateResource(t.gateways, gateway)
}

func (t *testDriverBase) getGatewayGlobalIP(name string) string {
	obj, err := t.gateways.Get(context.TODO(), name, metav1.GetOptions{})
	Expect(err).To(Succeed())

	return obj.GetAnnotations()[constants.SmGlobalIP]
}

func (t *testDriverBase) awaitGatewayGlobalIP(oldIP string) string {
	var globalIP string

	Eventually(func() string {
		globalIP = t.getGatewayGlobalIP(t.hostName)
		return globalIP
	}, 5).ShouldNot(Or(BeEmpty(), Equal(oldIP)))

	Expect(isValidIPForCIDR(t.globalCIDR, globalIP)).To(BeTrue(), "Allocated global IP %q is not valid for CIDR %q",
		globalIP, t.globalCIDR)

	t.verifyIPsReservedInPool(globalIP)

	return globalIP
}

func (t *testDriverBase) ensureGatewayGlobalIP(name, ip string) {
	Consistently(func() string {
		return t.getGatewayGlobalIP(name)
	}, 500*time.Millisecond).Should(Equal(ip))
}

func addAnnotation(obj metav1.Object, key, value string) {
	if value == "" {
		return
	}

	annotations := obj.GetAnnotations()
	if annotations == nil {
		obj.SetAnnotations(map[string]string{})
	}

	obj.GetAnnotations()[key] = value
}

func getStatus(client dynamic.ResourceInterface, name string, status interface{}) {
	obj, err := client.Get(context.TODO(), name, metav1.GetOptions{})
	Expect(err).To(Succeed())

	statusObj, ok, err := unstructured.NestedMap(obj.Object, "status")
	Expect(err).To(Succeed())

	if !ok {
		return
	}

	Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(statusObj, status)).To(Succeed())
}

func getGlobalEgressIPStatus(client dynamic.ResourceInterface, name string) *submarinerv1.GlobalEgressIPStatus {
	status := &submarinerv1.GlobalEgressIPStatus{}
	getStatus(client, name, status)

	return status
}

func (t *testDriverBase) awaitEgressIPStatus(client dynamic.ResourceInterface, name string, expNumIPS int, expCond ...metav1.Condition) {
	t.awaitStatusConditions(client, name, expCond...)

	var status *submarinerv1.GlobalEgressIPStatus

	Eventually(func(g Gomega) {
		status = getGlobalEgressIPStatus(client, name)
		g.Expect(status.AllocatedIPs).To(HaveLen(expNumIPS))

		for _, ip := range status.AllocatedIPs {
			g.Expect(isValidIPForCIDR(t.globalCIDR, ip)).To(BeTrue(), "Allocated global IP %q is not valid for CIDR %q",
				ip, t.globalCIDR)
		}
	}).Should(Succeed())

	t.verifyIPsReservedInPool(status.AllocatedIPs...)
}

func (t *testDriverBase) awaitEgressIPStatusAllocated(client dynamic.ResourceInterface, name string, expNumIPS int) {
	t.awaitEgressIPStatus(client, name, expNumIPS, metav1.Condition{
		Type:   string(submarinerv1.GlobalEgressIPAllocated),
		Status: metav1.ConditionTrue,
	})
}

func (t *testDriverBase) awaitIngressIPStatus(name string, expCond ...metav1.Condition) {
	t.awaitStatusConditions(t.globalIngressIPs, name, expCond...)

	status := t.getGlobalIngressIPStatus(name)

	Expect(status.AllocatedIP).ToNot(BeEmpty())
	Expect(isValidIPForCIDR(t.globalCIDR, status.AllocatedIP)).To(BeTrue(), "Allocated global IP %q is not valid for CIDR %q",
		status.AllocatedIP, t.globalCIDR)

	t.verifyIPsReservedInPool(status.AllocatedIP)
}

func (t *testDriverBase) awaitIngressIPStatusAllocated(name string) {
	t.awaitIngressIPStatus(name, metav1.Condition{
		Type:   string(submarinerv1.GlobalEgressIPAllocated),
		Status: metav1.ConditionTrue,
	})
}

func (t *testDriverBase) awaitGlobalIngressIP(name string) *submarinerv1.GlobalIngressIP {
	return resource.MustFromUnstructured(test.AwaitResource(t.globalIngressIPs, name), &submarinerv1.GlobalIngressIP{})
}

func (t *testDriverBase) awaitService(name string) *corev1.Service {
	return resource.MustFromUnstructured(test.AwaitResource(t.services, name), &corev1.Service{})
}

func (t *testDriverBase) awaitNoService(name string) {
	test.AwaitNoResource(t.services, name)
}

func (t *testDriverBase) awaitEndpoints(name string) *corev1.Endpoints {
	return resource.MustFromUnstructured(test.AwaitResource(t.endpoints, name), &corev1.Endpoints{})
}

func (t *testDriverBase) awaitNoEndpoints(name string) {
	test.AwaitNoResource(t.endpoints, name)
}

func (t *testDriverBase) ensureNoEndpoints(name string) {
	testutil.EnsureNoResource(resource.ForDynamic(t.endpoints), name)
}

func (t *testDriverBase) awaitEndpointsHasIP(name, ip string) {
	Eventually(func() bool {
		obj, err := t.endpoints.Get(context.TODO(), name, metav1.GetOptions{})
		Expect(err).To(Succeed())

		ep := &corev1.Endpoints{}
		Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, ep)).To(Succeed())

		for _, subset := range ep.Subsets {
			for _, address := range subset.Addresses {
				if address.IP == ip {
					return true
				}
			}
		}

		return false
	}, 5).Should(BeTrue())
}

func (t *testDriverBase) awaitHeadlessGlobalIngressIP(svcName, podName string) *submarinerv1.GlobalIngressIP {
	ingressIP := getGlobalIngressIP(t, podName, func(gip *submarinerv1.GlobalIngressIP, name string) bool {
		return gip.Spec.PodRef != nil && gip.Spec.PodRef.Name == name
	})

	Expect(ingressIP.Spec.Target).To(Equal(submarinerv1.HeadlessServicePod))
	Expect(ingressIP.Spec.ServiceRef).ToNot(BeNil())
	Expect(ingressIP.Spec.ServiceRef.Name).To(Equal(svcName))

	return ingressIP
}

func (t *testDriverBase) awaitHeadlessGlobalIngressIPForEP(svcName, endpointsName string) *submarinerv1.GlobalIngressIP {
	// Intentionally comparing ServiceRef.Name and endpointsName (they should be the same)
	ingressIP := getGlobalIngressIP(t, endpointsName, func(gip *submarinerv1.GlobalIngressIP, name string) bool {
		return gip.Spec.ServiceRef != nil && gip.Spec.ServiceRef.Name == name
	})

	Expect(ingressIP.Spec.Target).To(Equal(submarinerv1.HeadlessServiceEndpoints))
	Expect(ingressIP.Spec.ServiceRef).ToNot(BeNil())
	Expect(ingressIP.Spec.ServiceRef.Name).To(Equal(svcName))

	return ingressIP
}

func getGlobalIngressIP(t *testDriverBase, name string,
	compFunc func(*submarinerv1.GlobalIngressIP, string) bool,
) *submarinerv1.GlobalIngressIP {
	var ingressIP *submarinerv1.GlobalIngressIP

	Eventually(func() bool {
		list, _ := t.globalIngressIPs.List(context.TODO(), metav1.ListOptions{})
		for i := range list.Items {
			gip := &submarinerv1.GlobalIngressIP{}
			Expect(runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[i].Object, gip)).To(Succeed())

			if compFunc(gip, name) {
				ingressIP = gip
				return true
			}
		}

		return false
	}, 5).Should(BeTrue(), "GlobalIngressIP not found")

	return ingressIP
}

func (t *testDriverBase) awaitNoGlobalIngressIP(name string) {
	test.AwaitNoResource(t.globalIngressIPs, name)
}

func (t *testDriverBase) ensureNoGlobalIngressIP(name string) {
	testutil.EnsureNoResource(resource.ForDynamic(t.globalIngressIPs), name)
}

func (t *testDriverBase) ensureNoGlobalIngressIPs() {
	Consistently(func() []unstructured.Unstructured {
		list, _ := t.globalIngressIPs.List(context.TODO(), metav1.ListOptions{})
		return list.Items
	}, time.Millisecond*300).Should(BeEmpty())
}

func (t *testDriverBase) awaitStatusConditions(client dynamic.ResourceInterface, name string, expCond ...metav1.Condition) {
	if len(expCond) == 0 {
		return
	}

	obj := test.AwaitResource(client, name)

	mapping, err := t.restMapper.RESTMapping(obj.GetObjectKind().GroupVersionKind().GroupKind(),
		obj.GetObjectKind().GroupVersionKind().Version)
	Expect(err).To(Succeed())

	Eventually(func(g Gomega) {
		var actualConditions []metav1.Condition

		actions := t.dynClient.Fake.Actions()
		for i := range actions {
			if actions[i].GetResource().Resource != mapping.Resource.Resource || actions[i].GetVerb() != "update" {
				continue
			}

			update := actions[i].(k8stesting.UpdateAction)
			objMeta := resource.MustToMeta(update.GetObject())

			if objMeta.GetName() != name {
				continue
			}

			conditions := util.ConditionsFromUnstructured(update.GetObject().(*unstructured.Unstructured), "status", "conditions")
			for j := range conditions {
				actualConditions, _ = slices.AppendIfNotPresent(actualConditions, conditions[j], func(c metav1.Condition) string {
					return resource.ToJSON(c)
				})
			}
		}

		for i := range expCond {
			index := slices.IndexOf(actualConditions, expCond[i].Type, func(c metav1.Condition) string {
				return c.Type
			})

			g.Expect(index).To(BeNumerically(">=", 0), "Missing condition %s", resource.ToJSON(expCond[i]))

			actual := actualConditions[index]
			actualConditions = actualConditions[index+1:]

			g.Expect(actual.Status).To(Equal(expCond[i].Status), "Status for condition %q", expCond[i].Type)
			g.Expect(actual.LastTransitionTime).To(Not(BeNil()), "LastTransitionTime is nil for condition %q", expCond[i].Type)
			g.Expect(actual.Message).To(Not(BeEmpty()), "Message is empty for condition %q", expCond[i].Type)

			if expCond[i].Reason != "" {
				g.Expect(actual.Reason).To(Equal(expCond[i].Reason), "Reason for condition %q", expCond[i].Type)
			} else {
				g.Expect(actual.Reason).To(Not(BeEmpty()), "Reason is empty for condition %q", expCond[i].Type)
			}
		}
	}).Should(Succeed())
}

//nolint:unparam // `name` always receives `globalEgressIPName` (`"east-region")
func newGlobalEgressIP(name string, numberOfIPs *int, podSelector *metav1.LabelSelector) *submarinerv1.GlobalEgressIP {
	return &submarinerv1.GlobalEgressIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: submarinerv1.GlobalEgressIPSpec{
			NumberOfIPs: numberOfIPs,
			PodSelector: podSelector,
		},
	}
}

func newClusterGlobalEgressIP(name string, numIPs int) *submarinerv1.ClusterGlobalEgressIP {
	return &submarinerv1.ClusterGlobalEgressIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: submarinerv1.ClusterGlobalEgressIPSpec{
			NumberOfIPs: &numIPs,
		},
	}
}

func newPod(namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginx",
			Namespace: namespace,
		},
		Status: corev1.PodStatus{
			PodIP: "1.2.3.4",
		},
	}
}

func newClusterIPService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  "1.2.3.4",
			Type:       corev1.ServiceTypeClusterIP,
			IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
			Ports: []corev1.ServicePort{{
				Name:       serviceName,
				Port:       int32(8080),
				TargetPort: intstr.FromInt32(8080),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

func newGlobalnetInternalService(svcName string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{{
				Name:       serviceName,
				Port:       int32(8080),
				TargetPort: intstr.FromInt(8080),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
}

func newHeadlessService() *corev1.Service {
	return toHeadlessService(newClusterIPService())
}

func toHeadlessService(s *corev1.Service) *corev1.Service {
	s.Spec.ClusterIP = corev1.ClusterIPNone
	s.Spec.Selector = map[string]string{"pod": s.Name}

	return s
}

func newHeadlessServicePod(svcName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      string(uuid.NewUUID()),
			Namespace: namespace,
			Labels:    map[string]string{"pod": svcName},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			PodIP: "172.45.4.3",
		},
	}
}

func newHeadlessServiceEndpoints(svcName string) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: namespace,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: "172.45.5.6"},
				},
				Ports: []corev1.EndpointPort{
					{
						Name:     "http",
						Port:     int32(80),
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}
}

func newServiceWithoutSelector() *corev1.Service {
	return toServiceWithoutSelector(newClusterIPService())
}

func toServiceWithoutSelector(s *corev1.Service) *corev1.Service {
	s.Spec.Selector = map[string]string{}

	return s
}

func newHeadlessServiceWithoutSelector() *corev1.Service {
	return toHeadlessServiceWithoutSelector(newClusterIPService())
}

func toHeadlessServiceWithoutSelector(s *corev1.Service) *corev1.Service {
	s.Spec.ClusterIP = corev1.ClusterIPNone
	s.Spec.Selector = map[string]string{}

	return s
}

func newDefaultEndpoints(svcName string) *corev1.Endpoints {
	return newEndpoints(svcName, "172.45.5.6", map[string]string{})
}

func newEndpoints(svcName, ip string, labels map[string]string) *corev1.Endpoints {
	return &corev1.Endpoints{
		ObjectMeta: metav1.ObjectMeta{
			Name:      svcName,
			Namespace: namespace,
			Labels:    labels,
		},
		Subsets: []corev1.EndpointSubset{
			{
				Addresses: []corev1.EndpointAddress{
					{IP: ip},
				},
				Ports: []corev1.EndpointPort{
					{
						Name:     "http",
						Port:     int32(80),
						Protocol: corev1.ProtocolTCP,
					},
				},
			},
		},
	}
}

func isValidIPForCIDR(cidr, ip string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())

	return ipnet.Contains(net.ParseIP(ip))
}

func getSNATAddress(ips ...string) string {
	targetSNATIP := ips[0]
	if len(ips) > 1 {
		targetSNATIP += "-" + ips[len(ips)-1]
	}

	return targetSNATIP
}
