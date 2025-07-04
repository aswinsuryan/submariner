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

package redundancy

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/shipyard/test/e2e/framework"
	"github.com/submariner-io/shipyard/test/e2e/tcp"
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	subDataplane "github.com/submariner-io/submariner/test/e2e/dataplane"
	subFramework "github.com/submariner-io/submariner/test/e2e/framework"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	k8snet "k8s.io/utils/net"
)

const (
	gatewayStatusLabel  = "gateway.submariner.io/status"
	gatewayStatusActive = "active"
	gatewayNodeLabel    = "gateway.submariner.io/node"
	TestLabel           = "redundancy"
)

var _ = Describe("Gateway fail-over tests", Label(TestLabel), func() {
	f := subFramework.NewFramework("gateway-redundancy")

	var supportedFamilies []k8snet.IPFamily

	BeforeEach(func() {
		supportedFamilies = subDataplane.GetActualIPFamilies(
			f.DetermineIPFamilyType(framework.ClusterA),
			f.DetermineIPFamilyType(framework.ClusterB),
		)
	})

	AfterEach(f.GatewayCleanup)

	When("one gateway node is configured and the submariner gateway pod fails", func() {
		It("should start a new submariner gateway pod and be able to connect from another cluster", func() {
			testGatewayPodRestartScenario(f, supportedFamilies)
		})
	})

	When("multiple gateway nodes are configured and fail-over is initiated", func() {
		It("should activate the passive gateway and be able to connect from another cluster", func() {
			testGatewayFailOverScenario(f, supportedFamilies)
		})
	})
})

func testGatewayPodRestartScenario(f *subFramework.Framework, supportedFamilies []k8snet.IPFamily) {
	framework.By(fmt.Sprintln("Sanity check - find a cluster with only one gateway node"))

	primaryCluster := subFramework.FindClusterWithSingleGateway()
	if primaryCluster == -1 {
		framework.Skipf("The test requires single gateway node in one of the test clusters...")
	}

	secondaryCluster := framework.ClusterIndex(framework.FindOtherClusterIndex(int(primaryCluster)))

	primaryClusterName := framework.TestContext.ClusterIDs[primaryCluster]
	secondaryClusterName := framework.TestContext.ClusterIDs[secondaryCluster]

	framework.By(fmt.Sprintf("Detected primary cluster %q with single gateway node", primaryClusterName))
	framework.By(fmt.Sprintf("Detected secondary cluster %q", secondaryClusterName))

	gatewayNodes := framework.FindGatewayNodes(primaryCluster)
	Expect(gatewayNodes).To(HaveLen(1), fmt.Sprintf("Expected only one gateway node on %q", primaryClusterName))
	framework.By(fmt.Sprintf("Found gateway on node %q on %q", gatewayNodes[0].Name, primaryClusterName))

	gatewayPod := f.AwaitSubmarinerGatewayPod(primaryCluster)
	framework.By(fmt.Sprintf("Found submariner gateway pod %q on %q, checking node and HA status labels", gatewayPod.Name, primaryClusterName))

	Expect(gatewayPod.Labels[gatewayStatusLabel]).To(Equal(gatewayStatusActive))
	Expect(gatewayPod.Labels[gatewayNodeLabel]).To(Equal(gatewayNodes[0].Name))

	framework.By(fmt.Sprintf("Ensuring that the gateway reports as active on %q", primaryClusterName))

	submEndpoint := f.AwaitSubmarinerEndpoint(primaryCluster, subFramework.NoopCheckEndpoint)
	activeGateway := f.AwaitGatewayFullyConnected(primaryCluster, resource.EnsureValidName(submEndpoint.Spec.Hostname))

	framework.By(fmt.Sprintf("Deleting submariner gateway pod %q", gatewayPod.Name))
	f.DeletePod(primaryCluster, gatewayPod.Name, framework.TestContext.SubmarinerNamespace)

	newGatewayPod := AwaitNewSubmarinerGatewayPod(f, primaryCluster, gatewayPod.ObjectMeta.UID)
	framework.By(fmt.Sprintf("Found new submariner gateway pod %q", newGatewayPod.Name))

	framework.By(fmt.Sprintf("Waiting for the gateway to be up and connected %q", newGatewayPod.Name))
	AwaitNewSubmarinerGatewayFullyConnected(f, primaryCluster, activeGateway.Name, activeGateway.UID)

	framework.By(fmt.Sprintf("Verifying TCP connectivity from gateway node on %q to gateway node on %q", secondaryClusterName,
		primaryClusterName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           secondaryCluster,
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             primaryCluster,
			ToClusterScheduling:   framework.GatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}

	if !subFramework.CanExecuteNonGatewayConnectivityTest(framework.NonGatewayNode, framework.NonGatewayNode,
		secondaryCluster, primaryCluster) {
		return
	}

	framework.By(fmt.Sprintf("Verifying TCP connectivity from non-gateway node on %q to non-gateway node on %q",
		secondaryClusterName, primaryClusterName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           secondaryCluster,
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             primaryCluster,
			ToClusterScheduling:   framework.NonGatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}
}

func AwaitNewSubmarinerGatewayPod(f *subFramework.Framework, cluster framework.ClusterIndex, prevPodUID types.UID) *v1.Pod {
	return framework.AwaitUntil("await new submariner gateway pod", func() (interface{}, error) {
		pod := f.AwaitSubmarinerGatewayPod(cluster)
		return pod, nil
	}, func(result interface{}) (bool, string, error) {
		pod := result.(*v1.Pod)
		if pod.ObjectMeta.UID != prevPodUID {
			return true, "", nil
		}

		return false, fmt.Sprintf("Expecting new gateway pod (UID %q matches previous instance)", prevPodUID), nil
	}).(*v1.Pod)
}

func AwaitNewSubmarinerGatewayFullyConnected(f *subFramework.Framework, cluster framework.ClusterIndex, name string,
	prevPodUID types.UID,
) *subv1.Gateway {
	return framework.AwaitUntil("await new submariner gateway", func() (interface{}, error) {
		return f.AwaitGatewayFullyConnected(cluster, resource.EnsureValidName(name)), nil
	}, func(result interface{}) (bool, string, error) {
		gw := result.(*subv1.Gateway)
		if gw.ObjectMeta.UID != prevPodUID {
			return true, "", nil
		}

		return false, fmt.Sprintf("Expecting new gateway (UID %q matches previous instance)", prevPodUID), nil
	}).(*subv1.Gateway)
}

func defaultEndpointType() tcp.EndpointType {
	if framework.TestContext.GlobalnetEnabled {
		return tcp.GlobalIP
	}

	return tcp.PodIP
}

func testGatewayFailOverScenario(f *subFramework.Framework, supportedFamilies []k8snet.IPFamily) {
	primaryCluster := f.FindClusterWithMultipleGateways()

	if primaryCluster == -1 {
		framework.Skipf("No cluster found with multiple gateways, skipping the fail-over test...")
		return
	}

	secondaryCluster := framework.FindOtherClusterIndex(primaryCluster)

	clusterAName := framework.TestContext.ClusterIDs[primaryCluster]
	clusterBName := framework.TestContext.ClusterIDs[secondaryCluster]

	framework.By(fmt.Sprintf("Found two gateway nodes on %q", clusterAName))

	initialGWPod := f.AwaitActiveGatewayPod(framework.ClusterIndex(primaryCluster), nil)
	Expect(initialGWPod).ToNot(BeNil(), "Did not find an active gateway pod")

	framework.By(fmt.Sprintf("Ensure active gateway node %q has established connections", initialGWPod.Name))

	submEndpoint := f.AwaitSubmarinerEndpoint(framework.ClusterIndex(primaryCluster), subFramework.NoopCheckEndpoint)
	framework.By(fmt.Sprintf("Found submariner endpoint for %q: %#v", clusterAName, submEndpoint))

	gwConnection := f.AwaitGatewayWithStatus(framework.ClusterIndex(primaryCluster),
		resource.EnsureValidName(submEndpoint.Spec.Hostname), subv1.HAStatusActive)
	Expect(gwConnection.Status.Connections).NotTo(BeEmpty(), "The active gateway must have established connections")

	framework.By("Performing fail-over to passive gateway")
	f.DoFailover(context.TODO(), framework.ClusterIndex(primaryCluster), initialGWPod.Spec.NodeName, initialGWPod.Name)

	newGWPod := f.AwaitActiveGatewayPod(framework.ClusterIndex(primaryCluster), func(pod *v1.Pod) bool {
		return pod.Spec.NodeName != initialGWPod.Spec.NodeName
	})

	Expect(newGWPod).ToNot(BeNil(), "Did not find a new active gateway pod running on a different node")
	framework.By(fmt.Sprintf("Found new submariner gateway pod %q", newGWPod.Name))

	// Verify a new Endpoint instance is created by the new gateway instance. This is a bit whitebox but it's a sanity check
	// and also gives it a bit more of a cushion to avoid premature timeout in the connectivity test.
	newSubmEndpoint := f.AwaitNewSubmarinerEndpoint(framework.ClusterIndex(primaryCluster), submEndpoint.ObjectMeta.UID)
	framework.By(fmt.Sprintf("Found new submariner endpoint for %q: %#v", clusterAName, newSubmEndpoint))

	framework.By(fmt.Sprintf("Waiting for the new pod %q to report as fully connected", newGWPod.Name))
	f.AwaitGatewayFullyConnected(framework.ClusterIndex(primaryCluster),
		resource.EnsureValidName(resource.EnsureValidName(newSubmEndpoint.Spec.Hostname)))

	framework.By(fmt.Sprintf("Waiting for the previous submariner endpoint %q to be removed on %q", newGWPod.Name, clusterBName))
	f.AwaitSubmarinerEndpointRemoved(framework.ClusterIndex(secondaryCluster), submEndpoint.Name)

	framework.By(fmt.Sprintf("Verifying TCP connectivity from gateway node on %q to gateway node on %q", clusterBName, clusterAName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           framework.ClusterIndex(secondaryCluster),
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             framework.ClusterIndex(primaryCluster),
			ToClusterScheduling:   framework.GatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}

	if !subFramework.CanExecuteNonGatewayConnectivityTest(framework.NonGatewayNode, framework.NonGatewayNode,
		framework.ClusterIndex(secondaryCluster), framework.ClusterIndex(primaryCluster)) {
		return
	}

	framework.By(fmt.Sprintf("Verifying TCP connectivity from non-gateway node on %q to non-gateway node on %q", clusterBName, clusterAName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           framework.ClusterIndex(secondaryCluster),
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             framework.ClusterIndex(primaryCluster),
			ToClusterScheduling:   framework.NonGatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}
}
