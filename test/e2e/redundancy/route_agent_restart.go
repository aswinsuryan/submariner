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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	"github.com/submariner-io/shipyard/test/e2e/framework"
	"github.com/submariner-io/shipyard/test/e2e/tcp"
	subDataplane "github.com/submariner-io/submariner/test/e2e/dataplane"
	subFramework "github.com/submariner-io/submariner/test/e2e/framework"
	v1 "k8s.io/api/core/v1"
	k8snet "k8s.io/utils/net"
)

var _ = Describe("Route Agent restart tests", Label(TestLabel), func() {
	f := subFramework.NewFramework("route-agent-restart")

	var supportedFamilies []k8snet.IPFamily

	BeforeEach(func() {
		supportedFamilies = subDataplane.GetActualIPFamilies(
			f.DetermineIPFamilyType(framework.ClusterA),
			f.DetermineIPFamilyType(framework.ClusterB),
		)
	})

	When("a route agent pod running on a gateway node is restarted", func() {
		It("should start a new route agent pod and be able to connect from another cluster", func() {
			testRouteAgentRestart(f, true, supportedFamilies)
		})
	})

	When("a route agent pod running on a non-gateway node is restarted", func() {
		It("should start a new route agent pod and be able to connect from another cluster", func() {
			testRouteAgentRestart(f, false, supportedFamilies)
		})
	})
})

func testRouteAgentRestart(f *subFramework.Framework, onGateway bool, supportedFamilies []k8snet.IPFamily) {
	clusterAName := framework.TestContext.ClusterIDs[framework.ClusterA]
	clusterBName := framework.TestContext.ClusterIDs[framework.ClusterB]

	var nodes []v1.Node
	if onGateway {
		nodes = framework.FindGatewayNodes(framework.ClusterA)
	} else {
		nodes = framework.FindNonGatewayNodes(framework.ClusterA)
	}

	if len(nodes) == 0 && !onGateway {
		framework.Skipf("Skipping the test as cluster %q doesn't have any suitable non-gateway nodes...", clusterAName)
		return
	}

	framework.By(fmt.Sprintf("Found node %q on %q", nodes[0].Name, clusterAName))
	node := nodes[0]

	routeAgentPod := f.AwaitRouteAgentPodOnNode(framework.ClusterA, node.Name, "")
	framework.By(fmt.Sprintf("Found route agent pod %q on node %q", routeAgentPod.Name, node.Name))

	framework.By(fmt.Sprintf("Deleting route agent pod %q", routeAgentPod.Name))
	f.DeletePod(framework.ClusterA, routeAgentPod.Name, framework.TestContext.SubmarinerNamespace)

	newRouteAgentPod := f.AwaitRouteAgentPodOnNode(framework.ClusterA, node.Name, routeAgentPod.UID)
	framework.By(fmt.Sprintf("Found new route agent pod %q on node %q", newRouteAgentPod.Name, node.Name))

	framework.By(fmt.Sprintf("Verifying TCP connectivity from gateway node on %q to gateway node on %q", clusterBName, clusterAName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           framework.ClusterB,
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             framework.ClusterA,
			ToClusterScheduling:   framework.GatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}

	framework.By(fmt.Sprintf("Verifying TCP connectivity from non-gateway node on %q to non-gateway node on %q", clusterBName, clusterAName))

	for _, ipFamily := range supportedFamilies {
		subFramework.VerifyDatapathConnectivity(&tcp.ConnectivityTestParams{
			Framework:             f.Framework,
			FromCluster:           framework.ClusterB,
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             framework.ClusterA,
			ToClusterScheduling:   framework.NonGatewayNode,
			ToEndpointType:        defaultEndpointType(),
			IPFamily:              ipFamily,
		}, subFramework.GetGlobalnetEgressParams(subFramework.ClusterSelector))
	}
}
