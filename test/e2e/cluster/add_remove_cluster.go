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

package cluster

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/shipyard/test/e2e/framework"
	"github.com/submariner-io/shipyard/test/e2e/tcp"
)

var _ = PDescribe("[expansion] Test expanding/shrinking an existing cluster fleet", func() {
	f := framework.NewFramework("add-remove-cluster")

	It("Should be able to add and remove third cluster", func() {
		clusterAName := framework.TestContext.ClusterIDs[framework.ClusterA]
		clusterBName := framework.TestContext.ClusterIDs[framework.ClusterB]
		clusterCName := framework.TestContext.ClusterIDs[framework.ClusterC]

		framework.By(fmt.Sprintf("Verifying no GW nodes are present on cluster %q", clusterCName))
		gatewayNode := framework.FindGatewayNodes(framework.ClusterC)
		Expect(gatewayNode).To(BeEmpty(), fmt.Sprintf("Expected no gateway node on %q", framework.ClusterC))

		framework.By(fmt.Sprintf("Verifying that a pod in cluster %q cannot connect to a pod in cluster %q", clusterAName, clusterCName))
		tcp.RunNoConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			FromCluster:           framework.ClusterA,
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.NonGatewayNode,
		})

		framework.By(fmt.Sprintf("Verifying that a pod in cluster %q cannot connect to a service in cluster %q", clusterBName, clusterCName))
		tcp.RunNoConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			ToEndpointType:        tcp.ServiceIP,
			FromCluster:           framework.ClusterB,
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.NonGatewayNode,
		})

		nonGatewayNodes := framework.FindNonGatewayNodes(framework.ClusterC)
		Expect(nonGatewayNodes).ToNot(BeEmpty(), fmt.Sprintf("No non-gateway nodes found on %q", clusterCName))
		nonGatewayNode := nonGatewayNodes[0].Name
		framework.By(fmt.Sprintf("Adding cluster %q by setting the gateway label on node %q", clusterCName, nonGatewayNode))
		f.SetGatewayLabelOnNode(context.TODO(), framework.ClusterC, nonGatewayNode, true)

		gatewayPod := f.AwaitSubmarinerGatewayPod(framework.ClusterC)
		framework.By(fmt.Sprintf("Found submariner gateway pod %q on %q", gatewayPod.Name, clusterCName))

		framework.By("Checking connectivity between clusters")
		tcp.RunConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			FromCluster:           framework.ClusterB,
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.GatewayNode,
		})

		tcp.RunConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			ToEndpointType:        tcp.ServiceIP,
			FromCluster:           framework.ClusterA,
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.NonGatewayNode,
		})

		framework.By(fmt.Sprintf("Removing cluster %q by unsetting the gateway label and deleting submariner gateway pod %q",
			clusterCName, gatewayPod.Name))
		f.SetGatewayLabelOnNode(context.TODO(), framework.ClusterC, nonGatewayNode, false)
		f.DeletePod(framework.ClusterC, gatewayPod.Name, framework.TestContext.SubmarinerNamespace)

		framework.By(fmt.Sprintf("Verifying that a pod in cluster %q cannot connect to a service in cluster %q", clusterAName, clusterCName))
		tcp.RunNoConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			FromCluster:           framework.ClusterA,
			FromClusterScheduling: framework.GatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.NonGatewayNode,
		})

		framework.By(fmt.Sprintf("Verifying that a pod in cluster %q cannot connect to a pod in cluster %q", clusterBName, clusterCName))
		tcp.RunNoConnectivityTest(&tcp.ConnectivityTestParams{
			Framework:             f,
			ToEndpointType:        tcp.ServiceIP,
			FromCluster:           framework.ClusterB,
			FromClusterScheduling: framework.NonGatewayNode,
			ToCluster:             framework.ClusterC,
			ToClusterScheduling:   framework.NonGatewayNode,
		})
	})
})
