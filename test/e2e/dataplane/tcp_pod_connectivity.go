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

package dataplane

import (
	. "github.com/onsi/ginkgo/v2"
	"github.com/submariner-io/shipyard/test/e2e/framework"
	"github.com/submariner-io/shipyard/test/e2e/tcp"
	subFramework "github.com/submariner-io/submariner/test/e2e/framework"
	k8snet "k8s.io/utils/net"
)

const TestLabel = "dataplane"

func GetActualIPFamilies(fromType, toType framework.IPFamilyType) []k8snet.IPFamily {
	var families []k8snet.IPFamily

	if (fromType == framework.SingleStackIPv4 || fromType == framework.DualStack) &&
		(toType == framework.SingleStackIPv4 || toType == framework.DualStack) {
		families = append(families, k8snet.IPv4)
	}

	if (fromType == framework.SingleStackIPv6 || fromType == framework.DualStack) &&
		(toType == framework.SingleStackIPv6 || toType == framework.DualStack) {
		families = append(families, k8snet.IPv6)
	}

	return families
}

var _ = Describe("Basic TCP connectivity tests across clusters without discovery", Label(TestLabel), func() {
	f := framework.NewFramework("dataplane-conn-nd")

	var (
		toEndpointType         tcp.EndpointType
		networking             framework.NetworkingType
		fromCluster, toCluster framework.ClusterIndex
		supportedFamilies      []k8snet.IPFamily
	)

	BeforeEach(func() {
		supportedFamilies = GetActualIPFamilies(f.DetermineIPFamilyType(framework.ClusterA), f.DetermineIPFamilyType(framework.ClusterB))
	})

	verifyInteraction := func(fromClusterScheduling, toClusterScheduling framework.NetworkPodScheduling) {
		It("should have sent the expected data from the pod to the other pod", func() {
			if framework.TestContext.GlobalnetEnabled {
				framework.Skipf("Globalnet enabled, skipping the test...")
				return
			}

			if !subFramework.CanExecuteNonGatewayConnectivityTest(fromClusterScheduling, toClusterScheduling,
				framework.ClusterA, framework.ClusterB) {
				return
			}

			for _, ipFamily := range supportedFamilies {
				tcp.RunConnectivityTest(&tcp.ConnectivityTestParams{
					Framework:             f,
					ToEndpointType:        toEndpointType,
					Networking:            networking,
					FromCluster:           fromCluster,
					FromClusterScheduling: fromClusterScheduling,
					ToCluster:             toCluster,
					ToClusterScheduling:   toClusterScheduling,
					IPFamily:              ipFamily,
				})
			}
		})
	}

	When("a pod connects via TCP to a remote pod", func() {
		BeforeEach(func() {
			toEndpointType = tcp.PodIP
			networking = framework.PodNetworking
			fromCluster = framework.ClusterA
			toCluster = framework.ClusterB
		})

		When("the pod is not on a gateway and the remote pod is not on a gateway", Label(framework.BasicTestLabel), func() {
			verifyInteraction(framework.NonGatewayNode, framework.NonGatewayNode)
		})

		When("the pod is not on a gateway and the remote pod is on a gateway", func() {
			verifyInteraction(framework.NonGatewayNode, framework.GatewayNode)
		})

		When("the pod is on a gateway and the remote pod is not on a gateway", func() {
			verifyInteraction(framework.GatewayNode, framework.NonGatewayNode)
		})

		When("the pod is on a gateway and the remote pod is on a gateway", Label(framework.BasicTestLabel), func() {
			verifyInteraction(framework.GatewayNode, framework.GatewayNode)
		})
	})

	When("a pod connects via TCP to a remote service", func() {
		BeforeEach(func() {
			toEndpointType = tcp.ServiceIP
			networking = framework.PodNetworking
			fromCluster = framework.ClusterA
			toCluster = framework.ClusterB
		})

		When("the pod is not on a gateway and the remote service is not on a gateway", Label(framework.BasicTestLabel), func() {
			verifyInteraction(framework.NonGatewayNode, framework.NonGatewayNode)
		})

		When("the pod is not on a gateway and the remote service is on a gateway", func() {
			verifyInteraction(framework.NonGatewayNode, framework.GatewayNode)
		})

		When("the pod is on a gateway and the remote service is not on a gateway", func() {
			verifyInteraction(framework.GatewayNode, framework.NonGatewayNode)
		})

		When("the pod is on a gateway and the remote service is on a gateway", Label(framework.BasicTestLabel), func() {
			verifyInteraction(framework.GatewayNode, framework.GatewayNode)
		})
	})

	When("a pod with HostNetworking connects via TCP to a remote pod", func() {
		BeforeEach(func() {
			toEndpointType = tcp.PodIP
			networking = framework.HostNetworking
			fromCluster = framework.ClusterA
			toCluster = framework.ClusterB
		})

		When("the pod is not on a gateway and the remote pod is not on a gateway", func() {
			verifyInteraction(framework.NonGatewayNode, framework.NonGatewayNode)
		})

		When("the pod is on a gateway and the remote pod is not on a gateway", func() {
			verifyInteraction(framework.GatewayNode, framework.NonGatewayNode)
		})
	})

	When("a pod connects via TCP to a remote pod in reverse direction", func() {
		BeforeEach(func() {
			toEndpointType = tcp.PodIP
			networking = framework.PodNetworking
			fromCluster = framework.ClusterB
			toCluster = framework.ClusterA
		})

		When("the pod is not on a gateway and the remote pod is not on a gateway", func() {
			verifyInteraction(framework.NonGatewayNode, framework.NonGatewayNode)
		})
	})
})
