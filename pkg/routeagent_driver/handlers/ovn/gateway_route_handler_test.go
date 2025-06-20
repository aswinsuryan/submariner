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

package ovn_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/admiral/pkg/fake"
	"github.com/submariner-io/admiral/pkg/test"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/event/testing"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/ovn"
	k8snet "k8s.io/utils/net"
)

var _ = Describe("GatewayRouteHandler", func() {
	t := newTestDriver()

	JustBeforeEach(func() {
		t.Start(ovn.NewGatewayRouteHandler(k8snet.IPv4, t.submClient))
	})

	awaitGatewayRoute := func(ep *submarinerv1.Endpoint) {
		gwRoute := test.AwaitResource(ovn.GatewayResourceInterface(t.submClient, testing.Namespace), ep.Spec.ClusterID)
		Expect(gwRoute.RoutePolicySpec.RemoteCIDRs).To(Equal(ep.Spec.Subnets))
		Expect(gwRoute.RoutePolicySpec.NextHops).To(Equal([]string{t.mgmntIntfIP}))
	}

	When("a remote Endpoint is created and deleted on the gateway", func() {
		JustBeforeEach(func() {
			t.CreateLocalHostEndpoint()
		})

		It("should create/delete GatewayRoutes for both IP families", func() {
			endpointV4 := t.CreateEndpoint(testing.NewEndpoint("remote-cluster-v4", "host", "192.0.4.0/24"))
			endpointV6 := t.CreateEndpoint(testing.NewEndpoint("remote-cluster-v6", "host", "192.0.4.0/24", "fd00:100::/64"))

			awaitGatewayRoute(endpointV4)
			awaitGatewayRoute(endpointV6)

			t.DeleteEndpoint(endpointV4.Name)
			t.DeleteEndpoint(endpointV6.Name)

			test.AwaitNoResource(ovn.GatewayResourceInterface(t.submClient, testing.Namespace), endpointV4.Spec.ClusterID)
			test.AwaitNoResource(ovn.GatewayResourceInterface(t.submClient, testing.Namespace), endpointV6.Spec.ClusterID)
		})

		Context("and the GatewayRoute operations initially fail", func() {
			JustBeforeEach(func() {
				r := fake.NewFailingReactorForResource(&t.submClient.Fake, "gatewayroutes")
				r.SetResetOnFailure(true)
				r.SetFailOnCreate(errors.New("mock GatewayRoute create error"))
				r.SetFailOnDelete(errors.New("mock GatewayRoute delete error"))
			})

			It("should eventually create/delete a GatewayRoute", func() {
				endpoint := t.CreateEndpoint(testing.NewEndpoint("remote-cluster1", "host", "192.0.4.0/24"))
				awaitGatewayRoute(endpoint)

				t.DeleteEndpoint(endpoint.Name)
				test.AwaitNoResource(ovn.GatewayResourceInterface(t.submClient, testing.Namespace), endpoint.Spec.ClusterID)
			})
		})
	})

	Context("on transition to gateway", func() {
		It("should create GatewayRoutes for all remote Endpoints", func() {
			endpoint := t.CreateEndpoint(testing.NewEndpoint("remote-cluster1", "host", "192.0.4.0/24"))
			test.EnsureNoResource(ovn.GatewayResourceInterface(t.submClient, testing.Namespace), endpoint.Spec.ClusterID)

			localEndpoint := t.CreateLocalHostEndpoint()
			awaitGatewayRoute(endpoint)

			t.DeleteEndpoint(localEndpoint.Name)

			t.submClient.Fake.ClearActions()
			t.CreateLocalHostEndpoint()
			test.EnsureNoActionsForResource(&t.submClient.Fake, "gatewayroutes", "create")
		})
	})
})
