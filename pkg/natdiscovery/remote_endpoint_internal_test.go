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

package natdiscovery

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	k8snet "k8s.io/utils/net"
)

var _ = Describe("remoteEndpointNAT", func() {
	var (
		rnat           *remoteEndpointNAT
		remoteEndpoint *submarinerv1.Endpoint
	)

	BeforeEach(func() {
		remoteEndpoint = &submarinerv1.Endpoint{
			Spec: submarinerv1.EndpointSpec{
				CableName:     "cable-east",
				ClusterID:     "east",
				PublicIPs:     []string{"10.3.3.3"},
				PrivateIPs:    []string{"1.2.3.4"},
				Subnets:       []string{"11.0.0.0/16"},
				NATEnabled:    true,
				BackendConfig: map[string]string{},
			},
		}

		rnat = newRemoteEndpointNAT(remoteEndpoint, k8snet.IPv4)
	})

	When("first created", func() {
		It("shouldCheck should return true", func() {
			Expect(rnat.shouldCheck()).To(BeTrue())
		})
	})

	When("right after a check has been sent", func() {
		It("shouldCheck should return false", func() {
			rnat.checkSent()
			Expect(rnat.shouldCheck()).To(BeFalse())
		})
	})

	Context("with the total timeout elapsed", func() {
		When("not targeting a load balancer", func() {
			It("should report as timed out only for the normal timeout", func() {
				rnat.started = time.Now().Add(-ToDuration(&TotalTimeoutLoadBalancer))
				Expect(rnat.hasTimedOut()).To(BeFalse())

				rnat.started = time.Now().Add(-ToDuration(&TotalTimeout))
				Expect(rnat.hasTimedOut()).To(BeTrue())
			})
		})
		When("targeting a load balancer", func() {
			It("should report as timed out earlier", func() {
				remoteEndpoint.Spec.BackendConfig[submarinerv1.UsingLoadBalancer] = "true"
				rnat = newRemoteEndpointNAT(remoteEndpoint, k8snet.IPv4)
				rnat.started = time.Now().Add(-ToDuration(&TotalTimeoutLoadBalancer))
				Expect(rnat.hasTimedOut()).To(BeTrue())
			})
		})
	})

	When("using legacy settings", func() {
		Context("and NAT is not enabled", func() {
			It("should select the private IP", func() {
				rnat.endpoint.Spec.NATEnabled = false
				rnat.useLegacyNATSettings()
				Expect(rnat.state).To(Equal(selectedPrivateIP))
				Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPrivateIP(k8snet.IPv4)))
			})
		})
		Context("and NAT is enabled", func() {
			It("should select the public IP", func() {
				rnat.endpoint.Spec.NATEnabled = true
				rnat.useLegacyNATSettings()
				Expect(rnat.state).To(Equal(selectedPublicIP))
				Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPublicIP(k8snet.IPv4)))
			})
		})
		Context("and targeting a load balancer", func() {
			It("should select the public IP and NAT", func() {
				remoteEndpoint.Spec.BackendConfig[submarinerv1.UsingLoadBalancer] = "true"
				rnat = newRemoteEndpointNAT(remoteEndpoint, k8snet.IPv4)
				rnat.endpoint.Spec.NATEnabled = false
				rnat.useLegacyNATSettings()
				Expect(rnat.state).To(Equal(selectedPublicIP))
				Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPublicIP(k8snet.IPv4)))
				Expect(rnat.useNAT).To(BeTrue())
			})
		})
	})

	When("the public IP is selected but no check was sent", func() {
		It("it should not transition the state", func() {
			oldState := rnat.state
			Expect(rnat.transitionToPublicIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), false)).To(BeFalse())
			Expect(rnat.state).To(Equal(oldState))
			Expect(rnat.useIP).To(Equal(""))
		})
	})

	When("the private IP is selected but no check was sent", func() {
		It("it should not transition the state", func() {
			oldState := rnat.state
			Expect(rnat.transitionToPrivateIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), false)).To(BeFalse())
			Expect(rnat.state).To(Equal(oldState))
			Expect(rnat.useIP).To(Equal(""))
		})
	})

	//nolint:dupl // Ignore
	When("the private IP is selected", func() {
		var useNAT bool

		JustBeforeEach(func() {
			rnat.checkSent()
			Expect(rnat.transitionToPrivateIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), useNAT)).To(BeTrue())
			Expect(rnat.state).To(Equal(selectedPrivateIP))
		})

		It("should use the private IP", func() {
			Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPrivateIP(k8snet.IPv4)))
		})

		Context("with NAT discovered", func() {
			BeforeEach(func() {
				useNAT = true
			})

			It("should set useNAT to true", func() {
				Expect(rnat.useNAT).To(BeTrue())
			})
		})

		Context("with no NAT discovered", func() {
			BeforeEach(func() {
				useNAT = false
			})

			It("should set useNAT to false", func() {
				Expect(rnat.useNAT).To(BeFalse())
			})
		})
	})

	//nolint:dupl // Ignore
	When("the public IP is selected", func() {
		var useNAT bool

		JustBeforeEach(func() {
			rnat.checkSent()
			Expect(rnat.transitionToPublicIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), useNAT)).To(BeTrue())
			Expect(rnat.state).To(Equal(selectedPublicIP))
		})

		It("should use the public IP", func() {
			Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPublicIP(k8snet.IPv4)))
		})

		Context("with NAT discovered", func() {
			BeforeEach(func() {
				useNAT = true
			})

			It("should set useNAT to true", func() {
				Expect(rnat.useNAT).To(BeTrue())
			})
		})

		Context("with no NAT discovered", func() {
			BeforeEach(func() {
				useNAT = false
			})

			It("should set useNAT to false", func() {
				Expect(rnat.useNAT).To(BeFalse())
			})
		})
	})

	When("private IP is selected right after publicIP ", func() {
		Context("and the grace period has not elapsed", func() {
			It("should use the private IP", func() {
				rnat.checkSent()
				Expect(rnat.transitionToPublicIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), true)).To(BeTrue())
				Expect(rnat.transitionToPrivateIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), false)).To(BeTrue())
				Expect(rnat.state).To(Equal(selectedPrivateIP))
				Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPrivateIP(k8snet.IPv4)))
				Expect(rnat.useNAT).To(BeFalse())
			})
		})

		Context("and the grace period has elapsed", func() {
			It("should still use the public IP", func() {
				rnat.checkSent()
				Expect(rnat.transitionToPublicIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), true)).To(BeTrue())
				rnat.lastTransition = rnat.lastTransition.Add(-time.Duration(PublicToPrivateFailoverTimeout))
				Expect(rnat.transitionToPrivateIP(remoteEndpoint.Spec.GetFamilyCableName(k8snet.IPv4), false)).To(BeFalse())
				Expect(rnat.state).To(Equal(selectedPublicIP))
				Expect(rnat.useIP).To(Equal(rnat.endpoint.Spec.GetPublicIP(k8snet.IPv4)))
				Expect(rnat.useNAT).To(BeTrue())
			})
		})
	})
})
