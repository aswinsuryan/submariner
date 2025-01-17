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

package v1_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	k8snet "k8s.io/utils/net"
)

const (
	ipV4Addr = "1.2.3.4"
	ipV6Addr = "2001:db8:3333:4444:5555:6666:7777:8888"
)

var _ = Describe("EndpointSpec", func() {
	Context("GenerateName", testGenerateName)
	Context("Equals", testEquals)
	Context("GetHealthCheckIP", testGetHealthCheckIP)
	Context("SetHealthCheckIP", testSetHealthCheckIP)
	Context("GetPublicIP", testGetPublicIP)
	Context("SetPublicIP", testSetPublicIP)
	Context("GetPrivateIP", testGetPrivateIP)
	Context("SetPrivateIP", testSetPrivateIP)
})

func testGenerateName() {
	When("the fields are valid", func() {
		It("should return <cluster ID>-<cable name>", func() {
			name, err := (&v1.EndpointSpec{
				ClusterID: "ClusterID",
				CableName: "CableName",
			}).GenerateName()

			Expect(err).ToNot(HaveOccurred())
			Expect(name).To(Equal("clusterid-cablename"))
		})
	})

	When("the ClusterID is empty", func() {
		It("should return an error", func() {
			_, err := (&v1.EndpointSpec{
				CableName: "CableName",
			}).GenerateName()

			Expect(err).To(HaveOccurred())
		})
	})

	When("the CableName is empty", func() {
		It("should return an error", func() {
			_, err := (&v1.EndpointSpec{
				ClusterID: "ClusterID",
			}).GenerateName()

			Expect(err).To(HaveOccurred())
		})
	})
}

func testEquals() {
	var spec *v1.EndpointSpec

	BeforeEach(func() {
		spec = &v1.EndpointSpec{
			ClusterID: "east",
			CableName: "submariner-cable-east-172-16-32-5",
			Hostname:  "my-host",
			Backend:   "libreswan",
		}
	})

	Context("with equal scalar fields", func() {
		Context("and nil BackendConfig maps", func() {
			It("should return true", func() {
				Expect(spec.Equals(spec.DeepCopy())).To(BeTrue())
			})
		})

		Context("and equal BackendConfig maps", func() {
			It("should return true", func() {
				spec.BackendConfig = map[string]string{"key": "aaa"}
				Expect(spec.Equals(spec.DeepCopy())).To(BeTrue())
			})
		})

		Context("and empty BackendConfig maps", func() {
			It("should return true", func() {
				spec.BackendConfig = map[string]string{}
				Expect(spec.Equals(spec.DeepCopy())).To(BeTrue())
			})
		})
	})

	Context("with differing ClusterID fields", func() {
		It("should return false", func() {
			other := spec.DeepCopy()
			other.ClusterID = "west"
			Expect(spec.Equals(other)).To(BeFalse())
		})
	})

	Context("with differing CableName fields", func() {
		It("should return false", func() {
			other := spec.DeepCopy()
			other.CableName = "submariner-cable-east-5-6-7-8"
			Expect(spec.Equals(other)).To(BeFalse())
		})
	})

	Context("with differing Hostname fields", func() {
		It("should return false", func() {
			other := spec.DeepCopy()
			other.Hostname = "other-host"
			Expect(spec.Equals(other)).To(BeFalse())
		})
	})

	Context("with differing Backend fields", func() {
		It("should return false", func() {
			other := spec.DeepCopy()
			other.Backend = "wireguard"
			Expect(spec.Equals(other)).To(BeFalse())
		})
	})

	Context("with differing BackendConfig maps", func() {
		It("should return false", func() {
			other := spec.DeepCopy()
			other.BackendConfig = map[string]string{"key": "bbb"}
			spec.BackendConfig = map[string]string{"key": "aaa"}
			Expect(spec.Equals(other)).To(BeFalse())
		})
	})
}

func testGetIP(ipsSetter func(*v1.EndpointSpec, []string, string), ipsGetter func(*v1.EndpointSpec, k8snet.IPFamily) string) {
	var (
		spec         *v1.EndpointSpec
		legacyIPv4IP string
		ips          []string
	)

	BeforeEach(func() {
		legacyIPv4IP = ""
		ips = []string{}
	})

	JustBeforeEach(func() {
		spec = &v1.EndpointSpec{}
		ipsSetter(spec, ips, legacyIPv4IP)
	})

	Context("IPv4", func() {
		When("an IPv4 address is present", func() {
			BeforeEach(func() {
				ips = []string{ipV6Addr, ipV4Addr}
			})

			It("should return the address", func() {
				Expect(ipsGetter(spec, k8snet.IPv4)).To(Equal(ipV4Addr))
			})
		})

		When("an IPv4 address is not present and the legacy IPv4 address is set", func() {
			BeforeEach(func() {
				ips = []string{ipV6Addr}
				legacyIPv4IP = ipV4Addr
			})

			It("should return the legacy address", func() {
				Expect(ipsGetter(spec, k8snet.IPv4)).To(Equal(ipV4Addr))
			})
		})

		When("an IPv4 address is not present and the legacy IPv4 address is not set", func() {
			It("should return empty string", func() {
				Expect(ipsGetter(spec, k8snet.IPv4)).To(BeEmpty())
			})
		})
	})

	Context("IPv6", func() {
		When("an IPv6 address is present", func() {
			BeforeEach(func() {
				ips = []string{ipV4Addr, ipV6Addr}
			})

			It("should return the address", func() {
				Expect(ipsGetter(spec, k8snet.IPv6)).To(Equal(ipV6Addr))
			})
		})

		When("an IPv6 address is not present", func() {
			BeforeEach(func() {
				ips = []string{ipV4Addr}
			})

			It("should return empty string", func() {
				Expect(ipsGetter(spec, k8snet.IPv6)).To(BeEmpty())
			})
		})
	})
}

func testSetIP(initIPs func(*v1.EndpointSpec, []string), ipsSetter func(*v1.EndpointSpec, string),
	ipsGetter func(*v1.EndpointSpec) ([]string, string),
) {
	var (
		spec       *v1.EndpointSpec
		ipToSet    string
		initialIPs []string
	)

	BeforeEach(func() {
		spec = &v1.EndpointSpec{}
		initialIPs = []string{}
		ipToSet = ""
	})

	JustBeforeEach(func() {
		initIPs(spec, initialIPs)
		ipsSetter(spec, ipToSet)
	})

	verifyIPs := func(ips []string, legacyV4 string) {
		actualIPs, actualLegacy := ipsGetter(spec)
		Expect(actualIPs).To(Equal(ips))
		Expect(actualLegacy).To(Equal(legacyV4))
	}

	Context("IPv4", func() {
		BeforeEach(func() {
			ipToSet = ipV4Addr
		})

		When("no addresses are present", func() {
			It("should add the new address", func() {
				verifyIPs([]string{ipToSet}, ipToSet)
			})
		})

		When("no IPv4 address is present", func() {
			BeforeEach(func() {
				initialIPs = []string{ipV6Addr}
			})

			It("should add the new address", func() {
				verifyIPs([]string{ipV6Addr, ipToSet}, ipToSet)
			})
		})

		When("an IPv4 address is already present", func() {
			BeforeEach(func() {
				initialIPs = []string{"11.22.33.44"}
			})

			It("should update address", func() {
				verifyIPs([]string{ipToSet}, ipToSet)
			})
		})
	})

	Context("IPv6", func() {
		BeforeEach(func() {
			ipToSet = ipV6Addr
		})

		When("no addresses are present", func() {
			It("should add the new address", func() {
				verifyIPs([]string{ipToSet}, "")
			})
		})

		When("no IPv6 address is present", func() {
			BeforeEach(func() {
				initialIPs = []string{ipV4Addr}
			})

			It("should add the new address", func() {
				verifyIPs([]string{ipV4Addr, ipToSet}, "")
			})
		})

		When("an IPv6 address is already present", func() {
			BeforeEach(func() {
				initialIPs = []string{"1234:cb9:3333:4444:5555:6666:7777:8888"}
			})

			It("should update address", func() {
				verifyIPs([]string{ipToSet}, "")
			})
		})
	})
}

func testGetHealthCheckIP() {
	testGetIP(func(s *v1.EndpointSpec, ips []string, ipv4IP string) {
		s.HealthCheckIPs = ips
		s.HealthCheckIP = ipv4IP
	}, func(s *v1.EndpointSpec, family k8snet.IPFamily) string {
		return s.GetHealthCheckIP(family)
	})
}

func testSetHealthCheckIP() {
	testSetIP(func(s *v1.EndpointSpec, ips []string) {
		s.HealthCheckIPs = ips
	}, func(s *v1.EndpointSpec, ip string) {
		s.SetHealthCheckIP(ip)
	}, func(s *v1.EndpointSpec) ([]string, string) {
		return s.HealthCheckIPs, s.HealthCheckIP
	})
}

func testGetPublicIP() {
	testGetIP(func(s *v1.EndpointSpec, ips []string, ipv4IP string) {
		s.PublicIPs = ips
		s.PublicIP = ipv4IP
	}, func(s *v1.EndpointSpec, family k8snet.IPFamily) string {
		return s.GetPublicIP(family)
	})
}

func testSetPublicIP() {
	testSetIP(func(s *v1.EndpointSpec, ips []string) {
		s.PublicIPs = ips
	}, func(s *v1.EndpointSpec, ip string) {
		s.SetPublicIP(ip)
	}, func(s *v1.EndpointSpec) ([]string, string) {
		return s.PublicIPs, s.PublicIP
	})
}

func testGetPrivateIP() {
	testGetIP(func(s *v1.EndpointSpec, ips []string, ipv4IP string) {
		s.PrivateIPs = ips
		s.PrivateIP = ipv4IP
	}, func(s *v1.EndpointSpec, family k8snet.IPFamily) string {
		return s.GetPrivateIP(family)
	})
}

func testSetPrivateIP() {
	testSetIP(func(s *v1.EndpointSpec, ips []string) {
		s.PrivateIPs = ips
	}, func(s *v1.EndpointSpec, ip string) {
		s.SetPrivateIP(ip)
	}, func(s *v1.EndpointSpec) ([]string, string) {
		return s.PrivateIPs, s.PrivateIP
	})
}
