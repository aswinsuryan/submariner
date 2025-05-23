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

package types

import (
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cidr"
	k8snet "k8s.io/utils/net"
)

type SubmarinerCluster struct {
	ID   string            `json:"id"`
	Spec subv1.ClusterSpec `json:"spec"`
}

type SubmarinerEndpoint struct {
	Spec subv1.EndpointSpec `json:"spec"`
}

type SubmarinerSpecification struct {
	ClusterCidr                   []string
	GlobalCidr                    []string
	ServiceCidr                   []string
	Broker                        string
	CableDriver                   string
	ClusterID                     string
	Namespace                     string
	PublicIP                      string
	Token                         string
	Debug                         bool
	NATEnabled                    bool
	HealthCheckEnabled            bool `default:"true"`
	Uninstall                     bool
	HaltOnCertError               bool `split_words:"true"`
	HealthCheckInterval           int
	HealthCheckMaxPacketLossCount int
	MetricsPort                   int `default:"32780"`
}

func (subSpec *SubmarinerSpecification) GetIPFamilies() []k8snet.IPFamily {
	return cidr.ExtractIPFamilies(subSpec.ClusterCidr)
}
