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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

// RoutePolicySpecApplyConfiguration represents a declarative configuration of the RoutePolicySpec type for use
// with apply.
type RoutePolicySpecApplyConfiguration struct {
	NextHops    []string `json:"nextHops,omitempty"`
	RemoteCIDRs []string `json:"remoteCIDRs,omitempty"`
}

// RoutePolicySpecApplyConfiguration constructs a declarative configuration of the RoutePolicySpec type for use with
// apply.
func RoutePolicySpec() *RoutePolicySpecApplyConfiguration {
	return &RoutePolicySpecApplyConfiguration{}
}

// WithNextHops adds the given value to the NextHops field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the NextHops field.
func (b *RoutePolicySpecApplyConfiguration) WithNextHops(values ...string) *RoutePolicySpecApplyConfiguration {
	for i := range values {
		b.NextHops = append(b.NextHops, values[i])
	}
	return b
}

// WithRemoteCIDRs adds the given value to the RemoteCIDRs field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the RemoteCIDRs field.
func (b *RoutePolicySpecApplyConfiguration) WithRemoteCIDRs(values ...string) *RoutePolicySpecApplyConfiguration {
	for i := range values {
		b.RemoteCIDRs = append(b.RemoteCIDRs, values[i])
	}
	return b
}
