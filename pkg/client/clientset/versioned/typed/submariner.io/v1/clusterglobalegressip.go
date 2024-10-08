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

// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	submarineriov1 "github.com/submariner-io/submariner/pkg/client/applyconfiguration/submariner.io/v1"
	scheme "github.com/submariner-io/submariner/pkg/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// ClusterGlobalEgressIPsGetter has a method to return a ClusterGlobalEgressIPInterface.
// A group's client should implement this interface.
type ClusterGlobalEgressIPsGetter interface {
	ClusterGlobalEgressIPs(namespace string) ClusterGlobalEgressIPInterface
}

// ClusterGlobalEgressIPInterface has methods to work with ClusterGlobalEgressIP resources.
type ClusterGlobalEgressIPInterface interface {
	Create(ctx context.Context, clusterGlobalEgressIP *v1.ClusterGlobalEgressIP, opts metav1.CreateOptions) (*v1.ClusterGlobalEgressIP, error)
	Update(ctx context.Context, clusterGlobalEgressIP *v1.ClusterGlobalEgressIP, opts metav1.UpdateOptions) (*v1.ClusterGlobalEgressIP, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, clusterGlobalEgressIP *v1.ClusterGlobalEgressIP, opts metav1.UpdateOptions) (*v1.ClusterGlobalEgressIP, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.ClusterGlobalEgressIP, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.ClusterGlobalEgressIPList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.ClusterGlobalEgressIP, err error)
	Apply(ctx context.Context, clusterGlobalEgressIP *submarineriov1.ClusterGlobalEgressIPApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ClusterGlobalEgressIP, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, clusterGlobalEgressIP *submarineriov1.ClusterGlobalEgressIPApplyConfiguration, opts metav1.ApplyOptions) (result *v1.ClusterGlobalEgressIP, err error)
	ClusterGlobalEgressIPExpansion
}

// clusterGlobalEgressIPs implements ClusterGlobalEgressIPInterface
type clusterGlobalEgressIPs struct {
	*gentype.ClientWithListAndApply[*v1.ClusterGlobalEgressIP, *v1.ClusterGlobalEgressIPList, *submarineriov1.ClusterGlobalEgressIPApplyConfiguration]
}

// newClusterGlobalEgressIPs returns a ClusterGlobalEgressIPs
func newClusterGlobalEgressIPs(c *SubmarinerV1Client, namespace string) *clusterGlobalEgressIPs {
	return &clusterGlobalEgressIPs{
		gentype.NewClientWithListAndApply[*v1.ClusterGlobalEgressIP, *v1.ClusterGlobalEgressIPList, *submarineriov1.ClusterGlobalEgressIPApplyConfiguration](
			"clusterglobalegressips",
			c.RESTClient(),
			scheme.ParameterCodec,
			namespace,
			func() *v1.ClusterGlobalEgressIP { return &v1.ClusterGlobalEgressIP{} },
			func() *v1.ClusterGlobalEgressIPList { return &v1.ClusterGlobalEgressIPList{} }),
	}
}
