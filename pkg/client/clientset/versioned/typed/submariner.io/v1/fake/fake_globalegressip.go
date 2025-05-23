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

package fake

import (
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	submarineriov1 "github.com/submariner-io/submariner/pkg/client/applyconfiguration/submariner.io/v1"
	typedsubmarineriov1 "github.com/submariner-io/submariner/pkg/client/clientset/versioned/typed/submariner.io/v1"
	gentype "k8s.io/client-go/gentype"
)

// fakeGlobalEgressIPs implements GlobalEgressIPInterface
type fakeGlobalEgressIPs struct {
	*gentype.FakeClientWithListAndApply[*v1.GlobalEgressIP, *v1.GlobalEgressIPList, *submarineriov1.GlobalEgressIPApplyConfiguration]
	Fake *FakeSubmarinerV1
}

func newFakeGlobalEgressIPs(fake *FakeSubmarinerV1, namespace string) typedsubmarineriov1.GlobalEgressIPInterface {
	return &fakeGlobalEgressIPs{
		gentype.NewFakeClientWithListAndApply[*v1.GlobalEgressIP, *v1.GlobalEgressIPList, *submarineriov1.GlobalEgressIPApplyConfiguration](
			fake.Fake,
			namespace,
			v1.SchemeGroupVersion.WithResource("globalegressips"),
			v1.SchemeGroupVersion.WithKind("GlobalEgressIP"),
			func() *v1.GlobalEgressIP { return &v1.GlobalEgressIP{} },
			func() *v1.GlobalEgressIPList { return &v1.GlobalEgressIPList{} },
			func(dst, src *v1.GlobalEgressIPList) { dst.ListMeta = src.ListMeta },
			func(list *v1.GlobalEgressIPList) []*v1.GlobalEgressIP { return gentype.ToPointerSlice(list.Items) },
			func(list *v1.GlobalEgressIPList, items []*v1.GlobalEgressIP) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
