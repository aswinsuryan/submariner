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

package datastoresyncer_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/admiral/pkg/fake"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/syncer/test"
	testutil "github.com/submariner-io/admiral/pkg/test"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/globalnet/constants"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	_ = Describe("Endpoint syncing", testEndpointSyncing)
	_ = Describe("Endpoint exclusivity", testEndpointExclusivity)
	_ = Describe("Endpoint cleanup", testEndpointCleanup)
)

func testEndpointSyncing() {
	t := newTestDriver()

	Context("on startup", func() {
		It("should create a new Endpoint locally and sync to the broker", func() {
			awaitEndpoint(t.localEndpoints, t.localEndpoint)
			awaitEndpoint(t.brokerEndpoints, t.localEndpoint)
		})

		When("creation of the local Endpoint fails", func() {
			BeforeEach(func() {
				t.expectedStartErr = errors.New("mock Create error")
				fake.FailOnAction(&t.localClient.Fake, "endpoints", "create", t.expectedStartErr, false)
			})

			It("Start should return an error", func() {
			})
		})

		When("a stale remote Endpoint exists locally", func() {
			var remoteEndpoint *submarinerv1.Endpoint

			BeforeEach(func() {
				remoteEndpoint = newEndpoint(&submarinerv1.EndpointSpec{
					CableName: fmt.Sprintf("submariner-cable-%s-10-253-1-2", otherClusterID),
					ClusterID: otherClusterID,
				})

				test.SetClusterIDLabel(remoteEndpoint, otherClusterID)
				test.CreateResource(t.localEndpoints, remoteEndpoint)
			})

			It("it should delete the Endpoint", func() {
				test.AwaitNoResource(t.localEndpoints, remoteEndpoint.GetName())
			})
		})
	})

	When("a remote Endpoint is created, updated and deleted on the broker", func() {
		It("should correctly sync the local datastore", func() {
			awaitEndpoint(t.brokerEndpoints, t.localEndpoint)

			endpoint := newEndpoint(&submarinerv1.EndpointSpec{
				CableName:  fmt.Sprintf("submariner-cable-%s-10-253-1-2", otherClusterID),
				ClusterID:  otherClusterID,
				Hostname:   "bruins",
				PrivateIPs: []string{"10-253-1-2"},
				Subnets:    []string{"200.0.0.0/16", "20.0.0.0/14"},
			})

			test.CreateResource(t.brokerEndpoints, test.SetClusterIDLabel(endpoint, endpoint.Spec.ClusterID))
			awaitEndpoint(t.localEndpoints, &endpoint.Spec)

			endpoint.Spec.Hostname = "celtics"
			endpoint.Spec.Subnets = append(endpoint.Spec.Subnets, "201.0.0.0/16")
			test.UpdateResource(t.brokerEndpoints, endpoint)
			awaitEndpoint(t.localEndpoints, &endpoint.Spec)

			Expect(t.brokerEndpoints.Delete(context.TODO(), endpoint.GetName(), metav1.DeleteOptions{})).To(Succeed())
			test.AwaitNoResource(t.localEndpoints, endpoint.GetName())
		})
	})

	When("a remote Endpoint is synced locally", func() {
		It("should not try to re-sync to the broker", func() {
			awaitEndpoint(t.brokerEndpoints, t.localEndpoint)

			endpoint := newEndpoint(&submarinerv1.EndpointSpec{
				CableName: fmt.Sprintf("submariner-cable-%s-10-253-1-2", otherClusterID),
				ClusterID: otherClusterID,
			})

			name := test.CreateResource(t.localEndpoints, test.SetClusterIDLabel(endpoint, endpoint.Spec.ClusterID)).GetName()

			time.Sleep(500 * time.Millisecond)
			test.AwaitNoResource(t.brokerEndpoints, name)
		})
	})

	When("the local Gateway's global IP is updated", func() {
		var gateway *submarinerv1.Gateway

		BeforeEach(func() {
			gateway = &submarinerv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:        t.localEndpoint.Hostname,
					Annotations: map[string]string{constants.SmGlobalIP: "200.0.0.40"},
				},
			}

			test.CreateResource(t.localGateways, gateway)
		})

		JustBeforeEach(func() {
			t.localEndpoint.SetHealthCheckIP(gateway.Annotations[constants.SmGlobalIP])
			awaitEndpoint(t.localEndpoints, t.localEndpoint)
		})

		It("should update the local Endpoint's HealthCheckIP", func() {
			gateway.Annotations[constants.SmGlobalIP] = "200.0.0.100"
			t.localEndpoint.SetHealthCheckIP(gateway.Annotations[constants.SmGlobalIP])

			test.UpdateResource(t.localGateways, gateway)
			awaitEndpoint(t.localEndpoints, t.localEndpoint)
		})

		Context("but the local Endpoint no longer exists", func() {
			It("should not recreate the local Endpoint", func() {
				Expect(t.localEndpoints.Delete(context.Background(), getEndpointName(t.localEndpoint), metav1.DeleteOptions{})).
					To(Succeed())

				gateway.Annotations[constants.SmGlobalIP] = "200.0.0.100"
				test.UpdateResource(t.localGateways, gateway)

				testutil.EnsureNoResource(resource.ForDynamic(t.localEndpoints), getEndpointName(t.localEndpoint))
			})
		})
	})
}

func testEndpointExclusivity() {
	t := newTestDriver()

	When("an Endpoint initially exists that doesn't match the local Endpoint", func() {
		var existingEndpoint *submarinerv1.Endpoint

		BeforeEach(func() {
			existingEndpoint = newEndpoint(&submarinerv1.EndpointSpec{
				CableName: "submariner-cable-east-1-2-3-4",
				ClusterID: clusterID,
			})

			test.CreateResource(t.localEndpoints, existingEndpoint)
			test.CreateResource(t.brokerEndpoints, test.SetClusterIDLabel(existingEndpoint, clusterID))
		})

		It("should delete the Endpoint from the local datastore and the broker", func() {
			test.AwaitNoResource(t.localEndpoints, existingEndpoint.GetName())
			test.AwaitNoResource(t.brokerEndpoints, existingEndpoint.GetName())
		})

		When("deletion of the Endpoint from the local datastore fails", func() {
			BeforeEach(func() {
				t.expectedStartErr = errors.New("mock Delete error")
				fake.FailOnAction(&t.localClient.Fake, "endpoints", "delete", t.expectedStartErr, false)
			})

			It("Start should return an error", func() {
			})
		})

		When("deletion of the Endpoint from the local datastore returns not found", func() {
			BeforeEach(func() {
				fake.FailOnAction(&t.localClient.Fake, "endpoints", "delete",
					apierrors.NewNotFound(schema.GroupResource{}, existingEndpoint.Spec.CableName), false)
			})

			It("should ignore it", func() {
				awaitEndpoint(t.brokerEndpoints, t.localEndpoint)
			})
		})
	})

	When("an Endpoint initially exists that matches the local Endpoint", func() {
		BeforeEach(func() {
			test.CreateResource(t.localEndpoints, newEndpoint(t.localEndpoint))
		})

		It("should not delete it", func() {
			time.Sleep(500 * time.Millisecond)
			awaitEndpoint(t.localEndpoints, t.localEndpoint)
			testutil.EnsureNoActionsForResource(&t.localClient.Fake, submarinerv1.EndpointGVR.Resource, "delete")
		})
	})

	When("an Endpoint from another cluster initially exists", func() {
		var remoteEndpointName string

		BeforeEach(func() {
			endpoint := newEndpoint(&submarinerv1.EndpointSpec{
				CableName: fmt.Sprintf("submariner-cable-%s-10-253-1-2", otherClusterID),
				ClusterID: otherClusterID,
			})

			remoteEndpointName = endpoint.Name

			endpoint = test.SetClusterIDLabel(endpoint, endpoint.Spec.ClusterID)
			test.CreateResource(t.localEndpoints, endpoint)
			test.CreateResource(t.brokerEndpoints, endpoint)
		})

		It("should not delete it", func() {
			time.Sleep(500 * time.Millisecond)
			test.AwaitResource(t.localEndpoints, remoteEndpointName)
		})
	})
}

func testEndpointCleanup() {
	t := newTestDriver()

	var (
		existingLocalEndpoint  *submarinerv1.Endpoint
		existingRemoteEndpoint *submarinerv1.Endpoint
	)

	BeforeEach(func() {
		t.doStart = false

		existingLocalEndpoint = newEndpoint(&submarinerv1.EndpointSpec{
			CableName: "submariner-cable-east-1-2-3-4",
			ClusterID: clusterID,
		})

		test.CreateResource(t.localEndpoints, existingLocalEndpoint)
		test.CreateResource(t.brokerEndpoints, test.SetClusterIDLabel(existingLocalEndpoint, clusterID))

		existingRemoteEndpoint = newEndpoint(&submarinerv1.EndpointSpec{
			CableName: fmt.Sprintf("submariner-cable-%s-10-253-1-2", otherClusterID),
			ClusterID: otherClusterID,
		})

		test.CreateResource(t.localEndpoints, test.SetClusterIDLabel(existingRemoteEndpoint, existingRemoteEndpoint.Spec.ClusterID))
		test.CreateResource(t.brokerEndpoints, test.SetClusterIDLabel(existingRemoteEndpoint, existingRemoteEndpoint.Spec.ClusterID))
	})

	It("should remove local Endpoints from the remote datastore", func() {
		Expect(t.syncer.Cleanup(context.Background())).To(Succeed())

		test.AwaitNoResource(t.brokerEndpoints, existingLocalEndpoint.GetName())

		time.Sleep(500 * time.Millisecond)
		test.AwaitResource(t.brokerEndpoints, existingRemoteEndpoint.GetName())
	})

	It("should remove all Endpoints from the local datastore", func() {
		Expect(t.syncer.Cleanup(context.Background())).To(Succeed())

		test.AwaitNoResource(t.localEndpoints, existingLocalEndpoint.GetName())
		test.AwaitNoResource(t.localEndpoints, existingRemoteEndpoint.GetName())
	})
}
