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
	"fmt"
	"reflect"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/fake"
	. "github.com/submariner-io/admiral/pkg/gomega"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	"github.com/submariner-io/admiral/pkg/syncer/broker"
	"github.com/submariner-io/admiral/pkg/syncer/test"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/controllers/datastoresyncer"
	"github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/types"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

const (
	clusterID       = "east"
	otherClusterID  = "west"
	localNamespace  = "submariner"
	brokerNamespace = "submariner-broker"
)

func TestDatastoresyncer(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Datastore syncer Suite")
}

func init() {
	kzerolog.AddFlags(nil)

	err := submarinerv1.AddToScheme(scheme.Scheme)
	if err != nil {
		panic(err)
	}
}

var _ = BeforeSuite(func() {
	kzerolog.InitK8sLogging()
})

type testDriver struct {
	syncer           *datastoresyncer.DatastoreSyncer
	localCluster     *types.SubmarinerCluster
	localEndpoint    *submarinerv1.EndpointSpec
	localClient      *dynamicfake.FakeDynamicClient
	brokerClient     *dynamicfake.FakeDynamicClient
	localClusters    dynamic.ResourceInterface
	brokerClusters   dynamic.ResourceInterface
	localEndpoints   dynamic.ResourceInterface
	localGateways    dynamic.ResourceInterface
	brokerEndpoints  dynamic.ResourceInterface
	syncerScheme     *runtime.Scheme
	restMapper       meta.RESTMapper
	stopFn           context.CancelFunc
	startCompleted   chan error
	expectedStartErr error
	doStart          bool
}

func newTestDriver() *testDriver {
	t := &testDriver{
		localCluster: &types.SubmarinerCluster{
			ID: clusterID,
			Spec: submarinerv1.ClusterSpec{
				ClusterID:   clusterID,
				ServiceCIDR: []string{"100.0.0.0/16"},
				ClusterCIDR: []string{"10.0.0.0/14"},
				GlobalCIDR:  []string{"200.0.0.0/16"},
			},
		},
		localEndpoint: &submarinerv1.EndpointSpec{
			CableName:  fmt.Sprintf("submariner-cable-%s-192-68-1-2", clusterID),
			ClusterID:  clusterID,
			Hostname:   "redsox",
			PrivateIPs: []string{"192.68.1.2"},
			Subnets:    []string{"100.0.0.0/16", "10.0.0.0/14"},
			Backend:    "ipsec",
		},
	}

	BeforeEach(func() {
		t.expectedStartErr = nil
		t.doStart = true

		t.syncerScheme = runtime.NewScheme()
		Expect(submarinerv1.AddToScheme(t.syncerScheme)).To(Succeed())
		Expect(corev1.AddToScheme(t.syncerScheme)).To(Succeed())

		t.localClient = dynamicfake.NewSimpleDynamicClient(t.syncerScheme)
		fake.AddBasicReactors(&t.localClient.Fake)

		t.brokerClient = dynamicfake.NewSimpleDynamicClient(t.syncerScheme)
		fake.AddBasicReactors(&t.brokerClient.Fake)

		t.restMapper = test.GetRESTMapperFor(&submarinerv1.Cluster{}, &submarinerv1.Endpoint{}, &submarinerv1.Gateway{}, &corev1.Node{})

		clusterGVR := test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.Cluster{})
		t.localClusters = t.localClient.Resource(*clusterGVR).Namespace(localNamespace)
		t.brokerClusters = t.brokerClient.Resource(*clusterGVR).Namespace(brokerNamespace)

		endpointGVR := test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.Endpoint{})
		t.localEndpoints = t.localClient.Resource(*endpointGVR).Namespace(localNamespace)
		t.brokerEndpoints = t.brokerClient.Resource(*endpointGVR).Namespace(brokerNamespace)

		t.localGateways = t.localClient.Resource(*test.GetGroupVersionResourceFor(t.restMapper, &submarinerv1.Gateway{})).
			Namespace(localNamespace)
	})

	JustBeforeEach(func() {
		t.run()
	})

	AfterEach(func() {
		t.stop()
	})

	return t
}

func (t *testDriver) run() {
	t.syncer = datastoresyncer.New(&broker.SyncerConfig{
		LocalClient:     t.localClient,
		LocalNamespace:  localNamespace,
		LocalClusterID:  clusterID,
		BrokerClient:    t.brokerClient,
		BrokerNamespace: brokerNamespace,
		RestMapper:      t.restMapper,
		Scheme:          t.syncerScheme,
	}, t.localCluster, endpoint.NewLocal(t.localEndpoint, t.localClient, localNamespace))

	if t.doStart {
		var ctx context.Context

		ctx, t.stopFn = context.WithCancel(context.Background())
		t.startCompleted = make(chan error, 1)

		go func() {
			t.startCompleted <- t.syncer.Start(ctx)
		}()
	}
}

func (t *testDriver) stop() {
	if !t.doStart {
		return
	}

	err := func() error {
		timeout := 5 * time.Second
		select {
		case err := <-t.startCompleted:
			return errors.WithMessage(err, "Start returned an error")
		case <-time.After(timeout):
			return fmt.Errorf("Start did not complete after %v", timeout)
		}
	}()

	t.stopFn()

	if t.expectedStartErr == nil {
		Expect(err).To(Succeed())
	} else {
		Expect(err).To(ContainErrorSubstring(t.expectedStartErr))
	}
}

func newEndpoint(spec *submarinerv1.EndpointSpec) *submarinerv1.Endpoint {
	return &submarinerv1.Endpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: getEndpointName(spec),
		},
		Spec: *spec,
	}
}

func newCluster(spec *submarinerv1.ClusterSpec) *submarinerv1.Cluster {
	return &submarinerv1.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: spec.ClusterID,
		},
		Spec: *spec,
	}
}

func getEndpointName(from *submarinerv1.EndpointSpec) string {
	endpointName, err := from.GenerateName()
	Expect(err).To(Succeed())

	return endpointName
}

func awaitCluster(clusters dynamic.ResourceInterface, expected *submarinerv1.ClusterSpec) {
	test.AwaitAndVerifyResource(clusters, expected.ClusterID, func(obj *unstructured.Unstructured) bool {
		defer GinkgoRecover()

		actual := &submarinerv1.Cluster{}
		Expect(scheme.Scheme.Convert(obj, actual, nil)).To(Succeed())

		return reflect.DeepEqual(actual.Spec, *expected)
	})
}

func awaitEndpoint(endpoints dynamic.ResourceInterface, expected *submarinerv1.EndpointSpec) {
	test.AwaitAndVerifyResource(endpoints, getEndpointName(expected), func(obj *unstructured.Unstructured) bool {
		defer GinkgoRecover()

		actual := &submarinerv1.Endpoint{}
		Expect(scheme.Scheme.Convert(obj, actual, nil)).To(Succeed())

		return reflect.DeepEqual(actual.Spec, *expected)
	})
}
