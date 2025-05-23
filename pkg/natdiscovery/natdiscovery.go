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
	"math/rand/v2"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/endpoint"
	"k8s.io/apimachinery/pkg/util/wait"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type Interface interface {
	Run(stopCh <-chan struct{}) error
	AddEndpoint(endpoint *v1.Endpoint, family k8snet.IPFamily)
	RemoveEndpoint(endpointName string)
	GetReadyChannel() chan *NATEndpointInfo
}

type (
	udpWriteFunction         func(b []byte, addr *net.UDPAddr) (int, error)
	FindSrcIPFunction        func(destinationIP string, family k8snet.IPFamily) string
	CreateServerConnectionFn func(port int32, family k8snet.IPFamily) (ServerConnection, error)
)

type Config struct {
	LocalEndpoint *endpoint.Local

	// These are hooks to allow unit tests to mock behavior.
	CreateServerConnection CreateServerConnectionFn
	FindSourceIP           FindSrcIPFunction
	RunLoop                func(stopCh <-chan struct{}, doCheck func())
}

type natDiscovery struct {
	sync.Mutex
	Config
	remoteEndpoints map[string]*remoteEndpointNAT
	requestCounter  uint64
	serverUDPWrite  map[k8snet.IPFamily]udpWriteFunction
	serverPort      int32
	readyChannel    chan *NATEndpointInfo
}

var logger = log.Logger{Logger: logf.Log.WithName("NAT")}

func New(localEndpoint *endpoint.Local) (Interface, error) {
	return NewWithConfig(Config{
		LocalEndpoint:          localEndpoint,
		CreateServerConnection: createServerConnection,
		FindSourceIP:           endpoint.GetLocalIPForDestination,
		RunLoop: func(stopCh <-chan struct{}, doCheck func()) {
			go wait.Until(func() {
				doCheck()
			}, time.Second, stopCh)
		},
	})
}

func NewWithConfig(config Config) (Interface, error) {
	ndPort, err := config.LocalEndpoint.Spec().GetBackendPort(v1.NATTDiscoveryPortConfig, 0)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing nat discovery port")
	}

	//nolint:gosec // Use of math/rand over crypto/rand is fine here as the request counter is not security-sensitive.
	return &natDiscovery{
		Config:          config,
		serverPort:      ndPort,
		remoteEndpoints: map[string]*remoteEndpointNAT{},
		serverUDPWrite:  map[k8snet.IPFamily]udpWriteFunction{},
		requestCounter:  rand.Uint64(),
		readyChannel:    make(chan *NATEndpointInfo, 100),
	}, nil
}

var errNoNATDiscoveryPort = errors.New("NATT discovery port missing in endpoint")

func extractNATDiscoveryPort(endPoint *v1.EndpointSpec) (int32, error) {
	natDiscoveryPort, err := endPoint.GetBackendPort(v1.NATTDiscoveryPortConfig, 0)
	if err != nil {
		return natDiscoveryPort, err //nolint:wrapcheck  // No need to wrap this error
	}

	if natDiscoveryPort == 0 {
		return natDiscoveryPort, errNoNATDiscoveryPort
	}

	return natDiscoveryPort, nil
}

func (nd *natDiscovery) GetReadyChannel() chan *NATEndpointInfo {
	return nd.readyChannel
}

func (nd *natDiscovery) Run(stopCh <-chan struct{}) error {
	logger.V(log.DEBUG).Infof("NAT discovery server starting on port %d", nd.serverPort)

	err := nd.runListeners(stopCh)
	if err != nil {
		return err
	}

	nd.RunLoop(stopCh, nd.checkEndpointList)

	return nil
}

func (nd *natDiscovery) AddEndpoint(endPoint *v1.Endpoint, family k8snet.IPFamily) {
	nd.Lock()
	defer nd.Unlock()

	if ep, exists := nd.remoteEndpoints[endPoint.Spec.GetFamilyCableName(family)]; exists {
		if reflect.DeepEqual(ep.endpoint.Spec, endPoint.Spec) {
			if ep.isDiscoveryComplete() {
				nd.readyChannel <- ep.toNATEndpointInfo()
			}

			return
		}

		logger.V(log.DEBUG).Infof("NAT discovery updated endpoint IPv%v %q", family, endPoint.Spec.CableName)

		delete(nd.remoteEndpoints, endPoint.Spec.GetFamilyCableName(family))
	}

	remoteNAT := newRemoteEndpointNAT(endPoint, family)

	// support nat discovery disabled or a remote cluster endpoint which still hasn't implemented this protocol
	if _, err := extractNATDiscoveryPort(&endPoint.Spec); err != nil || nd.serverPort == 0 {
		if !errors.Is(err, errNoNATDiscoveryPort) {
			logger.Errorf(err, "Error extracting NATT discovery port from endpoint %q", endPoint.Spec.CableName)
		}

		remoteNAT.useLegacyNATSettings()
		nd.readyChannel <- remoteNAT.toNATEndpointInfo()
	} else {
		logger.Infof("Starting NAT discovery for endpoint %q", endPoint.Spec.CableName)
	}

	nd.remoteEndpoints[endPoint.Spec.GetFamilyCableName(family)] = remoteNAT
}

func (nd *natDiscovery) RemoveEndpoint(endpointName string) {
	nd.Lock()
	defer nd.Unlock()
	delete(nd.remoteEndpoints, endpointName)
}

func (nd *natDiscovery) checkEndpointList() {
	nd.Lock()
	defer nd.Unlock()

	logger.V(log.TRACE).Info("NAT discovery checking endpoint list")

	for _, endpointNAT := range nd.remoteEndpoints {
		name := endpointNAT.endpoint.Spec.GetFamilyCableName(endpointNAT.family)
		logger.V(log.TRACE).Infof("NAT processing remote endpoint %q", name)

		if endpointNAT.shouldCheck() {
			if endpointNAT.hasTimedOut() {
				logger.Warningf("NAT discovery for endpoint %q has timed out", name)
				endpointNAT.useLegacyNATSettings()
				nd.readyChannel <- endpointNAT.toNATEndpointInfo()
			} else if err := nd.sendCheckRequest(endpointNAT); err != nil {
				logger.Errorf(err, "Error sending check request to endpoint %q", name)
			}
		} else {
			logger.V(log.TRACE).Infof("NAT shouldCheck() == false for  %q", name)
		}
	}
}
