/*
© 2021 Red Hat, Inc. and others.

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
	"crypto/rand"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/submariner/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog"
)

type Interface interface {
	Run(stopCh <-chan struct{}) error
	AddEndpoint(endpoint *types.SubmarinerEndpoint)
	RemoveEndpoint(endpointName string)
	SetReadyChannel(readyChannel chan *NATEndpointInfo)
}

type udpWriteFunction func(b []byte, addr *net.UDPAddr) (int, error)
type findSrcIPFunction func(destinationIP string) (string, error)

type natDiscovery struct {
	sync.Mutex
	localEndpoint   *types.SubmarinerEndpoint
	remoteEndpoints map[string]*remoteEndpointNAT
	requestCounter  uint64
	serverUDPWrite  udpWriteFunction
	findSrcIP       findSrcIPFunction
	serverPort      int32
	readyChannel    chan *NATEndpointInfo
}

func (nd *natDiscovery) SetReadyChannel(readyChannel chan *NATEndpointInfo) {
	nd.readyChannel = readyChannel
}

func New(localEndpoint *types.SubmarinerEndpoint) (Interface, error) {
	return newNatDiscovery(localEndpoint)
}

func newNatDiscovery(localEndpoint *types.SubmarinerEndpoint) (*natDiscovery, error) {
	port, err := extractNATDiscoveryPort(localEndpoint)
	if err != nil {
		return nil, err
	}

	requestCounter, err := randomRequestCounter()
	if err != nil {
		return nil, err
	}

	return &natDiscovery{
		localEndpoint:   localEndpoint,
		serverPort:      port,
		remoteEndpoints: map[string]*remoteEndpointNAT{},
		findSrcIP:       findPreferredSourceIP,
		requestCounter:  requestCounter,
	}, nil
}

func randomRequestCounter() (uint64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return 0, errors.Wrapf(err, "generating random request counter")
	}

	return n.Uint64(), nil
}

var errorNoNatDiscoveryPort = errors.New("nat discovery port missing in endpoint")

func extractNATDiscoveryPort(endpoint *types.SubmarinerEndpoint) (int32, error) {
	if endpoint.Spec.NATDiscoveryPort == nil {
		return 0, errorNoNatDiscoveryPort
	}

	return *endpoint.Spec.NATDiscoveryPort, nil
}

func (nd *natDiscovery) Run(stopCh <-chan struct{}) error {
	err := nd.runListener(stopCh)
	if err != nil {
		return err
	}

	go wait.Until(func() {
		nd.checkEndpointList()
	}, time.Second, stopCh)

	return nil
}

func (nd *natDiscovery) AddEndpoint(endpoint *types.SubmarinerEndpoint) {
	nd.Lock()
	defer nd.Unlock()

	if ep, exists := nd.remoteEndpoints[endpoint.Spec.CableName]; exists {
		if reflect.DeepEqual(ep.endpoint.Spec, endpoint.Spec) {
			return
		} else {
			delete(nd.remoteEndpoints, endpoint.Spec.CableName)
		}
	}

	remoteNAT := newRemoteEndpointNAT(endpoint)

	// support a remote cluster endpoint which still hasn't implemented this protocol
	if _, err := extractNATDiscoveryPort(endpoint); err == errorNoNatDiscoveryPort {
		remoteNAT.useLegacyNATSettings()
		nd.readyChannel <- remoteNAT.toNATEndpointInfo()
	}

	nd.remoteEndpoints[endpoint.Spec.CableName] = remoteNAT
}

func (nd *natDiscovery) RemoveEndpoint(endpointName string) {
	nd.Lock()
	defer nd.Unlock()
	delete(nd.remoteEndpoints, endpointName)
}

func (nd *natDiscovery) checkEndpointList() {
	nd.Lock()
	defer nd.Unlock()

	for _, endpointNAT := range nd.remoteEndpoints {
		if endpointNAT.shouldCheck() {
			if endpointNAT.hasTimedOut() {
				endpointNAT.useLegacyNATSettings()
				nd.readyChannel <- endpointNAT.toNATEndpointInfo()
			} else if err := nd.sendCheckRequest(endpointNAT); err != nil {
				klog.Errorf("Error sending check request to %q: %s", endpointNAT.endpoint.Spec.CableName, err)
			}
		}
	}
}
