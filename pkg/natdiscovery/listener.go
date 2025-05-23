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
	"encoding/hex"
	"net"
	"strconv"

	"github.com/pkg/errors"
	natproto "github.com/submariner-io/submariner/pkg/natdiscovery/proto"
	"google.golang.org/protobuf/proto"
	k8snet "k8s.io/utils/net"
)

var familyToNetwork = map[k8snet.IPFamily]string{
	k8snet.IPv4: "udp4",
	k8snet.IPv6: "udp6",
}

type ServerConnection interface {
	Close() error
	ReadFromUDP(b []byte) (int, *net.UDPAddr, error)
	WriteToUDP(b []byte, addr *net.UDPAddr) (int, error)
}

func (nd *natDiscovery) runListeners(stopCh <-chan struct{}) error {
	for _, family := range nd.LocalEndpoint.Spec().GetIPFamilies() {
		if err := nd.runListener(family, stopCh); err != nil {
			return err
		}

		logger.Infof("NAT discovery started listener for IPv%v", family)
	}

	return nil
}

func (nd *natDiscovery) runListener(family k8snet.IPFamily, stopCh <-chan struct{}) error {
	if nd.serverPort == 0 {
		logger.Infof("NAT discovery protocol port not set for this gateway")
		return nil
	}

	serverConnection, err := nd.CreateServerConnection(nd.serverPort, family)
	if err != nil {
		return err
	}

	// Instead of storing the server connection I save the reference to the WriteToUDP
	// of our server connection instance, in a way that we can use this for unit testing
	// later too.
	nd.serverUDPWrite[family] = serverConnection.WriteToUDP

	go func() {
		<-stopCh
		serverConnection.Close()
	}()

	go nd.listenerLoop(serverConnection)

	return nil
}

func createServerConnection(port int32, family k8snet.IPFamily) (ServerConnection, error) {
	address := ":" + strconv.Itoa(int(port))

	serverAddr, err := net.ResolveUDPAddr(familyToNetwork[family], address)
	if err != nil {
		return nil, errors.Wrapf(err, "error resolving UDP address for IPv%v", family)
	}

	serverConnection, err := net.ListenUDP(familyToNetwork[family], serverAddr)
	if err != nil {
		return nil, errors.Wrapf(err, "error listening on UDP port %d for IPv%v", port, family)
	}

	return serverConnection, nil
}

func (nd *natDiscovery) listenerLoop(serverConnection ServerConnection) {
	buf := make([]byte, 2048)

	for {
		length, addr, err := serverConnection.ReadFromUDP(buf)
		if length == 0 {
			logger.Info("Stopping NAT listener")
			return
		} else if err != nil {
			logger.Errorf(err, "Error receiving from udp")
		} else if err := nd.parseAndHandleMessageFromAddress(buf[:length], addr); err != nil {
			logger.Errorf(err, "Error handling message from address %s:\n%s", addr.String(), hex.Dump(buf[:length]))
		}
	}
}

func (nd *natDiscovery) parseAndHandleMessageFromAddress(buf []byte, addr *net.UDPAddr) error {
	msg := natproto.SubmarinerNATDiscoveryMessage{}
	err := errors.Wrapf(proto.Unmarshal(buf, &msg), "Error unmarshaling message received on UDP port %d", natproto.DefaultPort)

	if err == nil {
		if request := msg.GetRequest(); request != nil {
			err = nd.handleRequestFromAddress(request, addr)
		} else if response := msg.GetResponse(); response != nil {
			err = nd.handleResponseFromAddress(response, addr)
		} else {
			err = errors.New("message without response or request received")
		}
	}

	return err
}
