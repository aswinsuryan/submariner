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
	"net"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	natproto "github.com/submariner-io/submariner/pkg/natdiscovery/proto"
	"google.golang.org/protobuf/proto"
)

func (nd *natDiscovery) sendCheckRequest(remoteNAT *remoteEndpointNAT) error {
	var errPrivate, errPublic error
	var reqID uint64

	if remoteNAT.endpoint.Spec.GetPrivateIP(remoteNAT.family) != "" {
		reqID, errPrivate = nd.sendCheckRequestToTargetIP(remoteNAT, remoteNAT.endpoint.Spec.GetPrivateIP(remoteNAT.family))
		if errPrivate == nil {
			remoteNAT.lastPrivateIPRequestID = reqID
		}
	}

	if remoteNAT.endpoint.Spec.GetPublicIP(remoteNAT.family) != "" {
		reqID, errPublic = nd.sendCheckRequestToTargetIP(remoteNAT, remoteNAT.endpoint.Spec.GetPublicIP(remoteNAT.family))
		if errPublic == nil {
			remoteNAT.lastPublicIPRequestID = reqID
		}
	}

	if errPrivate != nil && errPublic != nil {
		return errors.Errorf("error while trying to discover both public & private IPv%v addresses of endpoint %q, [%s, %s]",
			remoteNAT.family, remoteNAT.endpoint.Spec.CableName, errPublic, errPrivate)
	}

	if errPrivate != nil {
		return errors.Wrapf(errPrivate, "error while trying to NAT-discover private IPv%v of endpoint %q",
			remoteNAT.family, remoteNAT.endpoint.Spec.CableName)
	}

	if errPublic != nil {
		return errors.Wrapf(errPublic, "error while trying to NAT-discover public IPv%v of endpoint %q",
			remoteNAT.family, remoteNAT.endpoint.Spec.CableName)
	}

	return nil
}

func (nd *natDiscovery) sendCheckRequestToTargetIP(remoteNAT *remoteEndpointNAT, targetIP string) (uint64, error) {
	targetPort, err := extractNATDiscoveryPort(&remoteNAT.endpoint.Spec)
	if err != nil {
		return 0, err
	}

	sourceIP := nd.FindSourceIP(targetIP, remoteNAT.family)

	nd.requestCounter++

	localEndpointSpec := nd.LocalEndpoint.Spec()

	request := &natproto.SubmarinerNATDiscoveryRequest{
		RequestNumber: nd.requestCounter,
		Sender: &natproto.EndpointDetails{
			EndpointId: localEndpointSpec.GetFamilyCableName(remoteNAT.family),
			ClusterId:  localEndpointSpec.ClusterID,
		},
		Receiver: &natproto.EndpointDetails{
			EndpointId: remoteNAT.endpoint.Spec.GetFamilyCableName(remoteNAT.family),
			ClusterId:  remoteNAT.endpoint.Spec.ClusterID,
		},
		UsingSrc: &natproto.IPPortPair{
			IP:   sourceIP,
			Port: nd.serverPort,
		},
		UsingDst: &natproto.IPPortPair{
			IP:   targetIP,
			Port: targetPort,
		},
	}

	msgRequest := &natproto.SubmarinerNATDiscoveryMessage_Request{
		Request: request,
	}

	message := natproto.SubmarinerNATDiscoveryMessage{
		Version: natproto.Version,
		Message: msgRequest,
	}

	buf, err := proto.Marshal(&message)
	if err != nil {
		return request.GetRequestNumber(), errors.Wrapf(err, "error marshaling request %#v", request)
	}

	addr := net.UDPAddr{
		IP:   net.ParseIP(targetIP),
		Port: int(targetPort),
	}

	logger.V(log.DEBUG).Infof("Sending request - REQUEST_NUMBER: 0x%x, SENDER: %q, RECEIVER: %q, USING_SRC: %s:%d, USING_DST: %s:%d",
		request.GetRequestNumber(), request.GetSender().GetEndpointId(), request.GetReceiver().GetEndpointId(),
		request.GetUsingSrc().GetIP(), request.GetUsingSrc().GetPort(), request.GetUsingDst().GetIP(), request.GetUsingDst().GetPort())

	if length, err := nd.serverUDPWrite[remoteNAT.family](buf, &addr); err != nil {
		return request.GetRequestNumber(), errors.Wrapf(err, "error sending request packet %#v", request)
	} else if length != len(buf) {
		return request.GetRequestNumber(), errors.Errorf("the sent UDP packet was smaller than requested, sent=%d, expected=%d", length,
			len(buf))
	}

	remoteNAT.checkSent()

	return request.GetRequestNumber(), nil
}
