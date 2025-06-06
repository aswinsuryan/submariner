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

package kubeproxy

import (
	"net"

	"github.com/pkg/errors"
	submV1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cidr"
	"github.com/submariner-io/submariner/pkg/vxlan"
	k8snet "k8s.io/utils/net"
)

func (kp *SyncHandler) LocalEndpointCreated(endpoint *submV1.Endpoint) error {
	kp.localEndpointIfaceName = endpoint.Spec.BackendConfig[cable.InterfaceNameConfig]

	localClusterGwNodeIP := net.ParseIP(endpoint.Spec.GetPrivateIP(kp.ipFamily))

	// We are on nonGateway node
	if !kp.State().IsOnGateway() {
		// If the node already has a vxLAN interface that points to an oldEndpoint
		// (i.e., during gateway migration), delete it.
		if kp.vxlanDevice != nil && kp.activeEndpointHostname != endpoint.Spec.Hostname {
			err := kp.vxlanDevice.DeleteLinkDevice()
			if err != nil {
				return errors.Wrapf(err, "failed to delete the vxlan interface that points to old endpoint %s",
					kp.activeEndpointHostname)
			}

			kp.vxlanDevice = nil
			kp.activeEndpointHostname = ""
		}

		remoteVtepIP, err := vxlan.GetVtepIPAddressFrom(localClusterGwNodeIP.String(), kp.vtepPrefixCIDR, kp.ipFamily)
		if err != nil {
			return errors.Wrap(err, "failed to derive the remoteVtepIP")
		}

		logger.Infof("Creating the vxlan interface %s with gateway node IP %s", kp.vxlanIface, localClusterGwNodeIP)

		err = kp.createVxLANInterface(VxInterfaceWorker, localClusterGwNodeIP)
		if err != nil {
			logger.Fatalf("Unable to create VxLAN interface on non-GatewayNode (%s): %v", endpoint.Spec.Hostname, err)
		}

		kp.vxlanGwIP = &remoteVtepIP
		kp.activeEndpointHostname = endpoint.Spec.Hostname

		err = kp.reconcileRoutes(remoteVtepIP)
		if err != nil {
			return errors.Wrap(err, "error while reconciling routes")
		}
	} else {
		// Store local endpoint's private IP to use as the source address for the IPv6 VxLAN interface on GW.
		kp.vxlanGwIP = &localClusterGwNodeIP
	}

	return nil
}

func (kp *SyncHandler) LocalEndpointRemoved(endpoint *submV1.Endpoint) error {
	// If the vxLAN device exists and it points to the same endpoint, delete it.
	if kp.vxlanDevice != nil && kp.activeEndpointHostname == endpoint.Spec.Hostname {
		err := kp.vxlanDevice.DeleteLinkDevice()
		kp.vxlanDevice = nil
		kp.vxlanGwIP = nil
		kp.activeEndpointHostname = ""

		if err != nil {
			return errors.Wrap(err, "failed to delete the vxlan interface on Endpoint removal")
		}
	}

	return nil
}

func (kp *SyncHandler) RemoteEndpointCreated(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(kp.ipFamily, endpoint.Spec.Subnets)

	if err := cidr.OverlappingSubnets(kp.localServiceCidr, kp.localClusterCidr, subnets); err != nil {
		// Skip processing the endpoint when CIDRs overlap and return nil to avoid re-queuing.
		logger.Errorf(err, "overlappingSubnets for new remote %#v returned error", endpoint)
		return nil
	}

	for _, inputCidrBlock := range subnets {
		if !kp.remoteSubnets.Has(inputCidrBlock) {
			kp.remoteSubnets.Insert(inputCidrBlock)
		}

		gwIP := endpoint.Spec.GatewayIP(kp.ipFamily)
		kp.remoteSubnetGw[inputCidrBlock] = gwIP
	}

	if err := kp.updateRoutingRulesForInterClusterSupport(subnets, Add); err != nil {
		logger.Errorf(err, "updateRoutingRulesForInterClusterSupport for new remote %#v returned error",
			endpoint)
		return err
	}

	// Add routes to the new endpoint on the GatewayNode.
	kp.updateRoutingRulesForHostNetworkSupport(subnets, Add)
	kp.updateIptableRulesForInterClusterTraffic(subnets, Add)

	return nil
}

func (kp *SyncHandler) RemoteEndpointRemoved(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(kp.ipFamily, endpoint.Spec.Subnets)

	for _, inputCidrBlock := range subnets {
		kp.remoteSubnets.Delete(inputCidrBlock)
		delete(kp.remoteSubnetGw, inputCidrBlock)
	}

	if err := kp.updateRoutingRulesForInterClusterSupport(subnets, Delete); err != nil {
		logger.Errorf(err, "updateRoutingRulesForInterClusterSupport for removed remote %#v returned error",
			endpoint)
		return err
	}

	kp.updateRoutingRulesForHostNetworkSupport(subnets, Delete)
	kp.updateIptableRulesForInterClusterTraffic(subnets, Delete)

	return nil
}

func (kp *SyncHandler) getHostIfaceIPAddress() (net.IP, error) {
	addrs, err := kp.defaultHostIface.Addrs()
	if err != nil {
		return nil, errors.Wrap(err, "error getting default host addresses")
	}

	for i := range addrs {
		ipAddr, _, err := net.ParseCIDR(addrs[i].String())
		if err != nil {
			return nil, errors.Errorf("unable to parse CIDR : %s", addrs[i])
		}

		if k8snet.IPFamilyOf(ipAddr) == kp.ipFamily {
			return ipAddr, nil
		}
	}

	return nil, errors.Errorf("no default host interface IP found: %v", addrs)
}
