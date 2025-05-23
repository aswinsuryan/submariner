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

package vxlan

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cni"
	submendpoint "github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/natdiscovery"
	netlinkAPI "github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/submariner-io/submariner/pkg/vxlan"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	VxlanIface                 = "vxlan-tunnel"
	VxlanVTepNetworkPrefixCIDR = "241.0.0.0/8"
	CableDriverName            = "vxlan"
	TableID                    = 100
	DefaultPort                = 4500
)

type vxLan struct {
	localEndpoint v1.EndpointSpec
	localCluster  types.SubmarinerCluster
	connections   []v1.Connection
	mutex         sync.Mutex
	vxlanIface    *vxlan.Interface
	netLink       netlinkAPI.Interface
	vtepIP        net.IP
}

var logger = log.Logger{Logger: logf.Log.WithName("vxlan")}

func init() {
	cable.AddDriver(CableDriverName, NewDriver)
}

func NewDriver(localEndpoint *submendpoint.Local, localCluster *types.SubmarinerCluster) (cable.Driver, error) {
	// We'll panic if localEndpoint or localCluster are nil, this is intentional
	var err error

	v := vxLan{
		localEndpoint: *localEndpoint.Spec(),
		netLink:       netlinkAPI.New(),
		localCluster:  *localCluster,
	}

	if strings.EqualFold(v.localEndpoint.CableName, CableDriverName) && v.localEndpoint.NATEnabled {
		logger.Warning("VxLan cable-driver is supported only with no NAT deployments")
	}

	port, err := v.localEndpoint.GetBackendPort(v1.UDPPortConfig, DefaultPort)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the UDP port configuration")
	}

	if err = v.createVxlanInterface(int(port)); err != nil {
		return nil, errors.Wrap(err, "failed to setup Vxlan link")
	}

	return &v, nil
}

func (v *vxLan) createVxlanInterface(port int) error {
	ipAddr := v.localEndpoint.GetPrivateIP(k8snet.IPv4)

	var err error

	v.vtepIP, err = vxlan.GetVtepIPAddressFrom(ipAddr, VxlanVTepNetworkPrefixCIDR, k8snet.IPv4)
	if err != nil {
		return errors.Wrapf(err, "failed to derive the vxlan vtepIP for %s", ipAddr)
	}

	defaultHostIface, err := v.netLink.GetDefaultGatewayInterface(k8snet.IPv4)
	if err != nil {
		return errors.Wrapf(err, "Unable to find the default interface on host: %s",
			v.localEndpoint.Hostname)
	}

	attrs := &vxlan.Attributes{
		Name:     VxlanIface,
		VxlanID:  1000,
		Group:    nil,
		SrcAddr:  nil,
		VtepPort: port,
		Mtu:      defaultHostIface.MTU(),
	}

	v.vxlanIface, err = vxlan.NewInterface(attrs, v.netLink)
	if err != nil {
		return errors.Wrap(err, "failed to create vxlan interface on Gateway Node")
	}

	err = v.netLink.RuleAddIfNotPresent(netlinkAPI.NewTableRule(TableID, k8snet.IPv4))
	if err != nil && !os.IsExist(err) {
		return errors.Wrap(err, "failed to add ip rule")
	}

	err = v.netLink.EnsureLooseModeIsConfigured(VxlanIface, k8snet.IPv4)
	if err != nil {
		return errors.Wrap(err, "error while validating loose mode")
	}

	logger.V(log.DEBUG).Infof("Successfully configured rp_filter to loose mode(2) on %s", VxlanIface)

	err = v.vxlanIface.ConfigureIPAddress(v.vtepIP, net.CIDRMask(8, 32))
	if err != nil {
		return errors.Wrap(err, "failed to configure vxlan interface ipaddress on the Gateway Node")
	}

	err = v.netLink.EnableForwarding(VxlanIface, k8snet.IPv4)
	if err != nil {
		return errors.Wrapf(err, "error enabling forwarding on the %q iface", VxlanIface)
	}

	return nil
}

func (v *vxLan) ConnectToEndpoint(endpointInfo *natdiscovery.NATEndpointInfo) (string, error) {
	// We'll panic if endpointInfo is nil, this is intentional
	remoteEndpoint := endpointInfo.Endpoint
	if v.localEndpoint.ClusterID == remoteEndpoint.Spec.ClusterID {
		logger.V(log.DEBUG).Infof("Will not connect to self")
		return "", nil
	}

	remoteIP := net.ParseIP(endpointInfo.UseIP)
	if remoteIP == nil {
		return "", fmt.Errorf("failed to parse remote IP %s", endpointInfo.UseIP)
	}

	allowedIPs := remoteEndpoint.Spec.ParseSubnets(endpointInfo.UseFamily)

	logger.V(log.DEBUG).Infof("Connecting cluster %s endpoint %s",
		remoteEndpoint.Spec.ClusterID, remoteIP)
	v.mutex.Lock()
	defer v.mutex.Unlock()

	cable.RecordConnection(CableDriverName, &v.localEndpoint, &remoteEndpoint.Spec, string(v1.Connected), true, endpointInfo.UseFamily)

	privateIP := endpointInfo.Endpoint.Spec.GetPrivateIP(endpointInfo.UseFamily)

	remoteVtepIP, err := vxlan.GetVtepIPAddressFrom(privateIP, VxlanVTepNetworkPrefixCIDR, k8snet.IPv4)
	if err != nil {
		return endpointInfo.UseIP, fmt.Errorf("failed to derive the vxlan vtepIP for %s: %w", privateIP, err)
	}

	err = v.vxlanIface.AddFDB(remoteIP, "00:00:00:00:00:00")
	if err != nil {
		return endpointInfo.UseIP, fmt.Errorf("failed to add remoteIP %q to the forwarding database: %w", remoteIP, err)
	}

	var ipAddress net.IP

	cniIface, err := cni.Discover(v.localCluster.Spec.ClusterCIDR, endpointInfo.UseFamily)
	if err == nil {
		ipAddress = net.ParseIP(cniIface.IPAddress)
	} else {
		logger.Errorf(nil, "Failed to get the CNI interface IP for cluster CIDR %q, host-networking use-cases may not work",
			v.localCluster.Spec.ClusterCIDR[0])
	}

	err = v.vxlanIface.AddRoutes(remoteVtepIP, ipAddress, TableID, allowedIPs...)
	if err != nil {
		return endpointInfo.UseIP, fmt.Errorf("failed to add route for the CIDR %q with remoteVtepIP %q and vxlanInterfaceIP %q: %w",
			allowedIPs, remoteVtepIP, v.vtepIP, err)
	}

	v.connections = append(v.connections, v1.Connection{
		Endpoint: remoteEndpoint.Spec, Status: v1.Connected,
		UsingIP: endpointInfo.UseIP, UsingNAT: endpointInfo.UseNAT,
	})

	logger.V(log.DEBUG).Infof("Done adding endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return endpointInfo.UseIP, nil
}

func (v *vxLan) DisconnectFromEndpoint(remoteEndpoint *types.SubmarinerEndpoint, family k8snet.IPFamily) error {
	// We'll panic if remoteEndpoint is nil, this is intentional
	logger.V(log.DEBUG).Infof("Removing IPv%v endpoint %#v", family, remoteEndpoint)

	if v.localEndpoint.ClusterID == remoteEndpoint.Spec.ClusterID {
		logger.V(log.DEBUG).Infof("Will not disconnect self")
		return nil
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	var ip string

	for i := range v.connections {
		if v.connections[i].Endpoint.CableName == remoteEndpoint.Spec.CableName {
			ip = v.connections[i].UsingIP
		}
	}

	if ip == "" {
		logger.Errorf(nil, "Cannot disconnect remote endpoint %q - no prior connection entry found", remoteEndpoint.Spec.CableName)
		return nil
	}

	remoteIP := net.ParseIP(ip)

	if remoteIP == nil {
		return fmt.Errorf("failed to parse remote IP %s", ip)
	}

	allowedIPs := remoteEndpoint.Spec.ParseSubnets(k8snet.IPv4)

	err := v.vxlanIface.DelFDB(remoteIP, "00:00:00:00:00:00")
	if err != nil {
		return fmt.Errorf("failed to delete remoteIP %q from the forwarding database: %w", remoteIP, err)
	}

	err = v.vxlanIface.DelRoutes(TableID, allowedIPs...)
	if err != nil {
		return fmt.Errorf("failed to remove route for the CIDR %q: %w", allowedIPs, err)
	}

	v.connections = removeConnectionForEndpoint(v.connections, remoteEndpoint)
	cable.RecordDisconnected(CableDriverName, &v.localEndpoint, &remoteEndpoint.Spec, family)

	logger.V(log.DEBUG).Infof("Done removing endpoint for cluster %s", remoteEndpoint.Spec.ClusterID)

	return nil
}

func removeConnectionForEndpoint(connections []v1.Connection, endpoint *types.SubmarinerEndpoint) []v1.Connection {
	for j := range connections {
		if connections[j].Endpoint.CableName == endpoint.Spec.CableName {
			copy(connections[j:], connections[j+1:])
			return connections[:len(connections)-1]
		}
	}

	return connections
}

func (v *vxLan) GetConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vxLan) GetActiveConnections() ([]v1.Connection, error) {
	return v.connections, nil
}

func (v *vxLan) Init() error {
	return nil
}

func (v *vxLan) GetName() string {
	return CableDriverName
}

func (v *vxLan) Cleanup() error {
	logger.Infof("Uninstalling the vxlan cable driver")

	err := netlinkAPI.DeleteIfaceAndAssociatedRoutes(VxlanIface, TableID)
	if err != nil {
		logger.Errorf(nil, "Unable to delete interface %s and associated routes from table %d", VxlanIface, TableID)
	}

	err = v.netLink.RuleDelIfPresent(netlinkAPI.NewTableRule(TableID, k8snet.IPv4))
	if err != nil {
		return errors.Wrapf(err, "unable to delete IP rule pointing to %d table", TableID)
	}

	return nil
}
