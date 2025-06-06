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
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/submariner/pkg/cidr"
	cni "github.com/submariner-io/submariner/pkg/cni"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/packetfilter"
	"github.com/submariner-io/submariner/pkg/vxlan"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/set"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type SyncHandler struct {
	event.HandlerBase
	event.NodeHandlerBase
	localEndpointIfaceName string
	localClusterCidr       []string
	localServiceCidr       []string
	ipFamily               k8snet.IPFamily
	remoteSubnets          set.Set[string]
	remoteSubnetGw         map[string]net.IP
	remoteVTEPs            set.Set[string]
	routeCacheGWNode       set.Set[string]
	pFilter                packetfilter.Interface
	netLink                netlink.Interface
	vxlanDevice            *vxlan.Interface
	vxlanGwIP              *net.IP
	vxlanIface             string
	hostname               string
	cniIface               *cni.Interface
	defaultHostIface       netlink.NetworkInterface
	activeEndpointHostname string
	vtepPrefixCIDR         string
}

var logger = log.Logger{Logger: logf.Log.WithName("KubeProxy")}

func GetVxLANInterfaceName(ipFamily k8snet.IPFamily) string {
	vxlanIface := VxLANIface

	if ipFamily == k8snet.IPv6 {
		vxlanIface = VxLANIface + "-" + string(ipFamily)
	}

	return vxlanIface
}

func NewSyncHandler(ipFamily k8snet.IPFamily, localClusterCidr, localServiceCidr []string) *SyncHandler {
	pFilter, err := packetfilter.New(ipFamily)
	utilruntime.Must(err)

	vtepPrefixCIDR := VxLANVTepNetworkPrefixCIDR
	if ipFamily == k8snet.IPv6 {
		vtepPrefixCIDR = VxLANVTepNetworkPrefixCIDRIPv6
	}

	return &SyncHandler{
		ipFamily:         ipFamily,
		localClusterCidr: cidr.ExtractSubnets(ipFamily, localClusterCidr),
		localServiceCidr: cidr.ExtractSubnets(ipFamily, localServiceCidr),
		remoteSubnets:    set.New[string](),
		remoteSubnetGw:   map[string]net.IP{},
		remoteVTEPs:      set.New[string](),
		routeCacheGWNode: set.New[string](),
		netLink:          netlink.New(),
		pFilter:          pFilter,
		vtepPrefixCIDR:   vtepPrefixCIDR,
		vxlanIface:       GetVxLANInterfaceName(ipFamily),
	}
}

func (kp *SyncHandler) GetName() string {
	return fmt.Sprintf("Kubeproxy IPv%s", kp.ipFamily)
}

func (kp *SyncHandler) GetNetworkPlugins() []string {
	networkPlugins := []string{}

	// This handles everything but OVN
	for _, plugin := range cni.GetNetworkPlugins() {
		if plugin != cni.OVNKubernetes {
			networkPlugins = append(networkPlugins, plugin)
		}
	}

	return networkPlugins
}

var discoverCNIRetryConfig = wait.Backoff{
	Cap:      1 * time.Minute,
	Duration: 4 * time.Second,
	Factor:   1.2,
	Steps:    12,
}

func (kp *SyncHandler) Init(_ context.Context) error {
	var err error
	var cniIface *cni.Interface

	kp.hostname, err = os.Hostname()
	if err != nil {
		return errors.Wrapf(err, "unable to determine hostname")
	}

	kp.defaultHostIface, err = kp.netLink.GetDefaultGatewayInterface(kp.ipFamily)
	if err != nil {
		return errors.Wrapf(err, "Unable to find the default interface on host: %s", kp.hostname)
	}

	err = retry.OnError(discoverCNIRetryConfig, func(err error) bool {
		logger.Infof("Waiting for CNI interface discovery: %s", err)
		return true
	}, func() error {
		cniIface, err = cni.Discover(kp.localClusterCidr, kp.ipFamily)
		if err != nil {
			return errors.Wrapf(err, "Error discovering the CNI interface")
		}

		return nil
	})
	if err == nil {
		// Configure CNI Specific changes
		kp.cniIface = cniIface

		err := kp.netLink.EnableLooseModeReversePathFilter(kp.cniIface.Name, kp.ipFamily)
		if err != nil {
			return errors.Wrap(err, "error enabling loose mode")
		}
	} else {
		// This is not a fatal error. Connectivity and other datapath use-cases will continue
		// to work, but the following use-cases may not work.
		// 1. Hostnetworking to remote cluster support will be broken
		// 2. Health-check verification between the Gateway nodes will be disabled
		logger.Errorf(err, "Error discovering the CNI interface")
	}

	// Create the necessary IPTable chains in the filter and nat tables.
	err = kp.createPFilterChains()
	if err != nil {
		return errors.Wrapf(err, "createPFilterChains returned error")
	}

	return nil
}
