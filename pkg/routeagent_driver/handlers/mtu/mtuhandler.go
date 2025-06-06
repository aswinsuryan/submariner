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

package mtu

import (
	"context"
	"fmt"
	"strconv"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	submV1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	vxlandriver "github.com/submariner-io/submariner/pkg/cable/vxlan"
	"github.com/submariner-io/submariner/pkg/cidr"
	"github.com/submariner-io/submariner/pkg/event"
	netlinkAPI "github.com/submariner-io/submariner/pkg/netlink"
	"github.com/submariner-io/submariner/pkg/packetfilter"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/constants"
	"github.com/submariner-io/submariner/pkg/vxlan"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type forceMssSts int

const (
	notNeeded forceMssSts = iota
	needed
	configured
)

const (
	// TCP MSS = Default_Iface_MTU - TCP_H(20)-IP_H(20)-max_IpsecOverhed(80).
	MaxIPSecOverhead    = 120
	RemoteCIDRIPSetIPv4 = "SUBMARINER-REMOTECIDRS"
	LocalCIDRIPSetIPv4  = "SUBMARINER-LOCALCIDRS"
	RemoteCIDRIPSetIPv6 = "SUBMARINER-REMOTECIDRS-V6"
	LocalCIDRIPSetIPv6  = "SUBMARINER-LOCALCIDRS-V6"
)

type mtuHandler struct {
	event.HandlerBase
	ipFamily         k8snet.IPFamily
	localClusterCidr []string
	pFilter          packetfilter.Interface
	tableType        packetfilter.TableType
	chainType        packetfilter.ChainType
	remoteIPSet      packetfilter.NamedSet
	localIPSet       packetfilter.NamedSet
	forceMss         forceMssSts
	tcpMssValue      int
	localCIDRIPSet   string
	remoteCIDRIPSet  string
}

var logger = log.Logger{Logger: logf.Log.WithName("MTU")}

func NewHandler(ipFamily k8snet.IPFamily, localClusterCidr []string, isGlobalnet bool, tcpMssValue int) event.Handler {
	forceMss := notNeeded
	if isGlobalnet || tcpMssValue != 0 {
		forceMss = needed
	}

	h := &mtuHandler{
		ipFamily:         ipFamily,
		localClusterCidr: cidr.ExtractSubnets(ipFamily, localClusterCidr),
		forceMss:         forceMss,
		tcpMssValue:      tcpMssValue,
		localCIDRIPSet:   LocalCIDRIPSetIPv4,
		remoteCIDRIPSet:  RemoteCIDRIPSetIPv4,
	}

	if ipFamily == k8snet.IPv6 {
		h.localCIDRIPSet = LocalCIDRIPSetIPv6
		h.remoteCIDRIPSet = RemoteCIDRIPSetIPv6
	}

	return h
}

func (h *mtuHandler) GetNetworkPlugins() []string {
	return []string{event.AnyNetworkPlugin}
}

func (h *mtuHandler) GetName() string {
	return fmt.Sprintf("MTU handler IPv%s", h.ipFamily)
}

func (h *mtuHandler) Init(_ context.Context) error {
	var err error

	h.pFilter, err = packetfilter.New(h.ipFamily)
	if err != nil {
		return errors.Wrap(err, "error initializing iptables")
	}

	h.tableType, h.chainType = h.pFilter.GetMSSClampTypes()

	if err := h.pFilter.CreateIPHookChainIfNotExists(&packetfilter.ChainIPHook{
		Name:     constants.SmPostRoutingMssChain,
		Type:     h.chainType,
		Hook:     packetfilter.ChainHookPostrouting,
		Priority: packetfilter.ChainPriorityFirst,
	}); err != nil {
		return errors.Wrapf(err, "error creating IPHookChain chain %s", constants.SmPostRoutingMssChain)
	}

	h.remoteIPSet = h.newNamedSetSet(h.remoteCIDRIPSet)
	if err := h.remoteIPSet.Create(true); err != nil {
		return errors.Wrapf(err, "error creating ipset %q", h.remoteCIDRIPSet)
	}

	h.localIPSet = h.newNamedSetSet(h.localCIDRIPSet)
	if err := h.localIPSet.Create(true); err != nil {
		return errors.Wrapf(err, "error creating ipset %q", h.localCIDRIPSet)
	}

	// packetfilter rules to clamp TCP MSS to a fixed value will be programmed when the local endpoint is created
	if h.forceMss == needed {
		return nil
	}

	logger.Info("Creating packetfilter clamp-mss-to-pmtu rules")

	ruleSpecSource := &packetfilter.Rule{
		SrcSetName:  h.localCIDRIPSet,
		DestSetName: h.remoteCIDRIPSet,
		Action:      packetfilter.RuleActionMss,
		ClampType:   packetfilter.ToPMTU,
	}

	ruleSpecDest := &packetfilter.Rule{
		SrcSetName:  h.remoteCIDRIPSet,
		DestSetName: h.localCIDRIPSet,
		Action:      packetfilter.RuleActionMss,
		ClampType:   packetfilter.ToPMTU,
	}

	if err := h.pFilter.AppendUnique(h.tableType, constants.SmPostRoutingMssChain, ruleSpecSource); err != nil {
		return errors.Wrapf(err, "error appending packetfilter rule %q", ruleSpecSource)
	}

	if err := h.pFilter.AppendUnique(h.tableType, constants.SmPostRoutingMssChain, ruleSpecDest); err != nil {
		return errors.Wrapf(err, "error appending packetfilter rule %q", ruleSpecDest)
	}

	return nil
}

func (h *mtuHandler) LocalEndpointCreated(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(h.ipFamily, endpoint.Spec.Subnets)
	for _, subnet := range subnets {
		err := h.localIPSet.AddEntry(subnet, true)
		if err != nil {
			return errors.Wrap(err, "error adding local IP set entry")
		}
	}

	for _, subnet := range h.localClusterCidr {
		err := h.localIPSet.AddEntry(subnet, true)
		if err != nil {
			return errors.Wrap(err, "error adding localClusterCidr IP set entry")
		}
	}

	if h.forceMss == needed {
		logger.Info("Creating packetfilter set-mss rules")

		err := h.forceMssClamping(endpoint)
		if err != nil {
			return errors.Wrap(err, "error forcing TCP MSS clamping")
		}

		h.forceMss = configured
	}

	return nil
}

func (h *mtuHandler) LocalEndpointRemoved(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(h.ipFamily, endpoint.Spec.Subnets)
	for _, subnet := range subnets {
		logError(h.localIPSet.DelEntry(subnet), "Error deleting the subnet %q from the local IPSet", subnet)
	}

	for _, subnet := range h.localClusterCidr {
		logError(h.localIPSet.DelEntry(subnet), "Error deleting the subnet %q from the local IPSet", subnet)
	}

	return nil
}

func (h *mtuHandler) RemoteEndpointCreated(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(h.ipFamily, endpoint.Spec.Subnets)
	for _, subnet := range subnets {
		err := h.remoteIPSet.AddEntry(subnet, true)
		if err != nil {
			return errors.Wrap(err, "error adding remote IP set entry")
		}
	}

	return nil
}

func (h *mtuHandler) RemoteEndpointRemoved(endpoint *submV1.Endpoint) error {
	subnets := cidr.ExtractSubnets(h.ipFamily, endpoint.Spec.Subnets)
	for _, subnet := range subnets {
		logError(h.remoteIPSet.DelEntry(subnet), "Error deleting the subnet %q from the remote IPSet", subnet)
	}

	return nil
}

func (h *mtuHandler) newNamedSetSet(key string) packetfilter.NamedSet {
	return h.pFilter.NewNamedSet(&packetfilter.SetInfo{
		Name: key,
	})
}

func (h *mtuHandler) Uninstall() error {
	logger.Infof("Flushing packetfilter entries in %q chain of table type %q", constants.SmPostRoutingMssChain, h.tableType.String())

	logError(h.pFilter.ClearChain(h.tableType, constants.SmPostRoutingMssChain),
		"Error flushing chain %q of table type %q", constants.SmPostRoutingMssChain, h.tableType.String())

	logger.Infof("Deleting IPHook chain %q of table type %q", constants.SmPostRoutingMssChain, h.tableType.String())

	logError(h.pFilter.DeleteIPHookChain(&packetfilter.ChainIPHook{
		Name:     constants.SmPostRoutingMssChain,
		Type:     h.chainType,
		Hook:     packetfilter.ChainHookPostrouting,
		Priority: packetfilter.ChainPriorityFirst,
	}), "Error deleting IP hook chain %q of table type %q", constants.SmPostRoutingMssChain, h.tableType.String())

	logError(h.localIPSet.Flush(), "Error flushing ipset %q", h.localCIDRIPSet)

	logError(h.localIPSet.Destroy(), "Error deleting ipset %q", h.localCIDRIPSet)

	logError(h.remoteIPSet.Flush(), "Error flushing ipset %q", h.remoteCIDRIPSet)

	logError(h.remoteIPSet.Destroy(), "Error deleting ipset %q", h.remoteCIDRIPSet)

	return nil
}

func (h *mtuHandler) forceMssClamping(endpoint *submV1.Endpoint) error {
	tcpMssSrc := "user"
	tcpMssValue := h.tcpMssValue

	if tcpMssValue == 0 {
		defaultHostIface, err := netlinkAPI.New().GetDefaultGatewayInterface(h.ipFamily)
		if err != nil {
			return errors.Wrapf(err, "Unable to find the default interface on host")
		}

		overHeadSize := MaxIPSecOverhead
		if endpoint.Spec.Backend == vxlandriver.CableDriverName {
			overHeadSize = vxlan.MTUOverhead
		}

		tcpMssValue = defaultHostIface.MTU() - overHeadSize
		tcpMssSrc = "default"
	}

	logger.Infof("forceMssClamping to: %d (%s) ", tcpMssValue, tcpMssSrc)

	rules := []*packetfilter.Rule{}

	rules = append(rules, &packetfilter.Rule{
		SrcSetName:  h.localCIDRIPSet,
		DestSetName: h.remoteCIDRIPSet,
		Action:      packetfilter.RuleActionMss,
		ClampType:   packetfilter.ToValue,
		MssValue:    strconv.Itoa(tcpMssValue),
	}, &packetfilter.Rule{
		DestSetName: h.localCIDRIPSet,
		SrcSetName:  h.remoteCIDRIPSet,
		Action:      packetfilter.RuleActionMss,
		ClampType:   packetfilter.ToValue,
		MssValue:    strconv.Itoa(tcpMssValue),
	},
	)

	if err := h.pFilter.UpdateChainRules(h.tableType, constants.SmPostRoutingMssChain, rules); err != nil {
		return errors.Wrapf(err, "error updating chain %s table type %q", constants.SmPostRoutingMssChain, h.tableType.String())
	}

	return nil
}

func logError(err error, format string, args ...interface{}) {
	if err != nil {
		logger.Errorf(err, format, args...)
	}
}
