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

//nolint:wrapcheck // Most of the functions are simple wrappers so we'll let the caller wrap errors.
package netlink

import (
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/vishvananda/netlink"
	k8snet "k8s.io/utils/net"
)

type Adapter struct {
	Basic
}

func (a *Adapter) RuleAddIfNotPresent(rule *netlink.Rule) error {
	err := a.RuleAdd(rule)
	if err != nil && !os.IsExist(err) {
		return errors.Wrapf(err, "failed to add rule %s", rule)
	}

	return nil
}

func (a *Adapter) RuleDelIfPresent(rule *netlink.Rule) error {
	err := a.RuleDel(rule)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "failed to delete rule %s", rule)
	}

	return nil
}

func (a *Adapter) RouteAddOrReplace(route *netlink.Route) error {
	err := a.RouteAdd(route)

	if errors.Is(err, syscall.EEXIST) {
		err = a.RouteReplace(route)
	}

	return err
}

func (a *Adapter) AddDestinationRoutes(destIPs []net.IPNet, gwIP, srcIP net.IP, linkIndex, tableID int) error {
	for i := range destIPs {
		route := &netlink.Route{
			LinkIndex: linkIndex,
			Src:       srcIP,
			Dst:       &destIPs[i],
			Gw:        gwIP,
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     tableID,
		}

		err := a.RouteAddOrReplace(route)
		if err != nil {
			return errors.Wrapf(err, "unable to add the route entry %#v", route)
		}
	}

	return nil
}

func (a *Adapter) DeleteDestinationRoutes(destIPs []net.IPNet, linkIndex, tableID int) error {
	for i := range destIPs {
		route := &netlink.Route{
			LinkIndex: linkIndex,
			Dst:       &destIPs[i],
			Type:      netlink.NDA_DST,
			Flags:     netlink.NTF_SELF,
			Priority:  100,
			Table:     tableID,
		}

		err := netlink.RouteDel(route)
		if err != nil {
			return errors.Wrapf(err, "unable to delete the route entry %#v", route)
		}
	}

	return nil
}

func (a *Adapter) AddrAddIfNotPresent(link netlink.Link, addr *netlink.Addr) error {
	err := netlink.AddrAdd(link, addr)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		return nil
	}

	return err
}

func (a *Adapter) GetDefaultGatewayInterface(family k8snet.IPFamily) (NetworkInterface, error) {
	routes, err := a.RouteList(nil, family)
	if err != nil {
		return nil, err
	}

	for i := range routes {
		if (routes[i].Dst == nil || routes[i].Dst.String() == allZeroesFamilyAddress[family]) && routes[i].LinkIndex > 0 {
			return a.InterfaceByIndex(routes[i].LinkIndex)
		}
	}

	return nil, errors.Errorf("default gateway interface could not be determined from routes: %s", resource.ToJSON(routes))
}
