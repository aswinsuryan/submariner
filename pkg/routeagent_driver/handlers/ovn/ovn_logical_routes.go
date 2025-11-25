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

package ovn

import (
	"context"
	"strings"
	"time"

	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	libovsdbops "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/libovsdb/ops"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/pkg/errors"
	"github.com/submariner-io/submariner/pkg/versions"
	"k8s.io/apimachinery/pkg/util/sets"
	k8snet "k8s.io/utils/net"
	"k8s.io/utils/ptr"
)

const (
	OVNClusterRouter       = "ovn_cluster_router"
	ovnRoutePoliciesPrioV4 = 20000
	ovnRoutePoliciesPrioV6 = 20100
)

func (c *ConnectionHandler) reconcileOvnLogicalRouterStaticRoutes(remoteSubnets sets.Set[string],
	nextHop string,
) error {
	router, err := c.findLogicalRouter(OVNClusterRouter)
	if err != nil {
		return errors.Wrapf(err, "failed to find ovn cluster router %q", OVNClusterRouter)
	}

	if router.UUID == "" {
		return errors.Errorf("ovn cluster router %q found but has no UUID", OVNClusterRouter)
	}

	staleLRSRPred := func(item *nbdb.LogicalRouterStaticRoute) bool {
		// Legacy routes will have same prefix but different nextHop
		return (item.Nexthop == nextHop && !remoteSubnets.Has(item.IPPrefix)) ||
			(item.Nexthop != nextHop && remoteSubnets.Has(item.IPPrefix))
	}

	err = c.deleteLogicalRouterStaticRoutes(router.UUID, staleLRSRPred)
	if err != nil {
		return errors.Wrapf(err, "failed to delete existing ovn logical route static routes for nexthop: %s", nextHop)
	}

	lrsrToAdd := buildLRSRsFromSubnets(remoteSubnets.UnsortedList(), nextHop)

	for _, lrsr := range lrsrToAdd {
		LRSRPred := func(item *nbdb.LogicalRouterStaticRoute) bool {
			return item.Nexthop == nextHop && item.IPPrefix == lrsr.IPPrefix
		}

		err = c.createOrReplaceLogicalRouterStaticRoute(router.UUID, lrsr, LRSRPred)
		if err != nil {
			return errors.Wrap(err, "failed to create ovn lrsr and add it to the ovn submariner router")
		}
	}

	return nil
}

func buildLRSRsFromSubnets(subnetsToAdd []string, nextHop string) []*nbdb.LogicalRouterStaticRoute {
	toAdd := make([]*nbdb.LogicalRouterStaticRoute, len(subnetsToAdd))

	for i, subnet := range subnetsToAdd {
		toAdd[i] = &nbdb.LogicalRouterStaticRoute{
			Nexthop:  nextHop,
			IPPrefix: subnet,
			ExternalIDs: map[string]string{
				"submariner": versions.Submariner(),
			},
		}
	}

	return toAdd
}

func (c *ConnectionHandler) reconcileSubOvnLogicalRouterPolicies(remoteSubnets sets.Set[string], nextHop string) error {
	router, err := c.findLogicalRouter(OVNClusterRouter)
	if err != nil {
		return errors.Wrapf(err, "failed to find ovn cluster router %q", OVNClusterRouter)
	}

	if router.UUID == "" {
		return errors.Errorf("ovn cluster router %q found but has no UUID", OVNClusterRouter)
	}

	priority := ovnRoutePoliciesPrioV4
	if c.ipFamily == k8snet.IPv6 {
		priority = ovnRoutePoliciesPrioV6
	}

	expectedLRPs := buildLRPsFromSubnets(c.ipFamily, remoteSubnets.UnsortedList(), nextHop, priority)

	lrpStalePredicate := func(item *nbdb.LogicalRouterPolicy) bool {
		if item.Priority != priority {
			return false
		}

		parts := strings.Split(item.Match, " ")
		if len(parts) < 3 {
			return false
		}

		subnet := parts[2]

		return !remoteSubnets.Has(subnet) || item.Nexthop == nil || *item.Nexthop != nextHop
	}

	if err := c.deleteLogicalRouterPolicies(router.UUID, lrpStalePredicate); err != nil {
		return errors.Wrapf(err, "failed to delete stale submariner logical route policies")
	}

	for _, lrp := range expectedLRPs {
		lrpSubPredicate := func(item *nbdb.LogicalRouterPolicy) bool {
			return item.Priority == lrp.Priority &&
				item.Match == lrp.Match &&
				item.Nexthop != nil && *item.Nexthop == *lrp.Nexthop
		}

		if err := c.createOrUpdateLogicalRouterPolicy(router.UUID, lrp, lrpSubPredicate); err != nil {
			return errors.Wrapf(err, "failed to create submariner logical Router policy %v and add it to the ovn cluster router", lrp)
		}
	}

	return nil
}

// getNorthSubnetsToAddAndRemove receives the existing state for the north (other clusters) routes in the OVN
// database, and based on the known remote endpoints it will return the elements that need
// to be added and removed.
func buildLRPsFromSubnets(family k8snet.IPFamily, subnetsToAdd []string, nextHop string, priority int) []*nbdb.LogicalRouterPolicy {
	toAdd := make([]*nbdb.LogicalRouterPolicy, 0, len(subnetsToAdd))

	var ipMatchField string

	if family == k8snet.IPv6 {
		ipMatchField = "ip6.dst"
	} else {
		ipMatchField = "ip4.dst"
	}

	for _, subnet := range subnetsToAdd {
		match := ipMatchField + " == " + subnet

		toAdd = append(toAdd, &nbdb.LogicalRouterPolicy{
			Priority: priority,
			Action:   "reroute",
			Match:    match,
			Nexthop:  ptr.To(nextHop),
			ExternalIDs: map[string]string{
				"submariner": versions.Submariner(),
			},
		})
	}

	return toAdd
}

func (c *ConnectionHandler) findLogicalRouter(name string) (*nbdb.LogicalRouter, error) {
	routers := []*nbdb.LogicalRouter{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.nbdb.WhereCache(func(r *nbdb.LogicalRouter) bool {
		return r.Name == name
	}).List(ctx, &routers)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to list logical routers matching %q", name)
	}

	if len(routers) == 0 {
		return nil, errors.Errorf("logical router %q not found", name)
	}

	return routers[0], nil
}

func (c *ConnectionHandler) createOrUpdateLogicalRouterPolicy(
	routerUUID string,
	lrp *nbdb.LogicalRouterPolicy,
	p func(*nbdb.LogicalRouterPolicy) bool,
) error {
	existingPolicies, err := libovsdbops.FindLogicalRouterPoliciesWithPredicate(c.nbdb, p)
	if err != nil {
		return errors.Wrapf(err, "failed to find existing policies for router %q", routerUUID)
	}

	var ops []ovsdb.Operation

	if len(existingPolicies) > 0 {
		lrp.UUID = existingPolicies[0].UUID

		updateOps, err := c.nbdb.Where(lrp).Update(lrp)
		if err != nil {
			return errors.Wrapf(err, "failed to create update ops for policy %q", lrp.UUID)
		}

		ops = append(ops, updateOps...)
	} else {
		lrp.UUID = "new_lrp"

		createOps, err := c.nbdb.Create(lrp)
		if err != nil {
			return errors.Wrapf(err, "failed to create creation ops for policy %v", lrp)
		}

		ops = append(ops, createOps...)

		routerModel := &nbdb.LogicalRouter{UUID: routerUUID}

		mutateOps, err := c.nbdb.Where(routerModel).Mutate(routerModel, model.Mutation{
			Field:   &routerModel.Policies,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{lrp.UUID},
		})
		if err != nil {
			return errors.Wrapf(err, "failed to create mutate ops for router %q", routerUUID)
		}

		ops = append(ops, mutateOps...)
	}

	_, err = libovsdbops.TransactAndCheck(c.nbdb, ops)

	return errors.Wrapf(err, "failed to transact policy operations for router %q", routerUUID)
}

func (c *ConnectionHandler) createOrReplaceLogicalRouterStaticRoute(
	routerUUID string,
	lrsr *nbdb.LogicalRouterStaticRoute,
	p func(*nbdb.LogicalRouterStaticRoute) bool,
) error {
	existingRoutes, err := libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(c.nbdb, p)
	if err != nil {
		return errors.Wrapf(err, "failed to find existing static routes for router %q", routerUUID)
	}

	var ops []ovsdb.Operation

	if len(existingRoutes) > 0 {
		lrsr.UUID = existingRoutes[0].UUID

		updateOps, err := c.nbdb.Where(lrsr).Update(lrsr)
		if err != nil {
			return errors.Wrapf(err, "failed to create update ops for static route %q", lrsr.UUID)
		}

		ops = append(ops, updateOps...)
	} else {
		lrsr.UUID = "new_lrsr"

		createOps, err := c.nbdb.Create(lrsr)
		if err != nil {
			return errors.Wrapf(err, "failed to create creation ops for static route %v", lrsr.IPPrefix)
		}

		ops = append(ops, createOps...)

		routerModel := &nbdb.LogicalRouter{UUID: routerUUID}

		mutateOps, err := c.nbdb.Where(routerModel).Mutate(routerModel, model.Mutation{
			Field:   &routerModel.StaticRoutes,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   []string{lrsr.UUID},
		})
		if err != nil {
			return errors.Wrapf(err, "failed to create mutate ops for router %q", routerUUID)
		}

		ops = append(ops, mutateOps...)
	}

	_, err = libovsdbops.TransactAndCheck(c.nbdb, ops)

	return errors.Wrapf(err, "failed to transact static route operations for router %q", routerUUID)
}

//nolint:dupl // Similar to deleteLogicalRouterStaticRoutes but uses different types
func (c *ConnectionHandler) deleteLogicalRouterPolicies(
	routerUUID string,
	p func(*nbdb.LogicalRouterPolicy) bool,
) error {
	existing, err := libovsdbops.FindLogicalRouterPoliciesWithPredicate(c.nbdb, p)
	if err != nil {
		return errors.Wrapf(err, "failed to find policies to delete for router %q", routerUUID)
	}

	if len(existing) == 0 {
		return nil
	}

	var ops []ovsdb.Operation

	routerModel := &nbdb.LogicalRouter{UUID: routerUUID}
	uuids := []string{}

	for _, item := range existing {
		uuids = append(uuids, item.UUID)
	}

	mutateOps, err := c.nbdb.Where(routerModel).Mutate(routerModel, model.Mutation{
		Field:   &routerModel.Policies,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   uuids,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create mutate ops to remove policies from router %q", routerUUID)
	}

	ops = append(ops, mutateOps...)

	for _, item := range existing {
		delOps, err := c.nbdb.Where(item).Delete()
		if err != nil {
			return errors.Wrapf(err, "failed to create delete ops for policy %q", item.UUID)
		}

		ops = append(ops, delOps...)
	}

	_, err = libovsdbops.TransactAndCheck(c.nbdb, ops)

	return errors.Wrapf(err, "failed to transact policy deletion for router %q", routerUUID)
}

//nolint:dupl // Similar to deleteLogicalRouterPolicies but uses different types
func (c *ConnectionHandler) deleteLogicalRouterStaticRoutes(
	routerUUID string,
	p func(*nbdb.LogicalRouterStaticRoute) bool,
) error {
	existing, err := libovsdbops.FindLogicalRouterStaticRoutesWithPredicate(c.nbdb, p)
	if err != nil {
		return errors.Wrapf(err, "failed to find static routes to delete for router %q", routerUUID)
	}

	if len(existing) == 0 {
		return nil
	}

	var ops []ovsdb.Operation

	routerModel := &nbdb.LogicalRouter{UUID: routerUUID}
	uuids := []string{}

	for _, item := range existing {
		uuids = append(uuids, item.UUID)
	}

	mutateOps, err := c.nbdb.Where(routerModel).Mutate(routerModel, model.Mutation{
		Field:   &routerModel.StaticRoutes,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   uuids,
	})
	if err != nil {
		return errors.Wrapf(err, "failed to create mutate ops to remove static routes from router %q", routerUUID)
	}

	ops = append(ops, mutateOps...)

	for _, item := range existing {
		delOps, err := c.nbdb.Where(item).Delete()
		if err != nil {
			return errors.Wrapf(err, "failed to create delete ops for static route %q", item.UUID)
		}

		ops = append(ops, delOps...)
	}

	_, err = libovsdbops.TransactAndCheck(c.nbdb, ops)

	return errors.Wrapf(err, "failed to transact static route deletion for router %q", routerUUID)
}
