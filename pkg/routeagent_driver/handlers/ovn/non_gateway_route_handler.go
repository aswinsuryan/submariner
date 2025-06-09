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

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cidr"
	submarinerClientset "github.com/submariner-io/submariner/pkg/client/clientset/versioned"
	"github.com/submariner-io/submariner/pkg/cni"
	"github.com/submariner-io/submariner/pkg/event"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8snet "k8s.io/utils/net"
)

type NonGatewayRouteHandler struct {
	event.HandlerBase
	event.NodeHandlerBase
	smClient        submarinerClientset.Interface
	transitSwitchIP TransitSwitchIP
	ipFamily        k8snet.IPFamily
}

func NewNonGatewayRouteHandler(ipFamily k8snet.IPFamily, smClient submarinerClientset.Interface, transitSwitchIP TransitSwitchIP,
) *NonGatewayRouteHandler {
	return &NonGatewayRouteHandler{
		smClient:        smClient,
		transitSwitchIP: transitSwitchIP,
		ipFamily:        ipFamily,
	}
}

func (h *NonGatewayRouteHandler) Init(_ context.Context) error {
	logger.Info("Starting NonGatewayRouteHandler")
	return nil
}

func (h *NonGatewayRouteHandler) GetName() string {
	return "submariner-nongw-route-handler"
}

func (h *NonGatewayRouteHandler) GetNetworkPlugins() []string {
	return []string{cni.OVNKubernetes}
}

func (h *NonGatewayRouteHandler) RemoteEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	if !h.State().IsOnGateway() || h.transitSwitchIP.Get() == "" {
		return nil
	}

	ngwr := h.newNonGatewayRoute(endpoint)
	if ngwr == nil {
		return nil
	}

	result, err := util.CreateOrUpdate(context.TODO(), NonGatewayResourceInterface(h.smClient, endpoint.Namespace),
		ngwr, util.Replace(ngwr))
	if err != nil {
		return errors.Wrapf(err, "error processing the remote endpoint create event for %q", endpoint.Name)
	}

	logger.Infof("NonGatewayRoute %s from remote endpoint %s: %s", result, endpoint.Name, resource.ToJSON(ngwr))

	return nil
}

func (h *NonGatewayRouteHandler) RemoteEndpointRemoved(endpoint *submarinerv1.Endpoint) error {
	if !h.State().IsOnGateway() || h.transitSwitchIP.Get() == "" {
		return nil
	}

	routeName := endpoint.Spec.ClusterID + familySuffix(h.ipFamily)

	if err := h.smClient.SubmarinerV1().NonGatewayRoutes(endpoint.Namespace).Delete(context.TODO(),
		routeName, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
		return errors.Wrapf(err, "error deleting nonGatewayRoute %q", routeName)
	}

	logger.Infof("NonGatewayRoute %s deleted for remote endpoint %s", routeName, endpoint.Name)

	return nil
}

func (h *NonGatewayRouteHandler) TransitionToGateway() error {
	if h.transitSwitchIP.Get() == "" {
		return nil
	}

	endpoints := h.State().GetRemoteEndpoints()
	for i := range endpoints {
		if err := h.smClient.SubmarinerV1().NonGatewayRoutes(endpoints[i].Namespace).Delete(context.TODO(),
			endpoints[i].Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return errors.Wrapf(err, "error deleting nonGatewayRoute %q", endpoints[i].Name)
		}

		ngwr := h.newNonGatewayRoute(&endpoints[i])
		if ngwr == nil {
			continue
		}

		result, err := util.CreateOrUpdate(context.TODO(),
			NonGatewayResourceInterface(h.smClient, endpoints[i].Namespace), ngwr, util.Replace(ngwr))
		if err != nil {
			return errors.Wrapf(err, "error creating/updating NonGatewayRoute")
		}

		logger.Infof("NonGatewayRoute %s from remote endpoint %s: %s", result, endpoints[i].Name, resource.ToJSON(ngwr))
	}

	return nil
}

func (h *NonGatewayRouteHandler) NodeUpdated(node *corev1.Node) error {
	updated, err := h.transitSwitchIP.UpdateFrom(node)
	if err != nil {
		logger.Errorf(err, "Error updating transit switch IP from node: %s", resource.ToJSON(node))
		return nil
	}

	if !updated {
		return nil
	}

	logger.Infof("Transit switch IP updated to %s", h.transitSwitchIP.Get())

	if !h.State().IsOnGateway() {
		return nil
	}

	endpoints := h.State().GetRemoteEndpoints()
	for i := range endpoints {
		ngwr := h.newNonGatewayRoute(&endpoints[i])
		if ngwr == nil {
			continue
		}

		err = util.Update(context.TODO(), NonGatewayResourceInterface(h.smClient, endpoints[i].Namespace),
			ngwr, func(existing *submarinerv1.NonGatewayRoute) (*submarinerv1.NonGatewayRoute, error) {
				existing.RoutePolicySpec.NextHops = []string{h.transitSwitchIP.Get()}
				return existing, nil
			})
		if err != nil {
			return errors.Wrapf(err, "error updating NonGatewayRoute %q", ngwr.Name)
		}
	}

	return nil
}

func (h *NonGatewayRouteHandler) newNonGatewayRoute(endpoint *submarinerv1.Endpoint) *submarinerv1.NonGatewayRoute {
	famCIDRs := cidr.ExtractSubnets(h.ipFamily, endpoint.Spec.Subnets)

	if len(famCIDRs) == 0 {
		return nil
	}

	return &submarinerv1.NonGatewayRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      endpoint.Spec.ClusterID + familySuffix(h.ipFamily),
			Namespace: endpoint.Namespace,
		},
		RoutePolicySpec: submarinerv1.RoutePolicySpec{
			RemoteCIDRs: famCIDRs,
			NextHops:    []string{h.transitSwitchIP.Get()},
		},
	}
}

func NonGatewayResourceInterface(smClient submarinerClientset.Interface, namespace string,
) resource.Interface[*submarinerv1.NonGatewayRoute] {
	return &resource.InterfaceFuncs[*submarinerv1.NonGatewayRoute]{
		GetFunc:    smClient.SubmarinerV1().NonGatewayRoutes(namespace).Get,
		CreateFunc: smClient.SubmarinerV1().NonGatewayRoutes(namespace).Create,
		UpdateFunc: smClient.SubmarinerV1().NonGatewayRoutes(namespace).Update,
		DeleteFunc: smClient.SubmarinerV1().NonGatewayRoutes(namespace).Delete,
	}
}
