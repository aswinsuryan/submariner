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
	submarinerClientset "github.com/submariner-io/submariner/pkg/client/clientset/versioned"
	"github.com/submariner-io/submariner/pkg/cni"
	"github.com/submariner-io/submariner/pkg/event"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8snet "k8s.io/utils/net"
)

type GatewayRouteHandler struct {
	event.HandlerBase
	smClient  submarinerClientset.Interface
	nextHopIP string
	ipFamily  k8snet.IPFamily
}

func NewGatewayRouteHandler(ipFamily k8snet.IPFamily, smClientSet submarinerClientset.Interface) *GatewayRouteHandler {
	return &GatewayRouteHandler{
		smClient: smClientSet,
		ipFamily: ipFamily,
	}
}

func (h *GatewayRouteHandler) Init(_ context.Context) error {
	logger.Info("Starting GatewayRouteHandler")

	nextHopIP, err := getNextHopOnK8sMgmtIntf(h.ipFamily)
	if err != nil || nextHopIP == "" {
		return errors.Wrapf(err, "error getting the ovn kubernetes management interface IP")
	}

	h.nextHopIP = nextHopIP

	return nil
}

func (h *GatewayRouteHandler) GetName() string {
	return "submariner-gw-route-handler"
}

func (h *GatewayRouteHandler) GetNetworkPlugins() []string {
	return []string{cni.OVNKubernetes}
}

func (h *GatewayRouteHandler) RemoteEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	if h.State().IsOnGateway() {
		gwr := h.newGatewayRoute(endpoint)

		result, err := util.CreateOrUpdate(context.TODO(), GatewayResourceInterface(h.smClient, endpoint.Namespace),
			gwr, util.Replace(gwr))
		if err != nil {
			return errors.Wrapf(err, "error processing the remote endpoint creation for %q", endpoint.Name)
		}

		logger.Infof("GatewayRoute %s from remote endpoint %s: %s", result, endpoint.Name, resource.ToJSON(gwr))
	}

	return nil
}

func (h *GatewayRouteHandler) RemoteEndpointRemoved(endpoint *submarinerv1.Endpoint) error {
	if h.State().IsOnGateway() {
		if err := h.smClient.SubmarinerV1().GatewayRoutes(endpoint.Namespace).Delete(context.TODO(),
			endpoint.Spec.ClusterID, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return errors.Wrapf(err, "error deleting gatewayRoute %q", endpoint.Name)
		}

		logger.Infof("GatewayRoute %s deleted for remote endpoint %s", endpoint.Spec.ClusterID, endpoint.Name)
	}

	return nil
}

func (h *GatewayRouteHandler) TransitionToGateway() error {
	endpoints := h.State().GetRemoteEndpoints()
	for i := range endpoints {
		// This piece of code is designed to manage upgrades from a version lower than 0.16.3 to a higher version,
		// where we utilize the endpoint name as the identifier for gwr. It can be removed once we stop supporting
		// the 0.16 version.
		if err := h.smClient.SubmarinerV1().GatewayRoutes(endpoints[i].Namespace).Delete(context.TODO(),
			endpoints[i].Name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return errors.Wrapf(err, "error deleting gatewayRoute %q", endpoints[i].Name)
		}

		gwr := h.newGatewayRoute(&endpoints[i])

		result, err := util.CreateOrUpdate(context.TODO(), GatewayResourceInterface(h.smClient, endpoints[i].Namespace),
			gwr, util.Replace(gwr))
		if err != nil {
			return errors.Wrapf(err, "error creating/updating GatewayRoute")
		}

		logger.Infof("GatewayRoute %s from remote endpoint %s: %s", result, endpoints[i].Name, resource.ToJSON(gwr))
	}

	return nil
}

func (h *GatewayRouteHandler) newGatewayRoute(endpoint *submarinerv1.Endpoint) *submarinerv1.GatewayRoute {
	return &submarinerv1.GatewayRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name: endpoint.Spec.ClusterID,
		},
		RoutePolicySpec: submarinerv1.RoutePolicySpec{
			RemoteCIDRs: endpoint.Spec.Subnets,
			NextHops:    []string{h.nextHopIP},
		},
	}
}

func GatewayResourceInterface(smClient submarinerClientset.Interface, namespace string) resource.Interface[*submarinerv1.GatewayRoute] {
	return &resource.InterfaceFuncs[*submarinerv1.GatewayRoute]{
		GetFunc:    smClient.SubmarinerV1().GatewayRoutes(namespace).Get,
		CreateFunc: smClient.SubmarinerV1().GatewayRoutes(namespace).Create,
		UpdateFunc: smClient.SubmarinerV1().GatewayRoutes(namespace).Update,
		DeleteFunc: smClient.SubmarinerV1().GatewayRoutes(namespace).Delete,
	}
}
