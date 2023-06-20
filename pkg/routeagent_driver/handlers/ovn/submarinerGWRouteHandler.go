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
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	submarinerClientset "github.com/submariner-io/submariner/pkg/client/clientset/versioned"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/environment"
	"github.com/vishvananda/netlink"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

type GatewayRouteHandler struct {
	event.HandlerBase
	mutex           sync.Mutex
	smClient        submarinerClientset.Interface
	config          *environment.Specification
	remoteEndpoints map[string]*submarinerv1.Endpoint
	isGateway       bool
	nextHopIP       string
}

func NewGatewayRouteHandler(env *environment.Specification, smClientSet submarinerClientset.Interface) *GatewayRouteHandler {
	// We'll panic if env is nil, this is intentional
	return &GatewayRouteHandler{
		config:          env,
		smClient:        smClientSet,
		remoteEndpoints: map[string]*submarinerv1.Endpoint{},
	}
}

func (gatewayRouteHandler *GatewayRouteHandler) Init() error {
	logger.Infof("Starting GatewayRouteHandler")

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) GetName() string {
	return "submariner-gw-route-handler"
}

func (gatewayRouteHandler *GatewayRouteHandler) GetNetworkPlugins() []string {
	// TODO enable when we switch to new implementation
	// return []string{cni.OVNKubernetes}
	return []string{}
}

func (gatewayRouteHandler *GatewayRouteHandler) LocalEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	gatewayRouteHandler.mutex.Lock()
	defer gatewayRouteHandler.mutex.Unlock()

	nextHopIP, err := gatewayRouteHandler.getNextHopOnK8sMgmtIntf(endpoint)

	if err != nil || nextHopIP == nil {
		return errors.Wrapf(err, "error getting the ovn kubernetes management interface IP")
	}

	gatewayRouteHandler.nextHopIP = nextHopIP.String()

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) RemoteEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	gatewayRouteHandler.mutex.Lock()
	defer gatewayRouteHandler.mutex.Unlock()

	if gatewayRouteHandler.isGateway {
		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			_, err := gatewayRouteHandler.smClient.SubmarinerV1().GatewayRoutes(endpoint.Namespace).Create(context.TODO(),
				gatewayRouteHandler.getGatewayRoute(endpoint), metav1.CreateOptions{})
			if !apierrors.IsAlreadyExists(err) {
				return errors.Wrapf(err, "error processing the remote endpoint creation for %q", endpoint.Name)
			}
			return nil
		})

		return errors.Wrapf(retryErr, "processing the remote endpoint event failed even after retry")
	}

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) RemoteEndpointRemoved(endpoint *submarinerv1.Endpoint) error {
	gatewayRouteHandler.mutex.Lock()
	defer gatewayRouteHandler.mutex.Unlock()

	delete(gatewayRouteHandler.remoteEndpoints, endpoint.Name)

	if gatewayRouteHandler.isGateway {
		if err := gatewayRouteHandler.smClient.SubmarinerV1().GatewayRoutes(endpoint.Namespace).Delete(context.TODO(),
			endpoint.Name, metav1.DeleteOptions{}); err != nil {
			return errors.Wrapf(err, "error deleting gatewayRoute %q", endpoint.Name)
		}
	}

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) getNextHopOnK8sMgmtIntf(*submarinerv1.Endpoint) (*net.IP, error) {
	link, err := netlink.LinkByName(OVNK8sMgmntIntfName)

	if err != nil && !errors.Is(err, netlink.LinkNotFoundError{}) {
		return nil, errors.Wrapf(err, "error retrieving link by name %q", OVNK8sMgmntIntfName)
	}

	currentRouteList, err := netlink.RouteList(link, syscall.AF_INET)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving routes on the link %s", OVNK8sMgmntIntfName)
	}

	for i := range currentRouteList {
		logger.V(log.DEBUG).Infof("Processing route %v", currentRouteList[i])

		if currentRouteList[i].Dst == nil || currentRouteList[i].Gw == nil {
			continue
		}

		for _, subnet := range gatewayRouteHandler.config.ClusterCidr {
			if currentRouteList[i].Dst.String() == subnet {
				return &currentRouteList[i].Gw, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find the route to %v via %q", gatewayRouteHandler.config.ClusterCidr, OVNK8sMgmntIntfName)
}

func (gatewayRouteHandler *GatewayRouteHandler) TransitionToNonGateway() error {
	gatewayRouteHandler.mutex.Lock()
	defer gatewayRouteHandler.mutex.Unlock()

	gatewayRouteHandler.isGateway = false

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) TransitionToGateway() error {
	gatewayRouteHandler.mutex.Lock()
	defer gatewayRouteHandler.mutex.Unlock()

	gatewayRouteHandler.isGateway = true

	for _, endpoint := range gatewayRouteHandler.remoteEndpoints {
		err := gatewayRouteHandler.smClient.SubmarinerV1().GatewayRoutes(endpoint.Namespace).DeleteCollection(context.TODO(),
			metav1.DeleteOptions{}, metav1.ListOptions{
				LabelSelector: "owner=submariner.io/ovn",
			})
		if err != nil {
			return errors.Wrapf(err, "error deleting gatewayRoute %q", endpoint.Name)
		}
	}

	for _, endpoint := range gatewayRouteHandler.remoteEndpoints {
		if _, err := gatewayRouteHandler.smClient.SubmarinerV1().GatewayRoutes(endpoint.Namespace).Create(context.TODO(),
			gatewayRouteHandler.getGatewayRoute(endpoint), metav1.CreateOptions{}); err != nil {
			if !apierrors.IsNotFound(err) {
				return errors.Wrapf(err, "error deleting gatewayRoute %q", endpoint.Name)
			}
		}
	}

	return nil
}

func (gatewayRouteHandler *GatewayRouteHandler) getGatewayRoute(endpoint *submarinerv1.Endpoint) *submarinerv1.GatewayRoute {
	return &submarinerv1.GatewayRoute{
		TypeMeta: metav1.TypeMeta{
			Kind:       "GatewayRoute",
			APIVersion: "submariner.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: endpoint.Name,
		},
		RoutePolicySpec: submarinerv1.RoutePolicySpec{
			RemoteCIDRs: endpoint.Spec.Subnets,
			NextHops:    []string{gatewayRouteHandler.nextHopIP},
		},
	}
}
