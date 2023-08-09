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
	"sync"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/watcher"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	nodeutil "github.com/submariner-io/submariner/pkg/node"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	clientset "k8s.io/client-go/kubernetes"
)

type NonGatewayRouteController struct {
	nonGatewayRouteWatcher watcher.Interface
	connectionHandler      *ConnectionHandler
	mutex                  sync.Mutex
	remoteSubnets          sets.Set[string]
	stopCh                 chan struct{}
	transitSwitchIP        string
	k8sClientSet           clientset.Interface
}

func NewNonGatewayRouteController(config *watcher.Config, connectionHandler *ConnectionHandler,
	k8sClientSet clientset.Interface, namespace string,
) (*NonGatewayRouteController, error) {
	// We'll panic if config is nil, this is intentional
	var err error

	controller := &NonGatewayRouteController{
		connectionHandler: connectionHandler,
		remoteSubnets:     sets.New[string](),
		k8sClientSet:      k8sClientSet,
	}

	config.ResourceConfigs = []watcher.ResourceConfig{
		{
			Name:         "NonGatewayRoute watcher",
			ResourceType: &submarinerv1.NonGatewayRoute{},
			Handler: watcher.EventHandlerFuncs{
				OnCreateFunc: controller.nonGatewayRouteCreatedorUpdated,
				OnUpdateFunc: controller.nonGatewayRouteCreatedorUpdated,
				OnDeleteFunc: controller.nonGatewayRouteDeleted,
			},
			SourceNamespace: namespace,
		},
	}

	node, err := nodeutil.GetLocalNode(k8sClientSet)
	if err != nil {
		return nil, errors.Wrap(err, "error getting the node")
	}

	annotations := node.GetAnnotations()

	transitSwitchIP := annotations["k8s.ovn.org/node-transit-switch-port-ifaddr"]
	if transitSwitchIP == "" {
		logger.Infof("No transit switch IP configured on node %q", node.Name)
		return controller, nil
	}

	controller.transitSwitchIP, err = jsonToIP(transitSwitchIP)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing transit switch IP")
	}

	controller.nonGatewayRouteWatcher, err = watcher.New(config)

	if err != nil {
		return nil, errors.Wrap(err, "error creating resource watcher")
	}

	err = controller.nonGatewayRouteWatcher.Start(controller.stopCh)
	if err != nil {
		return nil, errors.Wrapf(err, "error starting non gateway route controller")
	}

	logger.Infof("Started NonGatewayRouteController")

	return controller, nil
}

func (g *NonGatewayRouteController) nonGatewayRouteCreatedorUpdated(obj runtime.Object, _ int) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	submGWRoute := obj.(*submarinerv1.NonGatewayRoute)
	if submGWRoute.RoutePolicySpec.NextHops != nil && submGWRoute.RoutePolicySpec.NextHops[0] != g.transitSwitchIP {
		for _, subnet := range submGWRoute.RoutePolicySpec.RemoteCIDRs {
			g.remoteSubnets.Insert(subnet)
		}

		err := g.connectionHandler.reconcileSubOvnLogicalRouterPolicies(g.remoteSubnets, submGWRoute.RoutePolicySpec.NextHops[0])
		if err != nil {
			logger.Errorf(err, "error reconciling router policies for remote subnet %q", g.remoteSubnets)
			return true
		}
	}

	return false
}

func (g *NonGatewayRouteController) nonGatewayRouteDeleted(obj runtime.Object, _ int) bool {
	g.mutex.Lock()
	defer g.mutex.Unlock()

	submGWRoute := obj.(*submarinerv1.NonGatewayRoute)
	if submGWRoute.RoutePolicySpec.NextHops != nil && submGWRoute.RoutePolicySpec.NextHops[0] != g.transitSwitchIP {
		for _, subnet := range submGWRoute.RoutePolicySpec.RemoteCIDRs {
			g.remoteSubnets.Delete(subnet)
		}

		err := g.connectionHandler.reconcileSubOvnLogicalRouterPolicies(g.remoteSubnets, submGWRoute.RoutePolicySpec.NextHops[0])
		if err != nil {
			logger.Errorf(err, "error reconciling router policies for remote subnet %q", g.remoteSubnets)
			return true
		}
	}

	return false
}

func (g *NonGatewayRouteController) stop() {
	if g.transitSwitchIP != "" {
		close(g.stopCh)
	}
}
