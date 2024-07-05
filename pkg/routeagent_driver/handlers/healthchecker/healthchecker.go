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

package healthchecker

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	v1typed "github.com/submariner-io/submariner/pkg/client/clientset/versioned/typed/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/pinger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	RouteAgentUpdateInterval = 60 * time.Second
)

const UpdateTimestampAnnotation = "update-timestamp"

type Config struct {
	PingInterval         uint
	MaxPacketLossCount   uint
	HealthCheckerEnabled bool
	NewPinger            func(pinger.Config) pinger.Interface
}

type controller struct {
	event.HandlerBase
	sync.RWMutex
	pingers        map[string]pinger.Interface
	localNodeName  string
	remoteEndpoint map[string]*submarinerv1.Endpoint
	version        string
	config         *Config
	stopCh         chan struct{}
	client         v1typed.RouteAgentInterface
}

var logger = log.Logger{Logger: logf.Log.WithName("HealthChecker")}

func NewHealthCheckerHandler(config *Config, client v1typed.RouteAgentInterface, version, nodeName string) event.Handler {
	controller := &controller{
		pingers:        map[string]pinger.Interface{},
		remoteEndpoint: map[string]*submarinerv1.Endpoint{},
		config:         config,
		version:        version,
		client:         client,
		stopCh:         make(chan struct{}),
		localNodeName:  nodeName,
	}

	return controller
}

func (h *controller) Stop() error {
	h.Lock()
	defer h.Unlock()

	for _, p := range h.pingers {
		p.Stop()
	}

	h.pingers = map[string]pinger.Interface{}

	close(h.stopCh)

	err := h.client.Delete(context.TODO(),
		h.localNodeName, metav1.DeleteOptions{})
	if err != nil {
		logger.Warningf("Error deleting RouteAgent: %s: %v", h.localNodeName, err)
	}

	return nil
}

func (h *controller) RemoteEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	if !h.config.HealthCheckerEnabled && h.State().IsOnGateway() {
		return nil
	}

	h.remoteEndpoint[endpoint.Name] = endpoint

	return h.processEndpointCreatedOrUpdated(endpoint)
}

func (h *controller) RemoteEndpointUpdated(endpoint *submarinerv1.Endpoint) error {
	if !h.config.HealthCheckerEnabled && h.State().IsOnGateway() {
		return nil
	}

	h.remoteEndpoint[endpoint.Name] = endpoint

	return h.processEndpointCreatedOrUpdated(endpoint)
}

func (h *controller) processEndpointCreatedOrUpdated(endpoint *submarinerv1.Endpoint) error {
	logger.Infof("Endpoint created: %#v", endpoint)

	if endpoint.Spec.HealthCheckIP == "" || endpoint.Spec.CableName == "" {
		logger.Infof("HealthCheckIP (%q) and/or CableName (%q) for Endpoint %q empty - will not monitor endpoint health",
			endpoint.Spec.HealthCheckIP, endpoint.Spec.CableName, endpoint.Name)
		return nil
	}

	h.Lock()
	defer h.Unlock()

	if pingerObject, found := h.pingers[endpoint.Spec.CableName]; found {
		if pingerObject.GetIP() == endpoint.Spec.HealthCheckIP {
			logger.Infof("HealthChecker did not change %q ", endpoint.Name)
			return nil
		}

		logger.Infof("HealthChecker is already running for %q - stopping", endpoint.Name)
		pingerObject.Stop()
		delete(h.pingers, endpoint.Spec.CableName)
	}

	pingerConfig := pinger.Config{
		IP:                 endpoint.Spec.HealthCheckIP,
		MaxPacketLossCount: h.config.MaxPacketLossCount,
	}

	if h.config.PingInterval != 0 {
		pingerConfig.Interval = time.Second * time.Duration(h.config.PingInterval)
	}

	if h.config.MaxPacketLossCount != 0 {
		pingerConfig.MaxPacketLossCount = h.config.MaxPacketLossCount
	}

	newPingerFunc := h.config.NewPinger
	if newPingerFunc == nil {
		newPingerFunc = pinger.NewPinger
	}

	pingerObject := newPingerFunc(pingerConfig)
	h.pingers[endpoint.Spec.CableName] = pingerObject
	pingerObject.Start()

	logger.Infof("CableEngine HealthChecker started pinger for CableName: %q with HealthCheckIP %q",
		endpoint.Spec.CableName, endpoint.Spec.HealthCheckIP)

	return nil
}

func (h *controller) RemoteEndpointDeleted(endpoint *submarinerv1.Endpoint) error {
	h.Lock()
	defer h.Unlock()

	if pingerObject, found := h.pingers[endpoint.Spec.CableName]; found {
		pingerObject.Stop()
		delete(h.pingers, endpoint.Spec.CableName)
	}

	delete(h.remoteEndpoint, endpoint.Name)

	return nil
}

func (h *controller) Init() error {
	go func() {
		wait.Until(h.syncRouteAgentStatus, RouteAgentUpdateInterval, h.stopCh)
	}()

	return nil
}

// TransitionToNonGateway is called once for each transition of the local node from Gateway to a non-Gateway.
func (h *controller) TransitionToNonGateway() error {
	if h.config.HealthCheckerEnabled {
		for i := range h.remoteEndpoint {
			err := h.processEndpointCreatedOrUpdated(h.remoteEndpoint[i])
			if err != nil {
				logger.Warningf("Error processing remote endpoint %s: %v", h.remoteEndpoint[i].Name, err)
			}
		}
	}

	return nil
}

// TransitionToGateway is called once for each transition of the local node from non-Gateway to a Gateway.
func (h *controller) TransitionToGateway() error {
	if h.config.HealthCheckerEnabled {
		for i := range h.pingers {
			h.pingers[i].Stop()
			delete(h.pingers, i)
		}
	}

	close(h.stopCh)

	err := h.client.Delete(context.TODO(), h.localNodeName, metav1.DeleteOptions{})
	if err != nil {
		logger.Warningf("Error deleting RouteAgent: %s: %v", h.localNodeName, err)
	}

	return nil
}

func (h *controller) GetNetworkPlugins() []string {
	return []string{event.AnyNetworkPlugin}
}

func (h *controller) GetName() string {
	return "routeAgent-health-checker"
}

func (h *controller) syncRouteAgentStatus() {
	routeAgent := h.generateRouteAgentObject()
	routeAgent.Status.RemoteEndpoints = []submarinerv1.RemoteEndpoint{}

	for _, endpoint := range h.remoteEndpoint {
		pingerObject, found := h.pingers[endpoint.Spec.CableName]
		if !found {
			logger.Warningf("Pinger not found for %q", endpoint.Spec.CableName)
			continue
		}

		latencyInfo := pingerObject.GetLatencyInfo()
		if latencyInfo != nil {
			connectionStatus := submarinerv1.ConnectionStatus(latencyInfo.ConnectionStatus)

			remoteEndpoint := submarinerv1.RemoteEndpoint{
				Status:        connectionStatus,
				StatusMessage: latencyInfo.ConnectionError,
				Spec: submarinerv1.EndpointSpec{
					ClusterID:     endpoint.Spec.ClusterID,
					CableName:     endpoint.Spec.CableName,
					HealthCheckIP: endpoint.Spec.HealthCheckIP,
					Hostname:      endpoint.Spec.Hostname,
					Subnets:       endpoint.Spec.Subnets,
					PrivateIP:     endpoint.Spec.PrivateIP,
					PublicIP:      endpoint.Spec.PublicIP,
					NATEnabled:    endpoint.Spec.NATEnabled,
					Backend:       endpoint.Spec.Backend,
					BackendConfig: endpoint.Spec.BackendConfig,
				},
				LatencyRTT: &submarinerv1.LatencyRTTSpec{
					Last:    latencyInfo.Spec.Last,
					Min:     latencyInfo.Spec.Min,
					Average: latencyInfo.Spec.Average,
					Max:     latencyInfo.Spec.Max,
					StdDev:  latencyInfo.Spec.StdDev,
				},
			}

			routeAgent.Status.RemoteEndpoints = append(routeAgent.Status.RemoteEndpoints, remoteEndpoint)
		}
	}

	// Use CreateOrUpdate to handle the RouteAgent resource
	result, err := util.CreateOrUpdate(context.TODO(), h.routeAgentResourceInterface(), routeAgent,
		func(existing *submarinerv1.RouteAgent) (*submarinerv1.RouteAgent, error) {
			existing.TypeMeta = routeAgent.TypeMeta
			existing.Status = routeAgent.Status

			if existing.Annotations == nil {
				existing.Annotations = map[string]string{}
			}

			existing.Annotations[UpdateTimestampAnnotation] = routeAgent.Annotations[UpdateTimestampAnnotation]

			return existing, nil
		})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error creating/updating RouteAgent: %w", err))
		return
	}

	if result == util.OperationResultCreated {
		logger.Infof("RouteAgent does not exist - created: %+v", routeAgent)
	} else if result == util.OperationResultUpdated {
		logger.Infof("RouteAgent already exists - updated: %+v", routeAgent)
	} else {
		logger.Info("RouteAgent already exists but doesn't need updating")
	}
}

func (h *controller) generateRouteAgentObject() *submarinerv1.RouteAgent {
	return &submarinerv1.RouteAgent{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "submariner.io/v1",
			Kind:       "RouteAgent",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        h.localNodeName,
			Annotations: map[string]string{UpdateTimestampAnnotation: strconv.FormatInt(time.Now().UTC().Unix(), 10)},
		},
		Status: submarinerv1.RouteAgentStatus{
			Version:         h.version,
			StatusFailure:   "",
			RemoteEndpoints: []submarinerv1.RemoteEndpoint{},
		},
	}
}

func (h *controller) routeAgentResourceInterface() resource.Interface[*submarinerv1.RouteAgent] {
	return &resource.InterfaceFuncs[*submarinerv1.RouteAgent]{
		GetFunc:    h.client.Get,
		CreateFunc: h.client.Create,
		UpdateFunc: h.client.Update,
		DeleteFunc: h.client.Delete,
	}
}
