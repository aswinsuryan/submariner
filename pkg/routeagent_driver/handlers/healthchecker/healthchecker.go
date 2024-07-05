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
	"sync"
	"time"

	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/watcher"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/pinger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	GatewayUpdateInterval = 5 * time.Second
	GatewayStaleTimeout   = GatewayUpdateInterval * 3
)

type Config struct {
	event.HandlerBase
	WatcherConfig      *watcher.Config
	EndpointNamespace  string
	ClusterID          string
	PingInterval       uint
	MaxPacketLossCount uint
	NewPinger          func(pinger.PingerConfig) pinger.PingerInterface
}

type controller struct {
	event.HandlerBase
	sync.RWMutex
	pingers  map[string]pinger.PingerInterface
	gateways dynamic.DynamicClient
	config   *Config
	stopCh   <-chan struct{}
}

var logger = log.Logger{Logger: logf.Log.WithName("HealthChecker")}

func NewHealthCheckerHandler(config *Config) event.Handler {
	controller := &controller{
		config:  config,
		pingers: map[string]pinger.PingerInterface{},
	}

	return controller
}

func (h *controller) Start(stopCh <-chan struct{}) error {

	return nil
}

func (h *controller) Stop() error {
	h.Lock()
	defer h.Unlock()

	for _, p := range h.pingers {
		p.Stop()
	}

	h.pingers = map[string]pinger.PingerInterface{}

	return nil
}

func (h *controller) RemoteEndpointCreated(endpoint *submarinerv1.Endpoint) error {
	return h.processEndpointCreatedOrUpdated(endpoint)
}

func (h *controller) RemoteEndpointUpdated(endpoint *submarinerv1.Endpoint) error {
	return h.processEndpointCreatedOrUpdated(endpoint)
}

func (h *controller) processEndpointCreatedOrUpdated(endpoint *submarinerv1.Endpoint) error {
	logger.V(log.TRACE).Infof("Endpoint created: %#v", endpoint)

	if endpoint.Spec.HealthCheckIP == "" || endpoint.Spec.CableName == "" {
		logger.Infof("HealthCheckIP (%q) and/or CableName (%q) for Endpoint %q empty - will not monitor endpoint health",
			endpoint.Spec.HealthCheckIP, endpoint.Spec.CableName, endpoint.Name)
		return nil
	}

	h.Lock()
	defer h.Unlock()

	if pinger, found := h.pingers[endpoint.Spec.CableName]; found {
		if pinger.GetIP() == endpoint.Spec.HealthCheckIP {
			return nil
		}

		logger.V(log.DEBUG).Infof("HealthChecker is already running for %q - stopping", endpoint.Name)
		pinger.Stop()
		delete(h.pingers, endpoint.Spec.CableName)
	}

	pingerConfig := pinger.PingerConfig{
		IP:                 endpoint.Spec.HealthCheckIP,
		MaxPacketLossCount: h.config.MaxPacketLossCount,
	}

	if h.config.PingInterval != 0 {
		pingerConfig.Interval = time.Second * time.Duration(h.config.PingInterval)
	}

	newPingerFunc := h.config.NewPinger
	if newPingerFunc == nil {
		newPingerFunc = pinger.NewPinger
	}

	pinger := newPingerFunc(pingerConfig)
	h.pingers[endpoint.Spec.CableName] = pinger
	pinger.Start()

	logger.Infof("CableEngine HealthChecker started pinger for CableName: %q with HealthCheckIP %q",
		endpoint.Spec.CableName, endpoint.Spec.HealthCheckIP)

	return nil
}

func (h *controller) RemoteEndpointDeleted(endpoint *submarinerv1.Endpoint) error {
	h.Lock()
	defer h.Unlock()

	if pinger, found := h.pingers[endpoint.Spec.CableName]; found {
		pinger.Stop()
		delete(h.pingers, endpoint.Spec.CableName)
	}

	return nil
}

// TransitionToNonGateway is called once for each transition of the local node from Gateway to a non-Gateway.
func (h *controller) TransitionToNonGateway() error {
	pingers := h.pingers
	for i := range pingers {
		pingers[i].Start()
	}

	return nil
}

// TransitionToGateway is called once for each transition of the local node from non-Gateway to a Gateway.
func (h *controller) TransitionToGateway() error {
	pingers := h.pingers
	for i := range pingers {
		pingers[i].Stop()
	}

	return nil
}

func (h *controller) GetNetworkPlugins() []string {
	return []string{event.AnyNetworkPlugin}
}

func (h *controller) GetName() string {
	return "RouteAgent Health Checker"
}

func (h *controller) Init() error {

	wait.Until(h.syncGatewayStatus, GatewayUpdateInterval, h.stopCh)
	return nil
}

func (h *controller) syncGatewayStatus() {

	// Define the GVR for Gateway
	gatewayGVR := schema.GroupVersionResource{
		Group:    "submariner.io",
		Version:  "v1",
		Resource: "gateways",
	}

	// List Gateways in the specified namespace
	gateways, err := h.gateways.Resource(gatewayGVR).Namespace("submariner-operator").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		logger.Fatalf("Error listing gateways: %s", err.Error())
	}

	for _, gateway := range gateways.Items {
		fmt.Printf("Name: %s, Namespace: %s\n", gateway.GetName(), gateway.GetNamespace())

		// Retrieve the status
		status, found, err := unstructured.NestedMap(gateway.Object, "status")
		if err != nil || !found {
			fmt.Println("Status: Not found")
			continue
		}

		// Check if gateway is active
		haStatus, found, err := unstructured.NestedString(status, "haStatus")
		if err != nil || !found || haStatus != "active" {
			fmt.Println("Gateway is not active, skipping...")
			continue
		}

		// Check the connections in the status
		connections, found, err := unstructured.NestedSlice(status, "connections")
		if err != nil || !found {
			fmt.Println("Connections: Not found")
			continue
		}

		updated := false
		for i, conn := range connections {
			if connMap, ok := conn.(map[string]interface{}); ok {
				connectionStatus, found := connMap["status"].(string)
				if !found {
					continue
				}

				// Extract the cable name
				cableName, found := connMap["cableName"].(string)
				if !found {
					logger.Warningf("CableName not found in gateway status")
					continue
				}

				// Simulate getting latency info (replace with actual logic)
				latencyInfo := h.pingers[cableName].GetLatencyInfo()
				localStatus := latencyInfo.ConnectionStatus

				if localStatus == "error" && connectionStatus == "connected" {
					logger.Infof("Updating connection status to 'error'")
					connMap["status"] = submarinerv1.ConnectionRouteAgentError
					updated = true

					// Update the connections slice with the modified connection
					connections[i] = connMap
				} else if localStatus == "connected" && connectionStatus == string(submarinerv1.ConnectionRouteAgentError) {
					logger.Infof("Updating connection status to 'connected'")
					connMap["status"] = submarinerv1.Connected
				}
			}
		}

		if updated {
			// Set the updated connections back to the status
			err = unstructured.SetNestedField(status, connections, "connections")
			if err != nil {
				logger.Warningf("Error setting connections: %s", err.Error())
			}

			// Set the updated status back to the gateway object
			err = unstructured.SetNestedField(gateway.Object, status, "status")
			if err != nil {
				logger.Warningf("Error setting status: %s", err.Error())
			}

			// Update the Gateway object
			_, err = h.gateways.Resource(gatewayGVR).Namespace("submariner-operator").Update(context.TODO(), &gateway, metav1.UpdateOptions{})
			if err != nil {
				logger.Warningf("Error updating Gateway: %s", err.Error())
			}
		}
	}
}
