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

package syncer

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/util"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable"
	"github.com/submariner-io/submariner/pkg/cableengine"
	"github.com/submariner-io/submariner/pkg/cableengine/healthchecker"
	v1typed "github.com/submariner-io/submariner/pkg/client/clientset/versioned/typed/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/pinger"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

type GatewaySyncer struct {
	mutex       sync.Mutex
	client      v1typed.GatewayInterface
	engine      cableengine.Engine
	version     string
	statusError error
	healthCheck healthchecker.Interface
}

var (
	GatewayUpdateInterval = 5 * time.Second
	GatewayStaleTimeout   = GatewayUpdateInterval * 3
)

//nolint:promlinter // Existing public API, we can't change it to include "_total"
var gatewaySyncIterations = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "submariner_gateway_sync_iterations",
	Help: "Gateway synchronization iterations",
})

var logger = log.Logger{Logger: logf.Log.WithName("GWSyncer")}

const UpdateTimestampAnnotation = "update-timestamp"

func init() {
	prometheus.MustRegister(gatewaySyncIterations)
}

// NewEngine creates a new Engine for the local cluster.
func NewGatewaySyncer(engine cableengine.Engine, client v1typed.GatewayInterface,
	version string, healthCheck healthchecker.Interface,
) *GatewaySyncer {
	return &GatewaySyncer{
		client:      client,
		engine:      engine,
		version:     version,
		healthCheck: healthCheck,
	}
}

func (gs *GatewaySyncer) Run(stopCh <-chan struct{}) {
	wait.Until(gs.syncGatewayStatus, GatewayUpdateInterval, stopCh)
	gs.CleanupGatewayEntry(context.Background())

	logger.Info("CableEngine syncer stopped")
}

func (gs *GatewaySyncer) syncGatewayStatus() {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	gs.syncGatewayStatusSafe(context.Background())
}

func (gs *GatewaySyncer) SetGatewayStatusError(ctx context.Context, err error) {
	gs.mutex.Lock()
	defer gs.mutex.Unlock()

	gs.statusError = err
	gs.syncGatewayStatusSafe(ctx)
}

func (gs *GatewaySyncer) gatewayResourceInterface() resource.Interface[*v1.Gateway] {
	return &resource.InterfaceFuncs[*v1.Gateway]{
		GetFunc:    gs.client.Get,
		CreateFunc: gs.client.Create,
		UpdateFunc: gs.client.Update,
		DeleteFunc: gs.client.Delete,
	}
}

func (gs *GatewaySyncer) syncGatewayStatusSafe(ctx context.Context) {
	logger.V(log.TRACE).Info("Running Gateway status sync")
	gatewaySyncIterations.Inc()

	gatewayObj := gs.generateGatewayObject()

	result, err := util.CreateOrUpdate(ctx, gs.gatewayResourceInterface(), gatewayObj,
		func(existing *v1.Gateway) (*v1.Gateway, error) {
			existing.Status = gatewayObj.Status

			if existing.Annotations == nil {
				existing.Annotations = map[string]string{}
			}

			existing.Annotations[UpdateTimestampAnnotation] = gatewayObj.Annotations[UpdateTimestampAnnotation]

			return existing, nil
		})
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("error creating/updating Gateway: %w", err))
		return
	}

	if result == util.OperationResultCreated {
		logger.V(log.TRACE).Infof("Gateway does not exist - created: %+v", gatewayObj)
	} else if result == util.OperationResultUpdated {
		logger.V(log.TRACE).Infof("Gateway already exists - updated %+v", gatewayObj)
	} else {
		logger.V(log.TRACE).Info("Gateway already exists but doesn't need updating")
	}

	if gatewayObj.Status.HAStatus == v1.HAStatusActive {
		err := gs.cleanupStaleGatewayEntries(ctx, gatewayObj.Name)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("error cleaning up stale gateway entries: %w", err))
		}
	}
}

func (gs *GatewaySyncer) cleanupStaleGatewayEntries(ctx context.Context, localGatewayName string) error {
	gateways, err := gs.client.List(ctx, metav1.ListOptions{})
	if err != nil {
		return errors.Wrap(err, "error listing Gateways")
	}

	for i := range gateways.Items {
		gw := &gateways.Items[i]
		if gw.Name == localGatewayName {
			continue
		}

		stale, err := isGatewayStale(gw)
		if err != nil {
			// In this case we don't want to stop the cleanup loop and just log it
			utilruntime.HandleError(fmt.Errorf("error processing stale Gateway %+v: %w", gw, err))
		}

		if stale {
			err := gs.client.Delete(ctx, gw.Name, metav1.DeleteOptions{})
			if err != nil {
				// In this case we don't want to stop the cleanup loop and just log it.
				utilruntime.HandleError(fmt.Errorf("error deleting stale Gateway %+v: %w", gw, err))
			} else {
				logger.Warningf("Deleted stale gateway: %s, didn't report for %s",
					gw.Name, GatewayStaleTimeout)
			}
		}
	}

	return nil
}

func isGatewayStale(gateway *v1.Gateway) (bool, error) {
	timestamp, ok := gateway.ObjectMeta.Annotations[UpdateTimestampAnnotation]
	if !ok {
		return true, fmt.Errorf("%q annotation not found", UpdateTimestampAnnotation)
	}

	timestampInt, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return true, fmt.Errorf("error parsing update-timestamp: %w", err)
	}

	now := time.Now().UTC().Unix()

	return now >= timestampInt+int64(GatewayStaleTimeout.Seconds()), nil
}

func (gs *GatewaySyncer) generateGatewayObject() *v1.Gateway {
	localEndpoint := gs.engine.GetLocalEndpoint()

	gateway := v1.Gateway{
		Status: v1.GatewayStatus{
			Version:       gs.version,
			LocalEndpoint: localEndpoint.Spec,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        resource.EnsureValidName(localEndpoint.Spec.Hostname),
			Annotations: map[string]string{UpdateTimestampAnnotation: strconv.FormatInt(time.Now().UTC().Unix(), 10)},
		},
	}

	gateway.Status.HAStatus = gs.engine.GetHAStatus()

	var connections []v1.Connection

	if gs.statusError != nil {
		gateway.Status.StatusFailure = gs.statusError.Error()
	} else {
		var err error

		connections, err = gs.engine.ListCableConnections()
		if err != nil {
			msg := fmt.Sprintf("Error retrieving driver connections: %s", err)
			logger.Error(nil, msg)
			gateway.Status.StatusFailure = msg
		}
	}

	if connections == nil {
		connections = []v1.Connection{}
	}

	if gs.healthCheck != nil {
		for index := range connections {
			connection := &connections[index]

			latencyInfo := gs.healthCheck.GetLatencyInfo(&connection.Endpoint, connection.GetFamily())
			if latencyInfo != nil {
				connection.LatencyRTT = latencyInfo.Spec
				connection.Endpoint.SetHealthCheckIP(latencyInfo.IP)

				if connection.Status == v1.Connected {
					lastRTT, _ := time.ParseDuration(latencyInfo.Spec.Last)
					cable.RecordConnectionLatency(localEndpoint.Spec.Backend, &localEndpoint.Spec, &connection.Endpoint, lastRTT.Seconds(),
						connection.GetFamily())

					if connection.StatusMessage != "" {
						connection.StatusMessage = ""
					}

					if latencyInfo.ConnectionStatus == pinger.ConnectionError {
						connection.Status = v1.ConnectionError
						connection.StatusMessage = latencyInfo.ConnectionError
					} else if latencyInfo.ConnectionStatus == pinger.ConnectionUnknown {
						connection.StatusMessage = latencyInfo.ConnectionError
					}
				} else if connection.Status == v1.ConnectionError && latencyInfo.ConnectionStatus == pinger.Connected {
					connection.Status = v1.Connected
					connection.StatusMessage = ""
				}
			}
		}
	}

	gateway.Status.Connections = connections

	logger.V(log.TRACE).Infof("Generated Gateway object: %+v", gateway)

	return &gateway
}

// CleanupGatewayEntry removes this Gateway entry from the k8s API, it does not
// propagate error up because it's a termination function that we also provide externally.
func (gs *GatewaySyncer) CleanupGatewayEntry(ctx context.Context) {
	hostName := gs.engine.GetLocalEndpoint().Spec.Hostname

	err := gs.client.Delete(ctx, hostName, metav1.DeleteOptions{})
	if err != nil {
		logger.Errorf(err, "Error while trying to delete own Gateway %q", hostName)
		return
	}

	logger.Infof("The Gateway entry for %q has been deleted", hostName)
}
