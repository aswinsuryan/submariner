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

package controller

import (
	smv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
)

func (c *handlerController) handleUpdatedEndpoint(endpoint *smv1.Endpoint, requeueCount int) bool {
	if requeueCount > maxRequeues {
		logger.Errorf(nil, "Handler %q: Ignoring update event for endpoint %q, as it's requeued for more than %d times",
			c.handler.GetName(), endpoint.Name, maxRequeues)
		return false
	}

	c.syncMutex.Lock()
	defer c.syncMutex.Unlock()

	var err error
	if endpoint.Spec.ClusterID != c.clusterID {
		err = c.handleUpdatedRemoteEndpoint(endpoint)
	} else {
		err = c.handleUpdatedLocalEndpoint(endpoint)
	}

	if err != nil {
		logger.Errorf(err, "Handler %q: Error handling updated endpoint %q", c.handler.GetName(), endpoint.Name)
	}

	return err != nil
}

func (c *handlerController) handleUpdatedLocalEndpoint(endpoint *smv1.Endpoint) error {
	return c.handler.LocalEndpointUpdated(endpoint) //nolint:wrapcheck  // Let the caller wrap it
}

func (c *handlerController) handleUpdatedRemoteEndpoint(endpoint *smv1.Endpoint) error {
	c.handlerState.remoteEndpoints.Store(endpoint.Name, endpoint)
	return c.handler.RemoteEndpointUpdated(endpoint) //nolint:wrapcheck  // Let the caller wrap it
}
