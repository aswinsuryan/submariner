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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/listers"
	"k8s.io/client-go/tools/cache"
)

// RouteAgentLister helps list RouteAgents.
// All objects returned here must be treated as read-only.
type RouteAgentLister interface {
	// List lists all RouteAgents in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.RouteAgent, err error)
	// RouteAgents returns an object that can list and get RouteAgents.
	RouteAgents(namespace string) RouteAgentNamespaceLister
	RouteAgentListerExpansion
}

// routeAgentLister implements the RouteAgentLister interface.
type routeAgentLister struct {
	listers.ResourceIndexer[*v1.RouteAgent]
}

// NewRouteAgentLister returns a new RouteAgentLister.
func NewRouteAgentLister(indexer cache.Indexer) RouteAgentLister {
	return &routeAgentLister{listers.New[*v1.RouteAgent](indexer, v1.Resource("routeagent"))}
}

// RouteAgents returns an object that can list and get RouteAgents.
func (s *routeAgentLister) RouteAgents(namespace string) RouteAgentNamespaceLister {
	return routeAgentNamespaceLister{listers.NewNamespaced[*v1.RouteAgent](s.ResourceIndexer, namespace)}
}

// RouteAgentNamespaceLister helps list and get RouteAgents.
// All objects returned here must be treated as read-only.
type RouteAgentNamespaceLister interface {
	// List lists all RouteAgents in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.RouteAgent, err error)
	// Get retrieves the RouteAgent from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.RouteAgent, error)
	RouteAgentNamespaceListerExpansion
}

// routeAgentNamespaceLister implements the RouteAgentNamespaceLister
// interface.
type routeAgentNamespaceLister struct {
	listers.ResourceIndexer[*v1.RouteAgent]
}
