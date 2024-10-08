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

package controllers

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/federate"
	"github.com/submariner-io/admiral/pkg/ipam"
	"github.com/submariner-io/admiral/pkg/syncer"
	"github.com/submariner-io/admiral/pkg/util"
	"github.com/submariner-io/admiral/pkg/watcher"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/globalnet/controllers/packetfilter"
	"github.com/submariner-io/submariner/pkg/globalnet/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

func NewGlobalEgressIPController(config *syncer.ResourceSyncerConfig, pool *ipam.IPPool) (Interface, error) {
	// We'll panic if config is nil, this is intentional
	var err error

	logger.Info("Creating GlobalEgressIP controller")

	pfIface, err := packetfilter.New()
	if err != nil {
		return nil, errors.WithMessage(err, "error creating the packetfilter Interface handler")
	}

	controller := &globalEgressIPController{
		baseIPAllocationController: newBaseIPAllocationController(pool, pfIface),
		podWatchers:                map[string]*egressPodWatcher{},
		watcherConfig: watcher.Config{
			RestMapper: config.RestMapper,
			Client:     config.SourceClient,
			Scheme:     config.Scheme,
		},
	}

	_, gvr, err := util.ToUnstructuredResource(&submarinerv1.GlobalEgressIP{}, config.RestMapper)
	if err != nil {
		return nil, errors.Wrap(err, "error converting resource")
	}

	client := config.SourceClient.Resource(*gvr).Namespace(corev1.NamespaceAll)

	list, err := client.List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error listing the resources")
	}

	federator := federate.NewUpdateStatusFederator(config.SourceClient, config.RestMapper, corev1.NamespaceAll)

	for i := range list.Items {
		err = controller.reserveAllocatedIPs(federator, &list.Items[i], func(reservedIPs []string) error {
			metrics.RecordAllocateGlobalEgressIPs(pool.GetCIDR(), len(reservedIPs))

			specObj := util.GetSpec(&list.Items[i])
			spec := &submarinerv1.GlobalEgressIPSpec{}
			_ = runtime.DefaultUnstructuredConverter.FromUnstructured(specObj.(map[string]interface{}), spec)
			key, _ := cache.MetaNamespaceKeyFunc(&list.Items[i])

			return controller.programGlobalEgressRules(key, reservedIPs, spec.PodSelector, controller.newNamedSet(key))
		})
		if err != nil {
			return nil, err
		}
	}

	controller.resourceSyncer, err = syncer.NewResourceSyncer(&syncer.ResourceSyncerConfig{
		Name:                "GlobalEgressIP syncer",
		ResourceType:        &submarinerv1.GlobalEgressIP{},
		SourceClient:        config.SourceClient,
		SourceNamespace:     corev1.NamespaceAll,
		RestMapper:          config.RestMapper,
		Federator:           federator,
		Scheme:              config.Scheme,
		Transform:           controller.process,
		ResourcesEquivalent: syncer.AreSpecsEquivalent,
	})
	if err != nil {
		return nil, errors.Wrap(err, "error creating the syncer")
	}

	return controller, nil
}

func (c *globalEgressIPController) Stop() {
	c.baseController.Stop()

	c.Lock()
	defer c.Unlock()

	for _, podWatcher := range c.podWatchers {
		close(podWatcher.stopCh)
	}
}

func (c *globalEgressIPController) process(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
	globalEgressIP := from.(*submarinerv1.GlobalEgressIP)

	numberOfIPs := 1
	if globalEgressIP.Spec.NumberOfIPs != nil {
		numberOfIPs = *globalEgressIP.Spec.NumberOfIPs
	}

	key, _ := cache.MetaNamespaceKeyFunc(globalEgressIP)

	logger.Infof("Processing %sd GlobalEgressIP %q, NumberOfIPs: %d, PodSelector: %#v, Status: %#v", op, key,
		numberOfIPs, globalEgressIP.Spec.PodSelector, globalEgressIP.Status)

	switch op {
	case syncer.Create, syncer.Update:
		prevStatus := globalEgressIP.Status

		trimAllocatedStatusCondition(&globalEgressIP.Status.Conditions)

		requeue := false
		if c.validate(numberOfIPs, globalEgressIP) {
			requeue = c.onCreateOrUpdate(key, numberOfIPs, globalEgressIP, numRequeues)
		}

		return checkStatusChanged(&prevStatus, &globalEgressIP.Status, globalEgressIP), requeue
	case syncer.Delete:
		return nil, c.onDelete(numRequeues, globalEgressIP)
	}

	return nil, false
}

func (c *globalEgressIPController) onCreateOrUpdate(key string, numberOfIPs int, globalEgressIP *submarinerv1.GlobalEgressIP,
	numRequeues int,
) bool {
	namedSet := c.newNamedSet(key)

	requeue := false
	if numberOfIPs != len(globalEgressIP.Status.AllocatedIPs) {
		requeue = c.flushGlobalEgressRulesAndReleaseIPs(key, namedSet.Name(), numRequeues, globalEgressIP)
	}

	return requeue || c.allocateGlobalIPs(key, numberOfIPs, globalEgressIP, namedSet) ||
		!c.createPodWatcher(key, namedSet, numberOfIPs, globalEgressIP)
}

//nolint:wrapcheck  // No need to wrap these errors.
func (c *globalEgressIPController) programGlobalEgressRules(key string, allocatedIPs []string, podSelector *metav1.LabelSelector,
	namedSet packetfilter.NamedSet,
) error {
	err := namedSet.Create(true)
	if err != nil {
		return errors.Wrapf(err, "error creating the IP set chain %q", namedSet.Name())
	}

	snatIP := getTargetSNATIPaddress(allocatedIPs)
	if podSelector != nil {
		if err := c.pfIface.AddEgressRulesForPods(key, namedSet.Name(), snatIP, globalNetIPTableMark); err != nil {
			_ = c.pfIface.RemoveEgressRulesForPods(key, namedSet.Name(), snatIP, globalNetIPTableMark)
			return err
		}
	} else {
		if err := c.pfIface.AddEgressRulesForNamespace(key, namedSet.Name(), snatIP, globalNetIPTableMark); err != nil {
			_ = c.pfIface.RemoveEgressRulesForNamespace(key, namedSet.Name(), snatIP, globalNetIPTableMark)
			return err
		}
	}

	return nil
}

func (c *globalEgressIPController) allocateGlobalIPs(key string, numberOfIPs int,
	globalEgressIP *submarinerv1.GlobalEgressIP, namedSet packetfilter.NamedSet,
) bool {
	logger.Infof("Allocating %d global IP(s) for %q", numberOfIPs, key)

	if numberOfIPs == 0 {
		globalEgressIP.Status.AllocatedIPs = nil

		meta.SetStatusCondition(&globalEgressIP.Status.Conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "ZeroInput",
			Message: "The specified NumberOfIPs is 0",
		})

		return false
	}

	if numberOfIPs == len(globalEgressIP.Status.AllocatedIPs) {
		return false
	}

	globalEgressIP.Status.AllocatedIPs = nil

	allocatedIPs, err := c.pool.Allocate(numberOfIPs)
	if err != nil {
		logger.Errorf(err, "Error allocating IPs for %q", key)

		meta.SetStatusCondition(&globalEgressIP.Status.Conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "IPPoolAllocationFailed",
			Message: fmt.Sprintf("Error allocating %d global IP(s) from the pool: %v", numberOfIPs, err),
		})

		return true
	}

	err = c.programGlobalEgressRules(key, allocatedIPs, globalEgressIP.Spec.PodSelector, namedSet)
	if err != nil {
		logger.Errorf(err, "Error programming egress IP table rules for %q", key)

		meta.SetStatusCondition(&globalEgressIP.Status.Conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "ProgramIPTableRulesFailed",
			Message: fmt.Sprintf("Error programming egress rules: %v", err),
		})

		_ = c.pool.Release(allocatedIPs...)

		return true
	}

	metrics.RecordAllocateGlobalEgressIPs(c.pool.GetCIDR(), numberOfIPs)

	meta.SetStatusCondition(&globalEgressIP.Status.Conditions, metav1.Condition{
		Type:    string(submarinerv1.GlobalEgressIPAllocated),
		Status:  metav1.ConditionTrue,
		Reason:  "Success",
		Message: fmt.Sprintf("Allocated %d global IP(s)", numberOfIPs),
	})

	globalEgressIP.Status.AllocatedIPs = allocatedIPs

	logger.Infof("Allocated %v global IP(s) for %q", globalEgressIP.Status.AllocatedIPs, key)

	return false
}

func (c *globalEgressIPController) validate(numberOfIPs int, egressIP *submarinerv1.GlobalEgressIP) bool {
	if numberOfIPs < 0 {
		meta.SetStatusCondition(&egressIP.Status.Conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "InvalidInput",
			Message: "The NumberOfIPs cannot be negative",
		})

		return false
	}

	return true
}

func (c *globalEgressIPController) onDelete(numRequeues int, globalEgressIP *submarinerv1.GlobalEgressIP) bool {
	key, _ := cache.MetaNamespaceKeyFunc(globalEgressIP)

	c.Lock()
	defer c.Unlock()

	podWatcher, found := c.podWatchers[key]
	if found {
		close(podWatcher.stopCh)
		delete(c.podWatchers, key)
	}

	namedSet := c.newNamedSet(key)

	if len(globalEgressIP.Status.AllocatedIPs) == 0 && len(podWatcher.allocatedIPs) > 0 {
		// Refer to issue for more details: https://github.com/submariner-io/submariner/issues/2388
		logger.Warningf("Using the cached allocatedIPs %q to delete the iptables rules for key %q", podWatcher.allocatedIPs, key)
		globalEgressIP.Status.AllocatedIPs = podWatcher.allocatedIPs
	}

	requeue := c.flushGlobalEgressRulesAndReleaseIPs(key, namedSet.Name(), numRequeues, globalEgressIP)
	if requeue {
		return requeue
	}

	if err := namedSet.Destroy(); err != nil {
		logger.Errorf(err, "Error destroying the ipSet %q for %q", namedSet.Name(), key)

		if shouldRequeue(numRequeues) {
			return true
		}
	}

	if numRequeues >= maxRequeues {
		logger.Infof("Failed to delete all the packetfilter/namedset rules for %q even after %d retries", key, numRequeues)
	} else {
		logger.Infof("Successfully deleted all the packetfilter/namedset rules for %q ", key)
	}

	return false
}

func (c *globalEgressIPController) getIPSetName(key string) string {
	hash := sha256.Sum256([]byte(key))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	// Max length of IPSet name can be 31
	return IPSetPrefix + encoded[:25]
}

func (c *globalEgressIPController) createPodWatcher(key string, namedSet packetfilter.NamedSet, numberOfIPs int,
	globalEgressIP *submarinerv1.GlobalEgressIP,
) bool {
	c.Lock()
	defer c.Unlock()

	prevPodWatcher, found := c.podWatchers[key]
	if found {
		if !equality.Semantic.DeepEqual(prevPodWatcher.podSelector, globalEgressIP.Spec.PodSelector) {
			logger.Errorf(nil, "PodSelector for %q cannot be updated after creation", key)

			meta.SetStatusCondition(&globalEgressIP.Status.Conditions, metav1.Condition{
				Type:    string(submarinerv1.GlobalEgressIPUpdated),
				Status:  metav1.ConditionFalse,
				Reason:  "PodSelectorUpdateNotSupported",
				Message: "The PodSelector cannot be updated after creation",
			})
		}

		return true
	}

	if numberOfIPs == 0 {
		return true
	}

	podWatcher, err := startEgressPodWatcher(key, globalEgressIP.Namespace, namedSet, &c.watcherConfig, globalEgressIP.Spec.PodSelector)
	if err != nil {
		logger.Errorf(err, "Error starting pod watcher for %q", key)
		return false
	}

	c.podWatchers[key] = podWatcher
	podWatcher.podSelector = globalEgressIP.Spec.PodSelector
	podWatcher.allocatedIPs = globalEgressIP.Status.AllocatedIPs

	logger.Infof("Started pod watcher for %q", key)

	return true
}

func (c *globalEgressIPController) flushGlobalEgressRulesAndReleaseIPs(key, namedSetName string, numRequeues int,
	globalEgressIP *submarinerv1.GlobalEgressIP,
) bool {
	return c.flushRulesAndReleaseIPs(key, numRequeues, func(allocatedIPs []string) error {
		metrics.RecordDeallocateGlobalEgressIPs(c.pool.GetCIDR(), len(allocatedIPs))

		if globalEgressIP.Spec.PodSelector != nil {
			return c.pfIface.RemoveEgressRulesForPods(key, namedSetName,
				getTargetSNATIPaddress(allocatedIPs), globalNetIPTableMark)
		}

		return c.pfIface.RemoveEgressRulesForNamespace(key, namedSetName, getTargetSNATIPaddress(allocatedIPs), globalNetIPTableMark)
	}, globalEgressIP.Status.AllocatedIPs...)
}

func (c *globalEgressIPController) newNamedSet(key string) packetfilter.NamedSet {
	return c.pfIface.NewNamedSet(c.getIPSetName(key))
}
