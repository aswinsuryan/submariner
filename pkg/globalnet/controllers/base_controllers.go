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
	"slices"
	"strings"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/federate"
	"github.com/submariner-io/admiral/pkg/ipam"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	pfiface "github.com/submariner-io/submariner/pkg/globalnet/controllers/packetfilter"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
)

const maxRequeues = 20

func newBaseController() *baseController {
	return &baseController{
		stopCh: make(chan struct{}),
	}
}

func (c *baseController) Stop() {
	close(c.stopCh)
}

func newBaseSyncerController() *baseSyncerController {
	return &baseSyncerController{
		baseController: newBaseController(),
	}
}

func newBaseIPAllocationController(pool *ipam.IPPool, pfIface pfiface.Interface) *baseIPAllocationController {
	return &baseIPAllocationController{
		baseSyncerController: newBaseSyncerController(),
		pool:                 pool,
		pfIface:              pfIface,
	}
}

func (c *baseSyncerController) Start() error {
	return c.resourceSyncer.Start(c.stopCh) //nolint:wrapcheck  // Let the caller wrap it
}

func (c *baseSyncerController) Stop() {
	c.baseController.Stop()

	err := c.resourceSyncer.AwaitStopped(context.TODO())
	if err != nil {
		logger.Warning(err.Error())
	}
}

func (c *baseSyncerController) reconcile(client dynamic.ResourceInterface, labelSelector, fieldSelector string,
	transform func(obj *unstructured.Unstructured) runtime.Object,
) {
	c.resourceSyncer.Reconcile(func() []runtime.Object {
		objList, err := client.List(context.TODO(), metav1.ListOptions{
			LabelSelector: labelSelector,
			FieldSelector: fieldSelector,
		})
		if err != nil {
			logger.Errorf(err, "Error listing resources for reconciliation")
			return nil
		}

		retList := make([]runtime.Object, 0, len(objList.Items))

		for i := range objList.Items {
			obj := transform(&objList.Items[i])
			if obj != nil {
				retList = append(retList, obj)
			}
		}

		return retList
	})
}

func (c *baseIPAllocationController) reserveAllocatedIPs(federator federate.Federator, obj *unstructured.Unstructured,
	postReserve func(allocatedIPs []string) error,
) error {
	var reservedIPs []string

	clearAllocatedIPs := func() {}

	ips, ok, _ := unstructured.NestedStringSlice(obj.Object, "status", "allocatedIPs")
	if ok {
		reservedIPs = ips
		clearAllocatedIPs = func() {
			_ = unstructured.SetNestedStringSlice(obj.Object, []string{}, "status", "allocatedIPs")
		}
	} else {
		ip, ok, _ := unstructured.NestedString(obj.Object, "status", "allocatedIP")
		if ok && ip != "" {
			reservedIPs = []string{ip}
			clearAllocatedIPs = func() {
				_ = unstructured.SetNestedField(obj.Object, "", "status", "allocatedIP")
			}
		}
	}

	err := c.pool.Reserve(reservedIPs...)
	if err != nil {
		key, _ := cache.MetaNamespaceKeyFunc(obj)

		logger.Warningf("Could not reserve allocated GlobalIPs for %q: %v", key, err)

		clearAllocatedIPs()

		conditions := util.ConditionsFromUnstructured(obj, "status", "conditions")

		meta.SetStatusCondition(&conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "ReserveAllocatedIPsFailed",
			Message: fmt.Sprintf("Error reserving the allocated global IP(s) from the pool: %v", err),
		})

		util.ConditionsToUnstructured(conditions, obj, "status", "conditions")

		logger.Infof("Updating %q: %#v", key, obj)

		return federator.Distribute(context.TODO(), obj) //nolint:wrapcheck  // Let the caller wrap it
	}

	if len(reservedIPs) == 0 {
		return nil
	}

	err = postReserve(reservedIPs)
	if err != nil {
		return err
	}

	logger.Infof("Successfully reserved GlobalIPs %q for %s \"%s/%s\"", reservedIPs, obj.GetKind(),
		obj.GetNamespace(), obj.GetName())

	return nil
}

func (c *baseIPAllocationController) flushRulesAndReleaseIPs(key string, numRequeues int, flushRules func(allocatedIPs []string) error,
	allocatedIPs ...string,
) bool {
	if len(allocatedIPs) == 0 {
		return false
	}

	logger.Infof("Releasing previously allocated IPs %v for %q", allocatedIPs, key)

	err := flushRules(allocatedIPs)
	if err != nil {
		logger.Errorf(err, "Error flushing the IP table rules for %q", key)

		if shouldRequeue(numRequeues) {
			return true
		}
	}

	if err := c.pool.Release(allocatedIPs...); err != nil {
		logger.Errorf(err, "Error while releasing the global IPs for %q", key)
	}

	return false
}

func shouldRequeue(numRequeues int) bool {
	return numRequeues < maxRequeues
}

func getTargetSNATIPaddress(allocIPs []string) string {
	var snatIP string

	allocatedIPs := len(allocIPs)

	if allocatedIPs == 1 {
		snatIP = allocIPs[0]
	} else {
		snatIP = fmt.Sprintf("%s-%s", allocIPs[0], allocIPs[len(allocIPs)-1])
	}

	return snatIP
}

func checkStatusChanged(oldStatus, newStatus interface{}, retObj runtime.Object) runtime.Object {
	if equality.Semantic.DeepEqual(oldStatus, newStatus) {
		return nil
	}

	logger.Infof("Updated: %#v", newStatus)

	return retObj
}

func getService(name, namespace string,
	client dynamic.NamespaceableResourceInterface, scheme *runtime.Scheme,
) (*corev1.Service, bool, error) {
	obj, err := client.Namespace(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, errors.Wrapf(err, "error retrieving Service %s/%s", namespace, name)
	}

	service := &corev1.Service{}

	err = scheme.Convert(obj, service, nil)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error converting %#v to Service", obj)
	}

	return service, true, nil
}

func deleteService(namespace, name string,
	client dynamic.NamespaceableResourceInterface,
) error {
	err := client.Namespace(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		logger.Warningf("Could not find Service %s/%s to delete", namespace, name)
		return nil
	}

	return errors.Wrapf(err, "error deleting Service %s/%s", namespace, name)
}

func GetInternalSvcName(name string) string {
	hash := sha256.Sum256([]byte(name))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	svcName := InternalServicePrefix + encoded[:32]

	return strings.ToLower(svcName)
}

func deleteEndpoints(namespace, name string,
	client dynamic.NamespaceableResourceInterface,
) error {
	err := client.Namespace(namespace).Delete(context.TODO(), name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		logger.Warningf("Could not find Endpoints %s/%s to delete", namespace, name)
		return nil
	}

	return errors.Wrapf(err, "error deleting Endpoints %s/%s", namespace, name)
}

func trimAllocatedStatusCondition(conditions *[]metav1.Condition) {
	last := -1

	for i := len(*conditions) - 1; i > 0; i-- {
		if (*conditions)[i].Type == string(submarinerv1.GlobalEgressIPAllocated) {
			last = i
			break
		}
	}

	for i := 0; i < last; i++ {
		if (*conditions)[i].Type == string(submarinerv1.GlobalEgressIPAllocated) {
			*conditions = slices.Delete(*conditions, i, i+1)
			i--
			last--
		}
	}
}
