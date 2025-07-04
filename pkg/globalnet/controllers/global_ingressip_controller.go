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
	"fmt"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/federate"
	"github.com/submariner-io/admiral/pkg/finalizer"
	"github.com/submariner-io/admiral/pkg/ipam"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/syncer"
	"github.com/submariner-io/admiral/pkg/util"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	pfiface "github.com/submariner-io/submariner/pkg/globalnet/controllers/packetfilter"
	"github.com/submariner-io/submariner/pkg/globalnet/metrics"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"
)

func NewGlobalIngressIPController(config *syncer.ResourceSyncerConfig, pool *ipam.IPPool) (*globalIngressIPController, error) {
	// We'll panic if config is nil, this is intentional
	var err error

	logger.Info("Creating GlobalIngressIP controller")

	pfIface, err := pfiface.New()
	if err != nil {
		return nil, errors.Wrap(err, "error creating the PacketFilter Interface handler")
	}

	_, gvr, err := util.ToUnstructuredResource(&corev1.Service{}, config.RestMapper)
	if err != nil {
		return nil, errors.Wrap(err, "error converting resource")
	}

	controller := &globalIngressIPController{
		baseIPAllocationController: newBaseIPAllocationController(pool, pfIface),
		services:                   config.SourceClient.Resource(*gvr),
		scheme:                     config.Scheme,
	}

	_, gvr, err = util.ToUnstructuredResource(&submarinerv1.GlobalIngressIP{}, config.RestMapper)
	if err != nil {
		return nil, errors.Wrap(err, "error converting resource")
	}

	federator := federate.NewUpdateStatusFederator(config.SourceClient, config.RestMapper, corev1.NamespaceAll)

	client := config.SourceClient.Resource(*gvr)

	list, err := client.Namespace(corev1.NamespaceAll).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "error listing the resources")
	}

	for i := range list.Items {
		obj := &list.Items[i]
		gip := &submarinerv1.GlobalIngressIP{}
		_ = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, gip)

		//nolint:wrapcheck  // No need to wrap these errors.
		err = controller.reserveAllocatedIPs(federator, obj, func(reservedIPs []string) error {
			var target string
			var tType pfiface.TargetType

			metrics.RecordAllocateGlobalIngressIPs(pool.GetCIDR(), len(reservedIPs))

			if gip.Spec.Target == submarinerv1.ClusterIPService {
				return controller.ensureInternalServiceExists(gip)
			} else if gip.Spec.Target == submarinerv1.HeadlessServicePod {
				target = gip.GetAnnotations()[headlessSvcPodIP]
				tType = pfiface.PodTarget
			} else if gip.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
				target = gip.GetAnnotations()[headlessSvcEndpointsIP]
				tType = pfiface.EndpointsTarget
			} else {
				return nil
			}

			err := controller.pfIface.AddIngressRulesForHeadlessSvc(reservedIPs[0], target, tType)
			if err != nil {
				return err
			}

			key, _ := cache.MetaNamespaceKeyFunc(obj)

			return controller.pfIface.AddEgressRulesForHeadlessSvc(key, target, reservedIPs[0], globalNetIPTableMark, tType)
		})
		if err != nil {
			return nil, err
		}
	}

	controller.resourceSyncer, err = syncer.NewResourceSyncer(&syncer.ResourceSyncerConfig{
		Name:                "GlobalIngressIP syncer",
		ResourceType:        &submarinerv1.GlobalIngressIP{},
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

func (c *globalIngressIPController) GetSyncer() syncer.Interface {
	return c.resourceSyncer
}

func (c *globalIngressIPController) process(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
	ingressIP := from.(*submarinerv1.GlobalIngressIP)

	logger.Infof("Processing %sd %s/%s, TargetRef: %q, %q, Status: %#v", op, ingressIP.Namespace,
		ingressIP.Name, ingressIP.Spec.Target, c.getTargetReference(ingressIP), ingressIP.Status)

	switch op {
	case syncer.Create:
		prevStatus := ingressIP.Status

		trimAllocatedStatusCondition(&ingressIP.Status.Conditions)

		requeue := c.onCreate(ingressIP)

		return checkStatusChanged(&prevStatus, &ingressIP.Status, ingressIP), requeue
	case syncer.Delete:
		return nil, c.onDelete(ingressIP, numRequeues)
	case syncer.Update:
	}

	return nil, false
}

func (c *globalIngressIPController) onCreate(ingressIP *submarinerv1.GlobalIngressIP) bool {
	// If the Ingress GlobalIP is already allocated, we may have gotten here due to an underlying service update (eg ports changed) in
	// which case we need to update the internal service for non-headless.
	if ingressIP.Status.AllocatedIP != "" {
		return c.onUpdate(ingressIP)
	}

	key, _ := cache.MetaNamespaceKeyFunc(ingressIP)

	ips, err := c.pool.Allocate(1)
	if err != nil {
		logger.Errorf(err, "Error allocating IP for %q", key)

		meta.SetStatusCondition(&ingressIP.Status.Conditions, metav1.Condition{
			Type:    string(submarinerv1.GlobalEgressIPAllocated),
			Status:  metav1.ConditionFalse,
			Reason:  "IPPoolAllocationFailed",
			Message: fmt.Sprintf("Error allocating a global IP from the pool: %v", err),
		})

		return true
	}

	logger.Infof("Allocated global IP %q for %q", ips, key)

	if ingressIP.Spec.Target == submarinerv1.ClusterIPService {
		serviceRef := ingressIP.Spec.ServiceRef

		service, exists, err := getService(serviceRef.Name, ingressIP.Namespace, c.services, c.scheme)
		if err != nil || !exists {
			_ = c.pool.Release(ips...)

			key := fmt.Sprintf("%s/%s", ingressIP.Namespace, serviceRef.Name)
			if err != nil {
				logger.Errorf(err, "Error retrieving exported Service %q - re-queueing", key)
			} else {
				logger.Warningf("Exported Service %q does not exist yet - re-queueing", key)
			}

			return false
		}

		err = c.createOrUpdateInternalService(service, ips[0])
		if err != nil {
			_ = c.pool.Release(ips...)

			logger.Errorf(err, "Failed to create the internal Service for %q", key)

			meta.SetStatusCondition(&ingressIP.Status.Conditions, metav1.Condition{
				Type:    string(submarinerv1.GlobalEgressIPAllocated),
				Status:  metav1.ConditionFalse,
				Reason:  "InternalServiceCreationFailed",
				Message: err.Error(),
			})

			return false
		}
	} else {
		var annotationKey string
		var tType pfiface.TargetType

		if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod {
			annotationKey = headlessSvcPodIP
			tType = pfiface.PodTarget
		} else if ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
			annotationKey = headlessSvcEndpointsIP
			tType = pfiface.EndpointsTarget
		}

		target := ingressIP.GetAnnotations()[annotationKey]
		if target == "" {
			_ = c.pool.Release(ips...)

			logger.Warningf("%q annotation is missing on %q", annotationKey, key)

			return true
		}

		err = c.pfIface.AddIngressRulesForHeadlessSvc(ips[0], target, tType)
		if err != nil {
			logger.Errorf(err, "Error while programming Service %q ingress rules for %v", key, tType)
			err = errors.WithMessage(err, "Error programming ingress rules")
		} else {
			err = c.pfIface.AddEgressRulesForHeadlessSvc(key, target, ips[0], globalNetIPTableMark, tType)
			if err != nil {
				_ = c.pfIface.RemoveIngressRulesForHeadlessSvc(ips[0], target, tType)
				err = errors.WithMessage(err, "Error programming egress rules")
			}
		}

		if err != nil {
			_ = c.pool.Release(ips...)

			meta.SetStatusCondition(&ingressIP.Status.Conditions, metav1.Condition{
				Type:    string(submarinerv1.GlobalEgressIPAllocated),
				Status:  metav1.ConditionFalse,
				Reason:  "ProgramIPTableRulesFailed",
				Message: err.Error(),
			})

			return true
		}
	}

	metrics.RecordAllocateGlobalIngressIPs(c.pool.GetCIDR(), 1)

	ingressIP.Status.AllocatedIP = ips[0]

	meta.SetStatusCondition(&ingressIP.Status.Conditions, metav1.Condition{
		Type:    string(submarinerv1.GlobalEgressIPAllocated),
		Status:  metav1.ConditionTrue,
		Reason:  "Success",
		Message: "Allocated global IP",
	})

	return false
}

func (c *globalIngressIPController) createOrUpdateInternalService(from *corev1.Service, extIP string) error {
	internalService := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: GetInternalSvcName(from.Name),
			Labels: map[string]string{
				InternalServiceLabel: from.Name,
			},
			Finalizers: []string{InternalServiceFinalizer},
		},
		Spec: corev1.ServiceSpec{
			Ports:                    from.Spec.Ports,
			Selector:                 from.Spec.Selector,
			ExternalIPs:              []string{extIP},
			IPFamilyPolicy:           ptr.To(corev1.IPFamilyPolicySingleStack),
			PublishNotReadyAddresses: from.Spec.PublishNotReadyAddresses,
		},
	}

	obj := resource.MustToUnstructured(internalService)
	result, err := util.CreateOrUpdate(context.TODO(), resource.ForDynamic(c.services.Namespace(from.Namespace)), obj, util.Replace(obj))

	if result == util.OperationResultCreated {
		logger.Infof("Created internal service \"%s/%s\"", from.Namespace, internalService.Name)
	} else if result == util.OperationResultUpdated {
		logger.Infof("Updated internal service \"%s/%s\"", from.Namespace, internalService.Name)
	}

	return err //nolint:wrapcheck  // No need to wrap here
}

func (c *globalIngressIPController) onUpdate(ingressIP *submarinerv1.GlobalIngressIP) bool {
	if ingressIP.Spec.Target != submarinerv1.ClusterIPService {
		return false
	}

	service, exists, err := getService(ingressIP.Spec.ServiceRef.Name, ingressIP.Namespace, c.services, c.scheme)
	if !exists {
		return false
	}

	if err != nil {
		logger.Errorf(err, "Error retrieving exported Service \"%s/%s\" - re-queueing", ingressIP.Namespace,
			ingressIP.Spec.ServiceRef.Name)
		return true
	}

	err = c.createOrUpdateInternalService(service, ingressIP.Status.AllocatedIP)
	if err != nil {
		logger.Errorf(err, "Failed to update the internal Service for \"%s/%s\"", ingressIP.Namespace, ingressIP.Name)
		return true
	}

	return false
}

//nolint:wrapcheck  // No need to wrap these errors.
func (c *globalIngressIPController) onDelete(ingressIP *submarinerv1.GlobalIngressIP, numRequeues int) bool {
	if ingressIP.Status.AllocatedIP == "" {
		return false
	}

	key, _ := cache.MetaNamespaceKeyFunc(ingressIP)

	if ingressIP.Spec.Target == submarinerv1.ClusterIPService {
		intSvcName := GetInternalSvcName(ingressIP.Spec.ServiceRef.Name)
		logger.Infof("Deleting the service %q/%q created by Globalnet controller", ingressIP.Namespace, intSvcName)

		intSvc, exists, err := getService(intSvcName, ingressIP.Namespace, c.services, c.scheme)
		if err != nil {
			logger.Errorf(err, "Error retrieving the internal service created by Globalnet controller %q", key)
			return shouldRequeue(numRequeues)
		}

		if exists {
			if err = finalizer.Remove(context.TODO(), resource.ForDynamic(c.services.Namespace(ingressIP.Namespace)),
				resource.MustToUnstructured(intSvc), InternalServiceFinalizer); err != nil {
				logger.Errorf(err, "Error while removing the finalizer from service %q", key)
				return true
			}

			err = deleteService(ingressIP.Namespace, intSvcName, c.services)
			if err != nil {
				logger.Errorf(err, "Error while deleting the internal %q", key)
				return true
			}
		}

		if err = c.pool.Release(ingressIP.Status.AllocatedIP); err != nil {
			logger.Errorf(err, "Error while releasing the global IPs for %q", key)
		}

		return false
	}

	return c.flushRulesAndReleaseIPs(key, numRequeues, func(allocatedIPs []string) error {
		var target string
		var tType pfiface.TargetType

		metrics.RecordDeallocateGlobalIngressIPs(c.pool.GetCIDR(), len(allocatedIPs))

		if ingressIP.Spec.Target == submarinerv1.HeadlessServicePod {
			target = ingressIP.GetAnnotations()[headlessSvcPodIP]
			tType = pfiface.PodTarget
		} else if ingressIP.Spec.Target == submarinerv1.HeadlessServiceEndpoints {
			target = ingressIP.GetAnnotations()[headlessSvcEndpointsIP]
			tType = pfiface.EndpointsTarget
		}

		if target != "" {
			if err := c.pfIface.RemoveIngressRulesForHeadlessSvc(ingressIP.Status.AllocatedIP, target, tType); err != nil {
				return err
			}

			return c.pfIface.RemoveEgressRulesForHeadlessSvc(key, target, ingressIP.Status.AllocatedIP, globalNetIPTableMark, tType)
		}

		return nil
	}, ingressIP.Status.AllocatedIP)
}

func (c *globalIngressIPController) ensureInternalServiceExists(ingressIP *submarinerv1.GlobalIngressIP) error {
	serviceRef := ingressIP.Spec.ServiceRef
	internalSvc := GetInternalSvcName(serviceRef.Name)
	key := fmt.Sprintf("%s/%s", ingressIP.Namespace, internalSvc)

	service, exists, err := getService(internalSvc, ingressIP.Namespace, c.services, c.scheme)
	if err != nil {
		return errors.Wrapf(err, "error retrieving Globalnet ExternalIP service %q for GlobalIngressIP %q", key, ingressIP.Name)
	}

	if !exists {
		logger.Warningf("The Globalnet ExternalIP service %q for GlobalIngressIP %q does not exist", key, ingressIP.Name)
		return nil
	}

	if len(service.Spec.ExternalIPs) == 0 || service.Spec.ExternalIPs[0] != ingressIP.Status.AllocatedIP {
		logger.Warningf("The global IP %q for Globalnet ExternalIP service %q does not match that assigned to GlobalIngressIP %q",
			c.getServiceExternalIP(service), key, ingressIP.Name)

		// A user is ideally not supposed to modify the external-ip of the Globalnet internal service, but
		// in-case its done accidentally, as part of controller start/re-start scenario, this code will fix
		// the issue by deleting and re-creating the internal service with valid configuration.
		if err := finalizer.Remove(context.TODO(), resource.ForDynamic(c.services.Namespace(ingressIP.Namespace)),
			resource.MustToUnstructured(service), InternalServiceFinalizer); err != nil {
			return errors.Wrapf(err, "error while removing the finalizer from Globalnet ExternalIP service %q", key)
		}

		return deleteService(ingressIP.Namespace, internalSvc, c.services)
	}

	return nil
}

func (c *globalIngressIPController) getServiceExternalIP(service *corev1.Service) string {
	if len(service.Spec.ExternalIPs) == 0 {
		return ""
	}

	return service.Spec.ExternalIPs[0]
}

func (c *globalIngressIPController) getTargetReference(giip *submarinerv1.GlobalIngressIP) string {
	if giip.Spec.Target == submarinerv1.ClusterIPService {
		return giip.Spec.ServiceRef.Name
	} else if giip.Spec.Target == submarinerv1.HeadlessServicePod {
		return giip.Spec.PodRef.Name
	}

	return ""
}
