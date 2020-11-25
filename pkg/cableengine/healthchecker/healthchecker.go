package healthchecker

import (
	"sync"

	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/watcher"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"
)

type LatencyInfo struct {
	ConnectionError string
	Spec            *submarinerv1.LatencySpec
}

type Interface interface {
	Start(stopCh <-chan struct{}) error

	GetLatencyInfo(hostName string) interface{}
}

type controller struct {
	endpointWatcher watcher.Interface
	pingers         sync.Map
	clusterID       string
}

func New(config *watcher.Config, endpointNameSpace, clusterID string) (Interface, error) {
	controller := &controller{
		clusterID: clusterID,
	}
	config.ResourceConfigs = []watcher.ResourceConfig{
		{
			Name:         "HealthChecker Endpoint Controller",
			ResourceType: &submarinerv1.Endpoint{},
			Handler: watcher.EventHandlerFuncs{
				OnCreateFunc: controller.endpointCreatedorUpdated,
				OnUpdateFunc: controller.endpointCreatedorUpdated,
				OnDeleteFunc: controller.endpointDeleted,
			},
			SourceNamespace: endpointNameSpace,
		},
	}

	endpointWatcher, err := watcher.New(config)

	if err != nil {
		return nil, err
	}

	controller.endpointWatcher = endpointWatcher

	return controller, nil
}

func (h *controller) GetLatencyInfo(hostName string) interface{} {
	if obj, found := h.pingers.Load(hostName); found {
		pinger := obj.(*pingerInfo)

		return &LatencyInfo{
			ConnectionError: pinger.failureMsg,
			Spec: &submarinerv1.LatencySpec{
				LastRTT:    pinger.statistics.lastRtt,
				MinRTT:     pinger.statistics.minRtt,
				AverageRTT: pinger.statistics.mean,
				MaxRTT:     pinger.statistics.maxRtt,
				StdDevRTT:  pinger.statistics.stdDev,
			},
		}
	}

	return nil
}

func (h *controller) Start(stopCh <-chan struct{}) error {
	if err := h.endpointWatcher.Start(stopCh); err != nil {
		return err
	}

	return nil
}

func (h *controller) endpointCreatedorUpdated(obj runtime.Object) bool {
	klog.V(log.TRACE).Infof("Endpoint created: %#v", obj)
	endpointCreated := obj.(*submarinerv1.Endpoint)
	if endpointCreated.Spec.ClusterID == h.clusterID {
		return false
	}

	if endpointCreated.Spec.HealthCheckIP == "" || endpointCreated.Spec.Hostname == "" {
		klog.Infof("HealthCheckIP (%q) and/or Hostname (%q) for Endpoint %q empty - will not monitor endpoint health",
			endpointCreated.Spec.HealthCheckIP, endpointCreated.Spec.Hostname, endpointCreated.Name)
		return false
	}

	if obj, found := h.pingers.Load(endpointCreated.Spec.Hostname); found {
		pinger := obj.(*pingerInfo)
		if pinger.healthCheckIP == endpointCreated.Spec.HealthCheckIP {
			return false
		}

		klog.V(log.DEBUG).Infof("HealthChecker is already running for %q - stopping", endpointCreated.Name)
		pinger.stop()
		h.pingers.Delete(endpointCreated.Spec.Hostname)
	}

	klog.V(log.TRACE).Infof("Starting Pinger for Hostname: %q, with HealthCheckIP: %q",
		endpointCreated.Spec.HealthCheckIP, endpointCreated.Spec.Hostname)

	pinger := newPinger(endpointCreated.Spec.HealthCheckIP)
	h.pingers.Store(endpointCreated.Spec.HealthCheckIP, pinger)
	pinger.start()

	return false
}

func (h *controller) endpointDeleted(obj runtime.Object) bool {
	endpointDeleted := obj.(*submarinerv1.Endpoint)
	if endpointDeleted.Spec.Hostname == "" {
		return false
	}

	if obj, found := h.pingers.Load(endpointDeleted.Spec.HealthCheckIP); found {
		pinger := obj.(*pingerInfo)
		pinger.stop()
		h.pingers.Delete(endpointDeleted.Spec.Hostname)
	}

	return false
}
