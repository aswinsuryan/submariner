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

package main

import (
	"flag"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/configmap"
	"github.com/submariner-io/admiral/pkg/http"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	"github.com/submariner-io/admiral/pkg/names"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/util"
	admversion "github.com/submariner-io/admiral/pkg/version"
	"github.com/submariner-io/admiral/pkg/watcher"
	v1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cidr"
	submarinerClientset "github.com/submariner-io/submariner/pkg/client/clientset/versioned"
	"github.com/submariner-io/submariner/pkg/cni"
	"github.com/submariner-io/submariner/pkg/event"
	"github.com/submariner-io/submariner/pkg/event/controller"
	"github.com/submariner-io/submariner/pkg/node"
	pfconfigure "github.com/submariner-io/submariner/pkg/packetfilter/configure"
	"github.com/submariner-io/submariner/pkg/pinger"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/cabledriver"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/environment"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/calico"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/healthchecker"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/kubeproxy"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/mtu"
	"github.com/submariner-io/submariner/pkg/routeagent_driver/handlers/ovn"
	"github.com/submariner-io/submariner/pkg/types"
	"github.com/submariner-io/submariner/pkg/versions"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
)

var (
	masterURL   string
	kubeconfig  string
	logger      = log.Logger{Logger: logf.Log.WithName("main")}
	showVersion = false
)

func main() {
	kzerolog.AddFlags(nil)
	flag.Parse()

	admversion.Print(names.RouteAgentComponent, versions.Submariner())

	if showVersion {
		return
	}

	kzerolog.InitK8sLogging()

	versions.Log(&logger)

	logger.Info("Starting submariner-route-agent using the event framework")
	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.SetupSignalHandler()

	// Clean up "sockets" created as directories by previous versions
	removeInvalidSockets()

	var env environment.Specification

	err := envconfig.Process("submariner", &env)
	logger.FatalOnError(err, "Error reading the environment variables")

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	logger.FatalOnError(err, "Error building kubeconfig")

	k8sClientSet, err := kubernetes.NewForConfig(cfg)
	logger.FatalOnError(err, "Error building clientset")

	dynamicClientSet, err := dynamic.NewForConfig(cfg)
	logger.FatalOnError(err, "Error building dynamic clientr")

	err = v1.AddToScheme(scheme.Scheme)
	logger.FatalOnError(err, "Error adding submariner to the scheme")

	smClientset, err := submarinerClientset.NewForConfig(cfg)
	logger.FatalOnError(err, "Error building submariner clientset")

	restMapper, err := util.BuildRestMapper(cfg)
	logger.FatalOnError(err, "Error building the REST mapper")

	globalConfigMap, err := configmap.Get(ctx, resource.ForConfigMap(k8sClientSet, env.Namespace), configmap.Global)
	logger.FatalOnError(err, "Error retrieving the global ConfigMap")

	err = pfconfigure.DriverFromConfigMap(globalConfigMap)
	logger.FatalOnError(err, "Error configuring packet filter driver")

	np := os.Getenv("SUBMARINER_NETWORKPLUGIN")

	if np == "" {
		np = cni.Generic
	}

	transitSwitchIP := ovn.NewTransitSwitchIP()
	submSpec := types.SubmarinerSpecification{}
	logger.FatalOnError(envconfig.Process("submariner", &submSpec), "Error processing env vars")

	config := &watcher.Config{RestConfig: cfg}

	localNode, err := node.GetLocalNode(ctx, k8sClientSet)
	logger.FatalOnError(err, "Error getting information on the local node")

	var handlers []event.Handler //nolint:prealloc // Ignore

	for _, family := range cidr.ExtractIPFamilies(env.ClusterCidr) {
		handlers = append(handlers, kubeproxy.NewSyncHandler(family, env.ClusterCidr, env.ServiceCidr),
			mtu.NewHandler(family, env.ClusterCidr, len(env.GlobalCidr) != 0, getTCPMssValue(localNode)),
			ovn.NewHandler(family, &ovn.HandlerConfig{
				Namespace:       env.Namespace,
				ClusterCIDR:     env.ClusterCidr,
				ServiceCIDR:     env.ServiceCidr,
				SubmClient:      smClientset,
				K8sClient:       k8sClientSet,
				DynClient:       dynamicClientSet,
				WatcherConfig:   config,
				TransitSwitchIP: transitSwitchIP,
			}),
			ovn.NewGatewayRouteHandler(family, smClientset))
	}

	handlers = append(handlers,
		ovn.NewNonGatewayRouteHandler(smClientset, transitSwitchIP),
		cabledriver.NewXRFMCleanupHandler(),
		cabledriver.NewVXLANCleanup(),
		calico.NewCalicoIPPoolHandler(cfg, env.Namespace, k8sClientSet),
		healthchecker.New(&healthchecker.Config{
			ControllerConfig: pinger.ControllerConfig{
				SupportedIPFamilies: submSpec.GetIPFamilies(),
				PingInterval:        submSpec.HealthCheckInterval * 60,
				MaxPacketLossCount:  submSpec.HealthCheckMaxPacketLossCount,
			},
			HealthCheckerEnabled:     submSpec.HealthCheckEnabled,
			RouteAgentUpdateInterval: 60 * time.Second,
		}, smClientset.SubmarinerV1().RouteAgents(submSpec.Namespace), versions.Submariner(), localNode.Name))

	registry, err := event.NewRegistry(ctx, "routeagent_driver", np, handlers...)

	logger.FatalOnError(err, "Error registering the handlers")

	if env.Uninstall {
		uninstall(registry)

		return
	}

	defer http.StartServer(http.Profile, env.ProfilePort)()

	ctl, err := controller.New(&controller.Config{
		Registry:   registry,
		Client:     dynamicClientSet,
		RestMapper: restMapper,
	})
	logger.FatalOnError(err, "Error creating controller for event handling")

	stopCh := ctx.Done()

	err = ctl.Start(stopCh)
	logger.FatalOnError(err, "Error starting controller")

	<-stopCh
	ctl.Stop()

	logger.Info("All controllers stopped or exited. Stopping submariner-route-agent")
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.BoolVar(&showVersion, "version", showVersion, "Show version")
}

func getTCPMssValue(localNode *corev1.Node) int {
	tcpMssStr := localNode.GetAnnotations()[v1.TCPMssValue]

	if tcpMssStr == "" {
		return 0
	}

	tcpMssValue, err := strconv.Atoi(tcpMssStr)
	if err != nil {
		logger.Errorf(err, "Error parsing %q annotation", v1.TCPMssValue)
		return 0
	}

	return tcpMssValue
}

func uninstall(registry *event.Registry) {
	if err := registry.StopHandlers(); err != nil {
		logger.Warningf("Error stopping handlers: %v", err)
	}

	if err := registry.Uninstall(); err != nil {
		logger.Warningf("Error uninstalling handlers: %v", err)
	}
}

func removeInvalidSockets() {
	// This can be removed once we stop supporting upgrades from 0.16.0 or older
	for _, dir := range []string{"/run/openvswitch/db.sock", "/var/run/openvswitch/ovnnb_db.sock", "/var/run/ovn-ic/ovnnb_db.sock"} {
		info, err := os.Stat(dir)
		if (err == nil || errors.Is(err, fs.ErrExist)) && info.IsDir() {
			err := os.Remove(dir)
			if err != nil {
				logger.Errorf(err, "Failed to delete invalid socket %s", dir)
			} else {
				logger.Infof("Deleted invalid socket %s", dir)
			}
		}
	}
}
