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
	"context"
	"flag"
	"os"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/submariner-io/admiral/pkg/configmap"
	"github.com/submariner-io/admiral/pkg/http"
	"github.com/submariner-io/admiral/pkg/log"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	"github.com/submariner-io/admiral/pkg/names"
	"github.com/submariner-io/admiral/pkg/resource"
	"github.com/submariner-io/admiral/pkg/util"
	admversion "github.com/submariner-io/admiral/pkg/version"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cidr"
	submarinerClientset "github.com/submariner-io/submariner/pkg/client/clientset/versioned"
	"github.com/submariner-io/submariner/pkg/globalnet/controllers"
	pfconfigure "github.com/submariner-io/submariner/pkg/packetfilter/configure"
	"github.com/submariner-io/submariner/pkg/versions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	k8snet "k8s.io/utils/net"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	mcsv1a1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
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

	admversion.Print(names.GlobalnetComponent, versions.Submariner())

	if showVersion {
		return
	}

	kzerolog.InitK8sLogging()

	versions.Log(&logger)

	var spec controllers.Specification

	err := envconfig.Process("submariner", &spec)
	logger.FatalOnError(err, "Error processing env config")

	cfg, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfig)
	logger.FatalOnError(err, "Error building kube config")

	submarinerClient, err := submarinerClientset.NewForConfig(cfg)
	logger.FatalOnError(err, "Error building submariner clientset")

	k8sClient, err := kubernetes.NewForConfig(cfg)
	logger.FatalOnError(err, "Error creating Kubernetes clientset")

	dynClient, err := dynamic.NewForConfig(cfg)
	logger.FatalOnError(err, "Unable to create dynamic client")

	// set up signals so we handle the first shutdown signal gracefully
	ctx := signals.SetupSignalHandler()

	globalConfigMap, err := configmap.Get(ctx, resource.ForConfigMap(k8sClient, spec.Namespace), configmap.Global)
	logger.FatalOnError(err, "Error retrieving the global ConfigMap")

	err = pfconfigure.DriverFromConfigMap(globalConfigMap)
	logger.FatalOnError(err, "Error configuring packet filter driver")

	if spec.Uninstall {
		logger.Info("Uninstalling submariner-globalnet")

		controllers.UninstallDataPath()
		controllers.DeleteGlobalnetObjects(submarinerClient, dynClient)

		return
	}

	logger.Info("Starting submariner-globalnet", spec)

	defer http.StartServer(http.Metrics|http.Profile, spec.MetricsPort)()

	err = mcsv1a1.AddToScheme(scheme.Scheme)
	logger.FatalOnError(err, "Error adding Multicluster v1alpha1 to the scheme")

	err = submarinerv1.AddToScheme(scheme.Scheme)
	logger.FatalOnError(err, "Error adding submariner to the scheme")

	var localCluster *submarinerv1.Cluster
	// During installation, sometimes creation of clusterCRD by submariner-gateway-pod would take few secs.
	for range 100 {
		localCluster, err = submarinerClient.SubmarinerV1().Clusters(spec.Namespace).Get(context.TODO(), spec.ClusterID,
			metav1.GetOptions{})
		if err == nil {
			break
		}

		time.Sleep(3 * time.Second)
	}

	logger.FatalfOnError(err, "Error while retrieving the local cluster %q info even after waiting for 5 mins", spec.ClusterID)

	if len(localCluster.Spec.GlobalCIDR) > 0 {
		spec.GlobalCIDR = localCluster.Spec.GlobalCIDR
	} else {
		logger.Fatalf("Cluster %s is not configured to use globalCidr", spec.ClusterID)
	}

	hostname, err := os.Hostname()
	logger.FatalOnError(err, "Unable to determine hostname")

	restMapper, err := util.BuildRestMapper(cfg)
	logger.FatalOnError(err, "Unable to build the REST mapper")

	clusterCIDRs := cidr.ExtractSubnets(k8snet.IPv4, localCluster.Spec.ClusterCIDR)

	gatewayMonitor, err := controllers.NewGatewayMonitor(ctx, &controllers.GatewayMonitorConfig{
		Client:            dynClient,
		RestMapper:        restMapper,
		Scheme:            scheme.Scheme,
		Spec:              spec,
		LocalClusterCIDRs: clusterCIDRs,
		LocalCIDRs:        append(clusterCIDRs, cidr.ExtractSubnets(k8snet.IPv4, localCluster.Spec.ServiceCIDR)...),
		KubeClient:        k8sClient,
		Hostname:          hostname,
	})
	logger.FatalOnError(err, "Error creating gatewayMonitor")

	err = gatewayMonitor.Start()
	logger.FatalOnError(err, "Error starting the gatewayMonitor")

	<-ctx.Done()
	gatewayMonitor.Stop()

	logger.Infof("All controllers stopped or exited. Stopping main loop")
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "",
		"The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
	flag.BoolVar(&showVersion, "version", showVersion, "Show version")
}
