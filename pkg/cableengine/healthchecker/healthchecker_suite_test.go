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

package healthchecker_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/submariner-io/admiral/pkg/log/kzerolog"
	submarinerv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	kubeScheme "k8s.io/client-go/kubernetes/scheme"
)

func init() {
	kzerolog.AddFlags(nil)
}

var _ = BeforeSuite(func() {
	kzerolog.InitK8sLogging()
	Expect(submarinerv1.AddToScheme(kubeScheme.Scheme)).To(Succeed())
})

func TestHealthChecker(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Health Checker Suite")
}
