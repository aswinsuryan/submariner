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

package natdiscovery

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	k8snet "k8s.io/utils/net"
)

func testListenerLoopExitsOnClose(family k8snet.IPFamily) {
	nd := &natDiscovery{}
	ended := make(chan struct{}, 1)

	serverConnection, err := createServerConnection(12345, family)
	Expect(err).NotTo(HaveOccurred())

	go func() {
		nd.listenerLoop(serverConnection)
		close(ended)
	}()

	Consistently(ended).ShouldNot(BeClosed())

	serverConnection.Close()
	Eventually(ended).Should(BeClosed())
}

var _ = Describe("Listener", func() {
	When("the server connection is closed", func() {
		It("should exit the listen loop for IPv4", func() {
			testListenerLoopExitsOnClose(k8snet.IPv4)
		})
		It("should exit the listen loop for IPv6", func() {
			testListenerLoopExitsOnClose(k8snet.IPv6)
		})
	})
})
