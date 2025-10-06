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

package libreswan_test

import (
	"context"
	"os"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/certificate"
	fakecommand "github.com/submariner-io/admiral/pkg/command/fake"
	subv1 "github.com/submariner-io/submariner/pkg/apis/submariner.io/v1"
	"github.com/submariner-io/submariner/pkg/cable/libreswan"
	"github.com/submariner-io/submariner/pkg/endpoint"
	"github.com/submariner-io/submariner/pkg/types"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

type mockSigningRequestor struct{}

func (m *mockSigningRequestor) Issue(ctx context.Context, name string, sanIPs []string, callback certificate.OnSignedFn) error {
	certData := map[string][]byte{
		certificate.TLSDataKey:        []byte("mock-tls-cert"),
		certificate.PrivateKeyDataKey: []byte("mock-tls-key"),
		certificate.CADataKey:         []byte("mock-ca-cert"),
	}

	return callback(certData)
}

func (m *mockSigningRequestor) Uninstall(ctx context.Context) error {
	return nil
}

func (m *mockSigningRequestor) Remove(ctx context.Context, name string) error {
	return nil
}

func testCertificate() {
	_ = newTestDriver()

	When("certificate authentication mode is enabled", func() {
		It("should create driver with certificate mode", func() {
			os.Setenv(authModeEnvVar, "cert")
			defer os.Unsetenv(authModeEnvVar)

			endpointSpec := subv1.EndpointSpec{
				ClusterID:  "local",
				CableName:  "submariner-cable-local-192-68-1-1",
				PrivateIPs: []string{"192.68.1.1"},
				Subnets:    []string{"10.0.0.0/16"},
			}
			localEndpoint := endpoint.NewLocal(&endpointSpec, dynamicfake.NewSimpleDynamicClient(scheme.Scheme), "")

			driver, err := libreswan.NewLibreswan(localEndpoint, &types.SubmarinerCluster{}, &mockSigningRequestor{})
			Expect(err).NotTo(HaveOccurred())

			Expect(driver).NotTo(BeNil())
			Expect(driver.GetName()).To(Equal("libreswan"))
		})
	})

	Context("Certificate loading", func() {
		var cmdExecutor *fakecommand.Executor
		var handler *libreswan.CertificateHandler

		BeforeEach(func() {
			cmdExecutor = fakecommand.New()
			handler = libreswan.NewCertificateHandler("test-cluster")
			Expect(handler).NotTo(BeNil())
			DeferCleanup(cmdExecutor.Clear)
		})

		It("should successfully load certificates into NSS database", func() {
			certData := map[string][]byte{
				certificate.CADataKey:         []byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_CERT\n-----END CERTIFICATE-----"),
				certificate.TLSDataKey:        []byte("-----BEGIN CERTIFICATE-----\nMOCK_CLIENT_CERT\n-----END CERTIFICATE-----"),
				certificate.PrivateKeyDataKey: []byte("-----BEGIN PRIVATE KEY-----\nMOCK_CLIENT_KEY\n-----END PRIVATE KEY-----"),
			}

			err := handler.OnSignedCallback(certData)
			Expect(err).NotTo(HaveOccurred())

			cmdExecutor.AwaitCommand(ContainSubstring("certutil"), "-N", "--empty-password")
			cmdExecutor.AwaitCommand(ContainSubstring("certutil"), "-A", "ca-cert")
			cmdExecutor.AwaitCommand(ContainSubstring("certutil"), "-A", "client-cert")
			cmdExecutor.AwaitCommand(ContainSubstring("certutil"), "-A", "client-key")
		})

		It("should handle NSS database initialization failure", func() {
			cmdExecutor = fakecommand.NewWithInterceptor(func(cmd *exec.Cmd) fakecommand.InterceptorFuncs {
				if fakecommand.CmdMatches(cmd, ContainSubstring("certutil"), "-N", "--empty-password") {
					return fakecommand.InterceptorFuncs{Run: func() error {
						return errors.New("database init failed")
					}}
				}

				return fakecommand.InterceptorFuncs{}
			})

			certData := map[string][]byte{
				certificate.CADataKey:         []byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_CERT\n-----END CERTIFICATE-----"),
				certificate.TLSDataKey:        []byte("-----BEGIN CERTIFICATE-----\nMOCK_CLIENT_CERT\n-----END CERTIFICATE-----"),
				certificate.PrivateKeyDataKey: []byte("-----BEGIN PRIVATE KEY-----\nMOCK_CLIENT_KEY\n-----END PRIVATE KEY-----"),
			}

			err := handler.OnSignedCallback(certData)
			Expect(err).To(HaveOccurred())
		})

		It("should handle certificate loading failure", func() {
			cmdExecutor = fakecommand.NewWithInterceptor(func(cmd *exec.Cmd) fakecommand.InterceptorFuncs {
				if fakecommand.CmdMatches(cmd, ContainSubstring("certutil"), "-A", "ca-cert") {
					return fakecommand.InterceptorFuncs{Run: func() error {
						return errors.New("certificate load failed")
					}}
				}

				return fakecommand.InterceptorFuncs{}
			})

			certData := map[string][]byte{
				certificate.CADataKey:         []byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_CERT\n-----END CERTIFICATE-----"),
				certificate.TLSDataKey:        []byte("-----BEGIN CERTIFICATE-----\nMOCK_CLIENT_CERT\n-----END CERTIFICATE-----"),
				certificate.PrivateKeyDataKey: []byte("-----BEGIN PRIVATE KEY-----\nMOCK_CLIENT_KEY\n-----END PRIVATE KEY-----"),
			}

			err := handler.OnSignedCallback(certData)
			Expect(err).To(HaveOccurred())
		})
	})
}
