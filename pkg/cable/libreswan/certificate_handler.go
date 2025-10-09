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

package libreswan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/certificate"
	"github.com/submariner-io/admiral/pkg/command"
	"github.com/submariner-io/admiral/pkg/log"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var certLogger = log.Logger{Logger: logf.Log.WithName("CertHandler")}

// CertificateHandler handles NSS database operations for certificates.
type CertificateHandler struct {
	clusterID    string
	nssDBDir     string
	lastCertHash string
}

func NewCertificateHandler(clusterID string) *CertificateHandler {
	return &CertificateHandler{
		clusterID: clusterID,
		nssDBDir:  "/var/lib/ipsec/nss",
	}
}

func initNSSDatabase(nssDBDir string) error {
	if _, err := os.Stat(nssDBDir + "/cert9.db"); err == nil {
		certLogger.Info("NSS database already exists , using existing database")
		return nil
	}

	certLogger.Info("NSS database does not exist, initializing new database")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // certutil args are from trusted config
	cmd := command.New(exec.CommandContext(ctx, "certutil", "-N", "-d", "sql:"+nssDBDir, "--empty-password"))

	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "failed to initialize NSS database")
	}

	certLogger.Info("NSS database initialized successfully")

	return nil
}

func loadCertificatesIntoNSS(nssDBDir string, tlsCert, tlsKey, caCert []byte) error {
	// Load CA certificate
	if err := loadCertificate(nssDBDir, caCert, "ca-cert", "CT,", "ca certificate"); err != nil {
		return errors.Wrap(err, "failed to load CA certificate")
	}

	// Load client certificate and key using pk12util
	if err := loadPrivateKey(nssDBDir, tlsCert, tlsKey, "client-cert"); err != nil {
		return errors.Wrap(err, "failed to load client certificate with key")
	}

	return nil
}

func loadCertificate(nssDBDir string, certData []byte, nickname, trustFlags, certType string) error {
	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	//nolint:gosec // certutil args are from trusted config
	execCmd := exec.CommandContext(ctx, "certutil", "-A", "-d", "sql:"+nssDBDir, "-n", nickname, "-t", trustFlags, "-i", "-", "-a")
	execCmd.Stdin = bytes.NewReader(certData)

	cmd := command.New(execCmd)

	if err := cmd.Run(); err != nil {
		return errors.Wrapf(err, "failed to load %s", certType)
	}

	return nil
}

func loadPrivateKey(nssDBDir string, certData, keyData []byte, nickname string) error {
	// Write cert and key to temporary files
	certFile, err := os.CreateTemp("", "submariner-cert-*.crt")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary cert file")
	}
	defer os.Remove(certFile.Name())

	if _, err := certFile.Write(certData); err != nil {
		return errors.Wrap(err, "failed to write certificate to temporary file")
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "submariner-key-*.key")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary key file")
	}
	defer os.Remove(keyFile.Name())

	if _, err := keyFile.Write(keyData); err != nil {
		return errors.Wrap(err, "failed to write key to temporary file")
	}
	keyFile.Close()

	// Create PKCS#12 file with openssl
	p12File, err := os.CreateTemp("", "submariner-client-*.p12")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary pkcs12 file")
	}
	defer os.Remove(p12File.Name())
	p12File.Close()

	// Use empty password for PKCS#12
	pkcs12Password := ""

	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	//nolint:gosec // openssl args are from trusted config
	opensslCmd := exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", certFile.Name(),
		"-inkey", keyFile.Name(),
		"-out", p12File.Name(),
		"-name", nickname,
		"-passout", "pass:"+pkcs12Password)
	cmd := command.New(opensslCmd)
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "failed to create PKCS#12 file")
	}

	// Import PKCS#12 into NSS using pk12util
	ctx, cancel = context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()
	pk12Cmd := exec.CommandContext(ctx, "pk12util", "-i", p12File.Name(), "-d", "sql:"+nssDBDir, "-W", pkcs12Password)
	cmd = command.New(pk12Cmd)
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "failed to import PKCS#12 into NSS")
	}

	return nil
}

func (c *CertificateHandler) Cleanup() {
	certLogger.Info("Cleaning up certificate handler")
	c.cleanupCertificateFromNSS()
}

func (c *CertificateHandler) cleanupCertificateFromNSS() {
	certName := "submariner-client-" + c.clusterID
	caName := "submariner-ca"
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)

	defer cancel()

	// Delete client certificate
	//nolint:gosec // certutil args are from trusted config
	cmd := command.New(exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", certName))

	if err := cmd.Run(); err != nil {
		certLogger.Warningf("Failed to delete client certificate from NSS database: %v", err)
	} else {
		certLogger.Infof("Deleted Submariner client certificate from NSS database: %s", certName)
	}

	// Delete CA certificate
	//nolint:gosec // certutil args are from trusted config
	cmd = command.New(exec.CommandContext(ctx, "certutil", "-D", "-d", "sql:"+c.nssDBDir, "-n", caName))

	if err := cmd.Run(); err != nil {
		certLogger.Warningf("Failed to delete CA certificate from NSS database: %v", err)
	} else {
		certLogger.Infof("Deleted Submariner CA certificate from NSS database: %s", caName)
	}
}

// OnSignedCallback implements the OnSignedFn callback for admiral's SigningRequestor.
func (c *CertificateHandler) OnSignedCallback(secretData map[string][]byte) error {
	// Extract certificate data
	tlsCert := secretData[certificate.TLSDataKey]
	tlsKey := secretData[certificate.PrivateKeyDataKey]
	caCert := secretData[certificate.CADataKey]

	// Compute hash of cert+key+ca to avoid reloading the same certificates
	certData := string(tlsCert) + string(tlsKey) + string(caCert)
	certHash := fmt.Sprintf("%x", sha256.Sum256([]byte(certData)))

	if certHash == c.lastCertHash {
		certLogger.V(log.TRACE).Info("Certificate data unchanged, skipping NSS loading")
		return nil
	}

	certLogger.Info("Certificate ready, loading into NSS database")

	if err := initNSSDatabase(c.nssDBDir); err != nil {
		return errors.Wrap(err, "failed to initialize NSS database")
	}

	if err := loadCertificatesIntoNSS(c.nssDBDir, tlsCert, tlsKey, caCert); err != nil {
		return errors.Wrap(err, "failed to load certificates into NSS database")
	}

	certLogger.Info("Certificates successfully loaded into NSS database via callback")

	c.lastCertHash = certHash

	return nil
}
