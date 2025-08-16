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
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/pkg/errors"
	"github.com/submariner-io/admiral/pkg/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var certLogger = log.Logger{Logger: logf.Log.WithName("certificate-controller")}

// CertificateController watches certificate secrets and loads them into NSS database
type CertificateController struct {
	client    dynamic.Interface
	clusterID string
	nssDBDir  string
	stopCh    chan struct{}
	informer  cache.SharedIndexInformer
}

// NewCertificateController creates a new certificate controller
func NewCertificateController(client dynamic.Interface, clusterID string) *CertificateController {
	return &CertificateController{
		client:    client,
		clusterID: clusterID,
		nssDBDir:  "/var/lib/ipsec/nss",
		stopCh:    make(chan struct{}),
	}
}

// Start starts the certificate controller
func (c *CertificateController) Start() error {
	certSecretName := getCertSecretName(c.clusterID)

	certLogger.Info("Starting certificate controller", "secretName", certSecretName, "namespace", LocalNamespace)

	// Start a simple watcher goroutine
	go c.watchCertificateSecret()

	// Try initial load
	c.tryInitialCertificateLoad()

	certLogger.Info("Certificate controller started successfully")
	return nil
}

// Stop stops the certificate controller
func (c *CertificateController) Stop() {
	certLogger.Info("Stopping certificate controller")
	close(c.stopCh)
}

// watchCertificateSecret implements a simple polling-based watcher
func (c *CertificateController) watchCertificateSecret() {
	certLogger.Info("Starting certificate secret watcher")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			certLogger.Info("Certificate secret watcher stopped")
			return
		case <-ticker.C:
			c.checkAndLoadCertificate()
		}
	}
}

// tryInitialCertificateLoad attempts to load certificates immediately if they're available
func (c *CertificateController) tryInitialCertificateLoad() {
	c.checkAndLoadCertificate()
}

// checkAndLoadCertificate checks for certificate availability and loads it
func (c *CertificateController) checkAndLoadCertificate() {
	certSecretName := getCertSecretName(c.clusterID)

	// Try to get the secret
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")
	secretClient := c.client.Resource(gvr).Namespace(LocalNamespace)

	unstructuredSecret, err := secretClient.Get(context.TODO(), certSecretName, metav1.GetOptions{})
	if err != nil {
		certLogger.V(1).Infof("Certificate secret not found: %v", err)
		return
	}

	// Extract data directly from unstructured object
	c.handleUnstructuredSecret(unstructuredSecret.Object)
}

// handleUnstructuredSecret extracts certificate data from an unstructured Kubernetes secret
func (c *CertificateController) handleUnstructuredSecret(unstructuredSecret interface{}) {
	log := certLogger.WithValues("event", "CHECK")

	// Extract the object as an unstructured map
	objMap, ok := unstructuredSecret.(map[string]interface{})
	if !ok {
		log.Error(nil, "Failed to cast secret to map")
		return
	}

	// Get metadata
	metadata, ok := objMap["metadata"].(map[string]interface{})
	if !ok {
		log.Error(nil, "Failed to get metadata from secret")
		return
	}

	// Check secret name
	secretName, _ := metadata["name"].(string)
	certSecretName := getCertSecretName(c.clusterID)
	if secretName != certSecretName {
		return
	}

	// Get annotations
	annotations, _ := metadata["annotations"].(map[string]interface{})

	// Check if certificate is signed
	if annotations == nil {
		log.V(1).Info("No annotations found, certificate not yet signed")
		return
	}

	signedAnnotation, _ := annotations["submariner.io/csr-request-signed"].(string)
	if signedAnnotation != "true" {
		log.V(1).Info("Certificate not yet signed, skipping NSS loading")
		return
	}

	// Get data
	data, ok := objMap["data"].(map[string]interface{})
	if !ok {
		log.Error(nil, "Failed to get data from secret")
		return
	}

	// Extract certificate data (base64 encoded)
	tlsCertB64, tlsOk := data["tls.crt"].(string)
	tlsKeyB64, keyOk := data["tls.key"].(string)
	caCertB64, caOk := data["ca.crt"].(string)

	if !tlsOk || !keyOk || !caOk {
		log.Info("Certificate data incomplete, skipping NSS loading")
		return
	}

	// Decode base64 data

	tlsCert, err := base64.StdEncoding.DecodeString(tlsCertB64)
	if err != nil {
		log.Error(err, "Failed to decode tls.crt")
		return
	}

	tlsKey, err := base64.StdEncoding.DecodeString(tlsKeyB64)
	if err != nil {
		log.Error(err, "Failed to decode tls.key")
		return
	}

	caCert, err := base64.StdEncoding.DecodeString(caCertB64)
	if err != nil {
		log.Error(err, "Failed to decode ca.crt")
		return
	}

	log.Info("Certificate ready, loading into NSS database")

	// Log certificate details including SAN
	c.logCertificateDetails(tlsCert)

	// Initialize NSS database if needed
	if err := c.initNSSDatabase(); err != nil {
		log.Error(err, "Failed to initialize NSS database")
		return
	}

	// Load certificates into NSS
	if err := c.loadCertificatesIntoNSS(tlsCert, tlsKey, caCert); err != nil {
		log.Error(err, "Failed to load certificates into NSS database")
		return
	}

	log.Info("Certificates successfully loaded into NSS database")
}

// initNSSDatabase initializes the NSS database if it doesn't exist
func (c *CertificateController) initNSSDatabase() error {
	// Check if NSS database already exists (likely from OVN)
	if _, err := os.Stat(c.nssDBDir + "/cert9.db"); err == nil {
		certLogger.Info("NSS database already exists (likely from OVN), using existing database")

		// List existing certificates for debugging
		ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+c.nssDBDir)
		output, err := cmd.CombinedOutput()
		if err == nil {
			certLogger.V(1).Infof("Existing certificates in NSS database:\n%s", string(output))
		}

		return nil
	}

	certLogger.Info("NSS database does not exist, initializing new database")
	ctx, cancel := context.WithTimeout(context.TODO(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-N", "-d", "sql:"+c.nssDBDir, "--empty-password")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to initialize NSS database: %s", string(output))
	}

	certLogger.Info("NSS database initialized successfully")
	return nil
}

// loadCertificatesIntoNSS loads all certificates into NSS database
func (c *CertificateController) loadCertificatesIntoNSS(tlsCert, tlsKey, caCert []byte) error {
	// Load CA certificate
	if err := c.loadCACertIntoNSS(caCert); err != nil {
		return errors.Wrap(err, "failed to load CA certificate into NSS")
	}

	// Load client certificate and key
	if err := c.loadClientCertIntoNSS(tlsCert, tlsKey); err != nil {
		return errors.Wrap(err, "failed to load client certificate into NSS")
	}

	// List all certificates for verification
	if err := c.listCertificatesInNSS(); err != nil {
		certLogger.Warningf("Failed to list certificates after loading: %v", err)
	}

	return nil
}

// loadCACertIntoNSS loads the CA certificate into NSS database
func (c *CertificateController) loadCACertIntoNSS(caCertPEM []byte) error {
	caName := "submariner-ca"

	// Check if CA already exists
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+c.nssDBDir, "-n", caName)
	if cmd.Run() == nil {
		certLogger.Info("Submariner CA certificate already exists in NSS database")
		return nil
	}

	certLogger.Info("Loading Submariner CA certificate into NSS database")

	// Write CA cert to temporary file
	caCertFile, err := os.CreateTemp("", "submariner-ca-*.crt")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary CA cert file")
	}
	defer os.Remove(caCertFile.Name())

	if _, err := caCertFile.Write(caCertPEM); err != nil {
		return errors.Wrap(err, "failed to write CA certificate to temporary file")
	}
	caCertFile.Close()

	// Import CA certificate
	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, "certutil", "-A", "-d", "sql:"+c.nssDBDir, "-n", caName, "-t", "CT,,", "-i", caCertFile.Name())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to import CA certificate: %s", string(output))
	}

	certLogger.Info("Submariner CA certificate imported successfully into NSS database")
	return nil
}

// loadClientCertIntoNSS loads the client certificate and private key into NSS database
func (c *CertificateController) loadClientCertIntoNSS(certPEM, keyPEM []byte) error {
	certName := fmt.Sprintf("submariner-client-%s", c.clusterID)

	// Check if client cert already exists
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+c.nssDBDir, "-n", certName)
	if cmd.Run() == nil {
		certLogger.Infof("Submariner client certificate already exists in NSS database: %s", certName)
		return nil
	}

	certLogger.Infof("Loading Submariner client certificate and key into NSS database: %s", certName)

	// Write cert and key to temp files
	certFile, err := os.CreateTemp("", "submariner-cert-*.crt")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary cert file")
	}
	defer os.Remove(certFile.Name())
	if _, err := certFile.Write(certPEM); err != nil {
		return errors.Wrap(err, "failed to write certificate to temporary file")
	}
	certFile.Close()

	keyFile, err := os.CreateTemp("", "submariner-key-*.key")
	if err != nil {
		return errors.Wrap(err, "failed to create temporary key file")
	}
	defer os.Remove(keyFile.Name())
	if _, err := keyFile.Write(keyPEM); err != nil {
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

	// Use a fixed password for pkcs12 (can be empty string, but libreswan doesn't care)
	pkcs12Password := ""

	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "openssl", "pkcs12", "-export",
		"-in", certFile.Name(),
		"-inkey", keyFile.Name(),
		"-out", p12File.Name(),
		"-name", certName,
		"-passout", "pass:"+pkcs12Password)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to create PKCS#12 file: %s", string(output))
	}

	// Import PKCS#12 into NSS
	ctx, cancel = context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "pk12util", "-i", p12File.Name(), "-d", "sql:"+c.nssDBDir, "-W", pkcs12Password)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to import PKCS#12 into NSS: %s", string(output))
	}

	certLogger.Infof("Submariner client certificate and key imported successfully into NSS database: %s", certName)
	return nil
}

// listCertificatesInNSS lists all certificates in NSS database for verification
func (c *CertificateController) listCertificatesInNSS() error {
	ctx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil", "-L", "-d", "sql:"+c.nssDBDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "failed to list certificates in NSS database: %s", string(output))
	}

	certLogger.Infof("All certificates in NSS database:\n%s", string(output))
	return nil
}

// logCertificateDetails parses and logs certificate details including Subject Alternative Names
func (c *CertificateController) logCertificateDetails(certPEM []byte) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		certLogger.Error(nil, "Failed to decode certificate PEM")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		certLogger.Error(err, "Failed to parse certificate")
		return
	}

	certLogger.Infof("Certificate Details: Subject=%s, Serial=%s", cert.Subject.String(), cert.SerialNumber.String())
	certLogger.Infof("Certificate Validity: NotBefore=%s, NotAfter=%s", cert.NotBefore.Format("2006-01-02 15:04:05"), cert.NotAfter.Format("2006-01-02 15:04:05"))

	if len(cert.IPAddresses) > 0 {
		ipAddrs := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ipAddrs[i] = ip.String()
		}
		certLogger.Infof("Certificate Subject Alternative Names (IP addresses): %v", ipAddrs)
	}

	if len(cert.DNSNames) > 0 {
		certLogger.Infof("Certificate Subject Alternative Names (DNS names): %v", cert.DNSNames)
	}

	if len(cert.IPAddresses) == 0 && len(cert.DNSNames) == 0 {
		certLogger.Info("Certificate has no Subject Alternative Names")
	}
}
