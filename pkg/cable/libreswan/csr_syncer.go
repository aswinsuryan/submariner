package libreswan

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/submariner-io/admiral/pkg/syncer"
	"github.com/submariner-io/admiral/pkg/syncer/broker"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"net"
)

const (
	RSABitSize        = 2048
	CertSecretName    = "submariner-certificate"
	LocalNamespace    = "submariner-operator"
	CertLabelKey      = "submariner.io/csr-request"
	PrivateKeyDataKey = "tls.key"
	CSRDataKey        = "csr.pem"
	SignedCertDataKey = "tls.crt"
)

func (i *libreswan) EnsureCertificateSecret(clusterID string, sanIPs []string) error {
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")
	secretClient := i.syncerConfig.LocalClient.Resource(gvr).Namespace(LocalNamespace)

	_, err := secretClient.Get(context.TODO(), CertSecretName, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	if !errors.IsNotFound(err) {
		return err
	}

	keyPEM, csrPEM, err := generateKeyAndCSR(clusterID, sanIPs)
	if err != nil {
		return fmt.Errorf("failed to generate key and CSR: %w", err)
	}

	// Build corev1.Secret, then convert it
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      CertSecretName,
			Namespace: LocalNamespace,
			Labels: map[string]string{
				CertLabelKey: clusterID,
			},
		},
		Data: map[string][]byte{
			PrivateKeyDataKey: keyPEM,
			CSRDataKey:        csrPEM,
		},
	}

	unstructuredSecret := &unstructured.Unstructured{}
	err = i.syncerConfig.Scheme.Convert(secret, unstructuredSecret, nil)
	if err != nil {
		return fmt.Errorf("failed to convert Secret to unstructured: %w", err)
	}

	_, err = secretClient.Create(context.TODO(), unstructuredSecret, metav1.CreateOptions{})
	return err
}

func (i *libreswan) DeleteCertificateSecret(ctx context.Context) error {
	gvr := corev1.SchemeGroupVersion.WithResource("secrets")

	err := i.syncerConfig.LocalClient.Resource(gvr).
		Namespace(LocalNamespace).
		Delete(ctx, CertSecretName, metav1.DeleteOptions{})

	return err
}
func generateKeyAndCSR(clusterID string, sanIPs []string) ([]byte, []byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, RSABitSize)
	if err != nil {
		return nil, nil, err
	}

	ipAddresses := []net.IP{}
	for _, ip := range sanIPs {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, nil, fmt.Errorf("invalid IP address in SAN: %s", ip)
		}
		ipAddresses = append(ipAddresses, parsed)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("submariner-%s", clusterID),
			Organization: []string{"submariner.io"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		IPAddresses:        ipAddresses,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return keyPEM, csrPEM, nil
}

func SetupCertificateSecretSyncer(syncerConfig broker.SyncerConfig) (*broker.Syncer, error) {

	syncerConfig.ResourceConfigs = []broker.ResourceConfig{
		{

			LocalSourceNamespace: LocalNamespace,
			LocalResourceType:    &corev1.Secret{},
			TransformLocalToBroker: func(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
				secret := from.(*corev1.Secret)

				// Filter: only Secrets for this cluster
				if secret.Labels[CertLabelKey] != syncerConfig.LocalClusterID {
					return nil, false
				}

				// Copy and strip private key
				newSecret := secret.DeepCopy()
				delete(newSecret.Data, PrivateKeyDataKey)

				return newSecret, true
			},
			BrokerResourceType: &corev1.Secret{},
			TransformBrokerToLocal: func(from runtime.Object, numRequeues int, op syncer.Operation) (runtime.Object, bool) {
				secret := from.(*corev1.Secret)

				if secret.Labels[CertLabelKey] != syncerConfig.LocalClusterID {
					return nil, false
				}

				if _, ok := secret.Annotations["submariner.io/csr-request-signed"]; !ok {
					return nil, false
				}

				if _, ok := secret.Data[SignedCertDataKey]; !ok {
					return nil, false
				}

				// Fetch existing secret using dynamic client
				gvr := corev1.SchemeGroupVersion.WithResource("secrets")

				existingUnstructured, err := syncerConfig.LocalClient.Resource(gvr).
					Namespace(syncerConfig.LocalNamespace).
					Get(context.TODO(), secret.Name, metav1.GetOptions{})
				if err == nil {
					existingSecret := &corev1.Secret{}
					if err := syncerConfig.Scheme.Convert(existingUnstructured, existingSecret, nil); err == nil {
						if key, ok := existingSecret.Data[PrivateKeyDataKey]; ok {
							if secret.Data == nil {
								secret.Data = map[string][]byte{}
							}
							secret.Data[PrivateKeyDataKey] = key
						}
					}
				}

				return secret, true
			},
		},
	}
	return broker.NewSyncer(syncerConfig)
}
