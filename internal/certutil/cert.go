package certutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func EnsureServerCertificate(certFile, keyFile string) error {
	if fileExists(certFile) && fileExists(keyFile) {
		return nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "rebecca-node",
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0o600)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
