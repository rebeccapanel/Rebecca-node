package node

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

const (
	letsEncryptProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	ipCertificateProfile           = "shortlived"
)

type acmeAccount struct {
	email        string
	key          *ecdsa.PrivateKey
	registration *registration.Resource
}

func (a *acmeAccount) GetEmail() string {
	return a.email
}

func (a *acmeAccount) GetRegistration() *registration.Resource {
	return a.registration
}

func (a *acmeAccount) GetPrivateKey() crypto.PrivateKey {
	return a.key
}

func (s *Server) issueCertificate(identifier, email string) ([]byte, []byte, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, nil, errors.New("certificate identifier is required")
	}
	if !s.issueMu.TryLock() {
		return nil, nil, errors.New("another certificate issue is already running")
	}
	defer s.issueMu.Unlock()

	key, err := loadOrCreateACMEAccountKey(filepath.Join(s.settings.RebeccaDataDir, "acme", "account.key"))
	if err != nil {
		return nil, nil, err
	}
	account := &acmeAccount{email: strings.TrimSpace(email), key: key}
	config := lego.NewConfig(account)
	config.CADirURL = letsEncryptProductionDirectory
	config.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, nil, fmt.Errorf("create ACME client: %w", err)
	}
	if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80")); err != nil {
		return nil, nil, fmt.Errorf("configure HTTP-01 validation: %w", err)
	}
	registered, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("register ACME account: %w", err)
	}
	account.registration = registered
	resource, err := client.Certificate.Obtain(certificate.ObtainRequest{
		Domains: []string{identifier},
		Profile: certificateProfile(identifier),
		Bundle:  true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("obtain certificate for %s with HTTP-01 on port 80: %w", identifier, err)
	}
	return resource.Certificate, resource.PrivateKey, nil
}

func certificateProfile(identifier string) string {
	if net.ParseIP(identifier) != nil {
		return ipCertificateProfile
	}
	return ""
}

func loadOrCreateACMEAccountKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("parse ACME account key %s: not PEM", path)
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read ACME account key: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ACME account key: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode ACME account key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ACME account directory: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("write ACME account key: %w", err)
	}
	return key, nil
}
