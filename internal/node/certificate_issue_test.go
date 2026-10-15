package node

import (
	"path/filepath"
	"testing"
)

func TestCertificateProfileIsShortLivedOnlyForIPAddresses(t *testing.T) {
	if got := certificateProfile("203.0.113.10"); got != ipCertificateProfile {
		t.Fatalf("IP profile = %q, want %q", got, ipCertificateProfile)
	}
	if got := certificateProfile("api.example.com"); got != "" {
		t.Fatalf("domain profile = %q, want the default profile", got)
	}
}

func TestIssueCertificateRejectsEmptyIdentifier(t *testing.T) {
	server := &Server{}
	if _, _, err := server.issueCertificate(" ", ""); err == nil {
		t.Fatal("expected an empty identifier to be rejected")
	}
}

func TestLoadOrCreateACMEAccountKeyIsStable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acme", "account.key")
	first, err := loadOrCreateACMEAccountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateACMEAccountKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.D.Cmp(second.D) != 0 {
		t.Fatal("ACME account key changed between loads")
	}
}
