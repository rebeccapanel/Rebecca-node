package node

import (
	"path/filepath"
	"testing"
)

func TestIssueIPCertificateRejectsNonIPIdentifier(t *testing.T) {
	server := &Server{}
	if _, _, err := server.issueIPCertificate("example.com", ""); err == nil {
		t.Fatal("expected a non-IP identifier to be rejected")
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
