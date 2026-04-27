package node

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeGeoFilenameOnlyAllowsExpectedAssets(t *testing.T) {
	if got := safeGeoFilename("geoip.dat"); got != "geoip.dat" {
		t.Fatalf("expected geoip.dat, got %q", got)
	}
	if got := safeGeoFilename("nested/geosite.dat"); got != "geosite.dat" {
		t.Fatalf("expected geosite.dat, got %q", got)
	}
	if got := safeGeoFilename("../../authorized_keys"); got != "" {
		t.Fatalf("expected unsafe filename to be rejected, got %q", got)
	}
}

func TestInstallZipToRejectsZipSlip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if w, err := zw.Create("../escape.txt"); err != nil {
		t.Fatal(err)
	} else if _, err := w.Write([]byte("owned")); err != nil {
		t.Fatal(err)
	}
	if w, err := zw.Create("xray"); err != nil {
		t.Fatal(err)
	} else if _, err := w.Write([]byte("binary")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "xray-core")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := installZipTo(buf.Bytes(), target); err == nil {
		t.Fatal("expected zip slip archive to be rejected")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("escape file should not exist, stat error: %v", err)
	}
}
