package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveXrayExecutablePathPrefersPersistentBinary(t *testing.T) {
	dataDir := t.TempDir()
	persistentBin := filepath.Join(dataDir, "xray-core", executableName("xray"))
	if err := ensureTestFile(persistentBin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_EXECUTABLE_PATH", "/opt/custom/xray")

	if got := resolveXrayExecutablePath(dataDir); got != persistentBin {
		t.Fatalf("expected persistent binary %q, got %q", persistentBin, got)
	}
}

func TestResolveXrayExecutablePathFallsBackToConfiguredEnv(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XRAY_EXECUTABLE_PATH", "/opt/custom/xray")

	if got := resolveXrayExecutablePath(dataDir); got != "/opt/custom/xray" {
		t.Fatalf("expected configured binary, got %q", got)
	}
}

func TestResolveXrayAssetsPathPrefersPersistentGeoFiles(t *testing.T) {
	dataDir := t.TempDir()
	persistentDir := filepath.Join(dataDir, "xray-core")
	if err := ensureTestFile(filepath.Join(persistentDir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_ASSETS_PATH", "/usr/local/share/xray")

	if got := resolveXrayAssetsPath(dataDir); got != persistentDir {
		t.Fatalf("expected persistent assets dir %q, got %q", persistentDir, got)
	}
}

func TestResolveXrayAssetsPathFallsBackToConfiguredEnv(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XRAY_ASSETS_PATH", "/opt/custom/assets")

	if got := resolveXrayAssetsPath(dataDir); got != "/opt/custom/assets" {
		t.Fatalf("expected configured assets path, got %q", got)
	}
}

func ensureTestFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("test"), 0o644)
}
