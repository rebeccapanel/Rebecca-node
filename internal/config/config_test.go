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

func TestResolveXrayAssetsPathPrefersUpdatedAssetsOverCoreCache(t *testing.T) {
	dataDir := t.TempDir()
	coreDir := filepath.Join(dataDir, "xray-core")
	assetsDir := filepath.Join(dataDir, "assets")
	if err := ensureTestFile(filepath.Join(coreDir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
	if err := ensureTestFile(filepath.Join(assetsDir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}

	if got := resolveXrayAssetsPath(dataDir); got != assetsDir {
		t.Fatalf("expected updated assets dir %q, got %q", assetsDir, got)
	}
}

func TestResolveXrayAssetsPathKeepsDownloadedGeoAssetsAfterRestart(t *testing.T) {
	dataDir := t.TempDir()
	persistentDir := filepath.Join(dataDir, "xray-core")
	customDir := filepath.Join(dataDir, "assets")
	if err := ensureTestFile(filepath.Join(persistentDir, "geoip.dat")); err != nil {
		t.Fatal(err)
	}
	if err := ensureTestFile(filepath.Join(customDir, "geosite.dat")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_ASSETS_PATH", persistentDir)

	if got := resolveXrayAssetsPath(dataDir); got != customDir {
		t.Fatalf("expected downloaded assets dir %q after restart, got %q", customDir, got)
	}
}

func TestResolveXrayAssetsPathFallsBackToConfiguredEnv(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("XRAY_ASSETS_PATH", "/opt/custom/assets")

	if got := resolveXrayAssetsPath(dataDir); got != "/opt/custom/assets" {
		t.Fatalf("expected configured assets path, got %q", got)
	}
}

func TestLoadDefaultsInstallModeToDocker(t *testing.T) {
	_ = os.Unsetenv("REBECCA_NODE_INSTALL_MODE")
	settings := Load()
	if settings.InstallMode != "docker" {
		t.Fatalf("expected docker install mode by default, got %q", settings.InstallMode)
	}
}

func TestLoadUsesServicePortForGRPCAndKeepsLegacyXrayDefault(t *testing.T) {
	t.Setenv("SERVICE_HOST", "127.0.0.2")
	t.Setenv("SERVICE_PORT", "63050")
	t.Setenv("XRAY_API_PORT", "63051")
	_ = os.Unsetenv("XRAY_API_HOST")

	settings := Load()
	if settings.ServiceHost != "127.0.0.2" || settings.ServicePort != 63050 {
		t.Fatalf("unexpected gRPC listener %s:%d", settings.ServiceHost, settings.ServicePort)
	}
	if settings.XrayAPIHost != "0.0.0.0" || settings.XrayAPIPort != 63051 {
		t.Fatalf("unexpected Xray API listener %s:%d", settings.XrayAPIHost, settings.XrayAPIPort)
	}
}

func ensureTestFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("test"), 0o644)
}
