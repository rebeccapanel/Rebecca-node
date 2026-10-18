//go:build linux

package xray

import "testing"

func TestStaleProcessExecutableStripsDeletedSuffix(t *testing.T) {
	if got := staleProcessExecutable("/var/lib/rebecca-node/xray-core/xray (deleted)"); got != "/var/lib/rebecca-node/xray-core/xray" {
		t.Fatalf("replaced binary must match its managed path, got %q", got)
	}
	if got := staleProcessExecutable("/usr/local/x-ui/bin/xray-linux-amd64"); got != "/usr/local/x-ui/bin/xray-linux-amd64" {
		t.Fatalf("live executable path must not change, got %q", got)
	}
}
