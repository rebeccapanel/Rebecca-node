package node

import (
	"os"
	"strings"
	"testing"
)

func TestOVStopDropsOnlyThatInboundSessions(t *testing.T) {
	baseDir := t.TempDir()
	m := &ovManager{baseDir: baseDir}
	path := vpnSessionsPath(baseDir)
	records := "1\tov\tvpn-a\tsess-1\t10.66.0.2\t1.1.1.1\t1700000000\t1194\n" +
		"2\tov\tvpn-b\tsess-2\t10.66.1.2\t2.2.2.2\t1700000000\t1194\n" +
		"3\tl2tp\tvpn-a\tsess-3\t10.67.0.2\t3.3.3.3\t1700000000\t1701\n"
	if err := os.WriteFile(path, []byte(records), 0o600); err != nil {
		t.Fatal(err)
	}

	m.dropInboundSessions("vpn-a")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if strings.Contains(got, "sess-1") {
		t.Fatalf("stale OV session of the stopped inbound was kept: %q", got)
	}
	if !strings.Contains(got, "sess-2") || !strings.Contains(got, "sess-3") {
		t.Fatalf("sessions of other inbounds or protocols were dropped: %q", got)
	}
}
