package node

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOVServerConfigUsesTCPServerProto(t *testing.T) {
	config := serverConfig(ovRuntimeInbound{
		Tag:       "ov-tcp",
		Port:      1194,
		Transport: "tcp",
		Settings:  map[string]any{"transport": "tcp"},
	}, "/tmp/ov", "/tmp/ov/ccd")

	if !strings.Contains(config, "proto tcp-server\n") {
		t.Fatalf("server config does not use tcp-server:\n%s", config)
	}
	if strings.Contains(config, "fast-io\n") {
		t.Fatalf("tcp server config should not enable fast-io:\n%s", config)
	}
}

func TestOVServerConfigEnablesFastIOForUDP(t *testing.T) {
	config := serverConfig(ovRuntimeInbound{
		Tag:       "ov-udp",
		Port:      1194,
		Transport: "udp",
		Settings:  map[string]any{"transport": "udp"},
	}, "/tmp/ov", "/tmp/ov/ccd")

	if !strings.Contains(config, "proto udp\nfast-io\n") {
		t.Fatalf("udp server config should enable fast-io:\n%s", config)
	}
}

func TestOVServerConfigRequiresDCODataCiphers(t *testing.T) {
	config := serverConfig(ovRuntimeInbound{
		Tag:       "ov-dco",
		Port:      1194,
		Transport: "udp",
		Settings: map[string]any{
			"transport":   "udp",
			"require_dco": true,
			"cipher":      "AES-256-GCM",
		},
	}, "/tmp/ov", "/tmp/ov/ccd")

	for _, want := range []string{
		"proto udp\n",
		"fast-io\n",
		"cipher AES-256-GCM\n",
		"data-ciphers " + ovDCODataCiphers + "\n",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("server config missing %q:\n%s", want, config)
		}
	}
	if strings.Contains(config, "disable-dco\n") {
		t.Fatalf("DCO-required config should not disable DCO:\n%s", config)
	}
}

func TestOVServerConfigOmitsDCOByDefault(t *testing.T) {
	config := serverConfig(ovRuntimeInbound{
		Tag:       "ov-no-dco",
		Port:      1194,
		Transport: "udp",
		Settings:  map[string]any{"transport": "udp"},
	}, "/tmp/ov", "/tmp/ov/ccd")

	if strings.Contains(config, "disable-dco\n") {
		t.Fatalf("server config should remain compatible with OpenVPN 2.5:\n%s", config)
	}
	if strings.Contains(config, "data-ciphers "+ovDCODataCiphers+"\n") {
		t.Fatalf("DCO-disabled config should not force DCO data ciphers:\n%s", config)
	}
}

func TestOVServerConfigAllowsSharedClientCertificate(t *testing.T) {
	config := serverConfig(ovRuntimeInbound{
		Tag:       "ov",
		Port:      1194,
		Transport: "udp",
		Settings:  map[string]any{"transport": "udp"},
	}, "/tmp/ov", "/tmp/ov/ccd")

	if !strings.Contains(config, "duplicate-cn\n") {
		t.Fatalf("server config should allow shared client certs:\n%s", config)
	}
	if !strings.Contains(config, "status ") || !strings.Contains(config, "status.log 5\n") {
		t.Fatalf("server config should refresh status quickly:\n%s", config)
	}
	if !strings.Contains(config, "status-version 2\n") {
		t.Fatalf("server config should emit machine-readable status:\n%s", config)
	}
}

func TestOVDCORejectsLegacyCipher(t *testing.T) {
	err := validateOVDCOSettings(ovRuntimeInbound{
		Tag:      "ov",
		Settings: map[string]any{"require_dco": true, "cipher": "AES-256-CBC"},
	})
	if err == nil || !strings.Contains(err.Error(), "not DCO-compatible") {
		t.Fatalf("expected DCO cipher error, got %v", err)
	}
}

func TestOVDCOInactiveReasonDetectsFallback(t *testing.T) {
	reason := ovDCOInactiveReason("Kernel support for ovpn-dco missing, disabling data channel offload.")
	if reason == "" {
		t.Fatal("expected inactive DCO reason")
	}
}

func TestOVTProxyMasqueradesICMP(t *testing.T) {
	script := nftScript(ovRuntimeInbound{
		Tag:        "ov",
		TunnelPort: 41940,
		Settings: map[string]any{
			"tproxy_enabled": true,
			"ipv4_pool_cidr": "10.66.0.0/16",
		},
	}, "rbov12345678")

	for _, want := range []string{
		"meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:41940",
		"type nat hook postrouting priority srcnat",
		"ip saddr 10.66.0.0/16 oifname != \"rbov12345678\" meta l4proto icmp masquerade",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script missing %q:\n%s", want, script)
		}
	}
}

func TestOVAuthCountsPendingUsage(t *testing.T) {
	script := authScript("/tmp/users.tsv", "/tmp/usage.tsv", "/tmp/callback.env", "/tmp/sessions.tsv", "ov")
	for _, want := range []string{
		"USAGE=\"/tmp/usage.tsv\"",
		"FILENAME == ARGV[1]",
		"pending[id] += $2",
		"used = $5 + pending[$1]",
		"assigned_ip=$(printf '%s' \"$info\"",
		"remote_ip=${trusted_ip:-${untrusted_ip:-unknown}}",
		"MANAGEMENT=\"$(dirname \"$USERS\")/management.sock\"",
		"old_endpoint=$(awk",
		"printf 'kill %s\\nquit\\n' \"$old_endpoint\"",
		"--unix-socket \"$MANAGEMENT\" -T - telnet://localhost",
		"vpn_admit \"$uid\" \"ov\" \"ov\" \"$session\" \"$assigned_ip\" \"$remote_ip\" \"$device_limit\" \"$remote_port\"",
		"ov_reconnect = proto == \"ov\"",
		"\"$USAGE\" \"$USERS\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("auth script missing %q:\n%s", want, script)
		}
	}
}

func TestOVCollectUsageReadsStatusDeltas(t *testing.T) {
	dir := t.TempDir()
	inboundDir := filepath.Join(dir, "openvpn", "edge")
	if err := os.MkdirAll(inboundDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvpn", "runtime.json"), []byte(`{"inbounds":[{"tag":"edge"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inboundDir, "users.tsv"), []byte("42\talice\tpass\t10.66.0.2\t100\t1000\tactive\t\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := "CLIENT_LIST,alice,198.51.100.10:5555,10.66.0.2,200,300,now,0,UNDEF,1,0\n"
	if err := os.WriteFile(filepath.Join(inboundDir, "status.log"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := newOVManager(dir, "binary")

	stats := manager.CollectUsage()
	if len(stats) != 1 || stats[0].UID != "openvpn:42" || stats[0].InboundTag != "edge" || stats[0].Value != 500 {
		t.Fatalf("unexpected first stats: %#v", stats)
	}
	stats = manager.CollectUsage()
	if len(stats) != 0 {
		t.Fatalf("second collect should have no duplicate delta: %#v", stats)
	}
}

func TestOVCollectUsageReadsStatusVersion2Deltas(t *testing.T) {
	dir := t.TempDir()
	inboundDir := filepath.Join(dir, "openvpn", "edge")
	if err := os.MkdirAll(inboundDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(inboundDir, "users.tsv"), []byte("42\talice\tpass\t10.66.0.2\t100\t1000\tactive\t\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status := "CLIENT_LIST,alice,198.51.100.10:5555,10.66.0.2,,102024,4985,2026-07-13 13:09:59,1783948199,alice,4,0,AES-256-GCM\n"
	if err := os.WriteFile(filepath.Join(inboundDir, "status.log"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := newOVManager(dir, "binary")

	stats := manager.CollectUsage()
	if len(stats) != 1 || stats[0].UID != "openvpn:42" || stats[0].Value != 107009 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestOVDisconnectSubtractsAccountedUsage(t *testing.T) {
	script := disconnectScript("/tmp/users.tsv", "/tmp/usage.tsv", "/tmp/accounting.tsv", "/tmp/callback.env", "/tmp/sessions.tsv", "edge")
	for _, want := range []string{
		"previous=$(awk",
		"delta=$((total - previous))",
		"printf 'openvpn:%s\\t%s\\t%s\\n' \"$uid\" \"$delta\" \"$INBOUND_TAG\"",
		"remote_ip=${trusted_ip:-${untrusted_ip:-unknown}}",
		"vpn_release \"$uid\" \"ov\" \"edge\" \"$session\" \"$assigned_ip\"",
		"awk -F '\\t' -v OFS='\\t' -v sid=\"$session\" -v uid=\"$uid\" -v total=\"$total\" '$1 != sid { print } END { print sid, uid, total, 0, 1 }'",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("disconnect script missing %q:\n%s", want, script)
		}
	}
}

func TestOVLiveUsageAndDisconnectCountEachByteOnce(t *testing.T) {
	for _, tool := range []string{"sh", "awk", "flock"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is required: %v", tool, err)
		}
	}
	dir := t.TempDir()
	inboundDir := filepath.Join(dir, "openvpn", "edge")
	if err := os.MkdirAll(inboundDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvpn", "runtime.json"), []byte(`{"inbounds":[{"tag":"edge"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	usersPath := filepath.Join(inboundDir, "users.tsv")
	if err := os.WriteFile(usersPath, []byte("42\talice\tpass\t10.66.0.2\t100\t1000\tactive\t\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	statusPath := filepath.Join(inboundDir, "status.log")
	writeStatus := func(rx, tx int64) {
		t.Helper()
		status := fmt.Sprintf("CLIENT_LIST,alice,198.51.100.10:5555,10.66.0.2,,%d,%d,2026-07-13 13:09:59,1783948199,alice,4,0,AES-256-GCM\n", rx, tx)
		if err := os.WriteFile(statusPath, []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manager := newOVManager(dir, "binary")
	collect := func() int64 {
		var sum int64
		for _, stat := range manager.CollectUsage() {
			sum += stat.Value
		}
		return sum
	}
	disconnect := func(rx, tx int64) {
		t.Helper()
		script := filepath.Join(dir, "client-disconnect.sh")
		body := disconnectScript(usersPath, filepath.Join(manager.baseDir, "usage.tsv"), filepath.Join(manager.baseDir, "accounting.tsv"), filepath.Join(dir, "callback.env"), vpnSessionsPath(manager.baseDir), "edge")
		if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", script)
		cmd.Env = append(os.Environ(), "username=alice", fmt.Sprintf("bytes_received=%d", rx), fmt.Sprintf("bytes_sent=%d", tx), "trusted_ip=198.51.100.10", "trusted_port=5555")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("disconnect script failed: %v\n%s", err, out)
		}
	}

	var counted int64
	writeStatus(200, 300)
	counted += collect()
	writeStatus(400, 300)
	counted += collect()
	disconnect(450, 300)
	counted += collect()
	if err := os.WriteFile(statusPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	counted += collect()
	if counted != 750 {
		t.Fatalf("counted %d bytes, want 750 (450 received + 300 sent, each counted once)", counted)
	}
}
