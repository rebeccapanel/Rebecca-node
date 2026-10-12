package node

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func TestServiceDiagnosticsReportLegacyConfigAndClearAfterConfigRemoval(t *testing.T) {
	s := &Server{settings: appconfig.Settings{RebeccaDataDir: t.TempDir()}, core: &xray.Core{}}
	s.setDiagnosticConfig(`{"outbounds":[{"tag":"windscribe-de","protocol":"wireguard"}]}`)
	issues := s.serviceDiagnostics()
	if len(issues) != 1 || issues[0].Protocol != "windscribe/windscribe-de" || issues[0].State != "error" || !strings.Contains(issues[0].Detail, "wireguard") {
		t.Fatalf("invalid outbound was hidden or changed: %v", issues)
	}
	s.recordNativeIssue("wireguard", "failed to apply peer")
	statuses := s.protocolStatuses()
	found := false
	for _, status := range statuses {
		found = found || status.Protocol == "wireguard/configuration" && status.Detail == "failed to apply peer"
	}
	if !found {
		t.Fatal("native failure was hidden by core status")
	}
	s.recordNativeIssue("wireguard", "")
	if len(s.nativeErrors) != 0 {
		t.Fatal("successful apply retained its previous failure")
	}
	s.clearConfigCache()
	if !s.runtimeStopped || len(s.serviceDiagnostics()) != 0 {
		t.Fatal("operator stop retained stale service diagnostics")
	}
	for _, status := range s.protocolStatuses() {
		if status.State == "error" {
			t.Fatalf("intentional stop reported as broken: %v", status)
		}
	}
}

func TestCachedConfigStartupFailureIsAvailableInHealth(t *testing.T) {
	s := &Server{settings: appconfig.Settings{RebeccaDataDir: t.TempDir()}, core: &xray.Core{}}
	if err := os.WriteFile(s.configCachePath(), []byte("{broken-json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.startCachedConfig(false); err == nil {
		t.Fatal("invalid cache was silently ignored")
	}
	state := s.protocolStatuses()[0]
	if state.State != "error" || !strings.Contains(state.Detail, "cached runtime configuration") {
		t.Fatalf("startup failure not exposed: %v", state)
	}
}

func TestServiceUnitDiagnosticsAreActionable(t *testing.T) {
	for _, tc := range []struct {
		output, want string
		commandErr   error
	}{
		{"LoadState=loaded\nActiveState=active\nSubState=running\nResult=success", "", nil},
		{"LoadState=not-found\nActiveState=inactive", "not found", errors.New("exit 1")},
		{"LoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code", "exit-code", nil},
		{"", "cannot inspect", errors.New("permission denied")},
	} {
		err := unitStatusError("rebecca-tor-9050.service", tc.output, tc.commandErr)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "rebecca-tor-9050.service")) {
			t.Fatalf("wanted %q: %v", tc.want, err)
		}
	}
}

func TestSOCKSHealthChecksAuthenticationWithoutCONNECTOrCredentialLeak(t *testing.T) {
	for _, tc := range []struct {
		name, user, pass string
		response         []byte
		want             string
	}{
		{"no auth", "", "", []byte{5, 0}, ""},
		{"authenticated", "secret-user", "secret-password", []byte{5, 2}, ""},
		{"bad listener", "", "", []byte{'H', 'T'}, "not a compatible SOCKS5"},
		{"wrong method", "secret-user", "secret-password", []byte{5, 0}, "rejected"},
		{"rejected credentials", "secret-user", "secret-password", []byte{5, 2, 1}, "rejected the saved credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			_ = server.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				var greeting [3]byte
				if _, err := io.ReadFull(server, greeting[:]); err != nil {
					done <- err
					return
				}
				if _, err := server.Write(tc.response[:2]); err != nil {
					done <- err
					return
				}
				if tc.response[1] == 2 && greeting[2] == 2 {
					var header [2]byte
					if _, err := io.ReadFull(server, header[:]); err != nil {
						done <- err
						return
					}
					username := make([]byte, int(header[1])+1)
					if _, err := io.ReadFull(server, username); err != nil {
						done <- err
						return
					}
					password := make([]byte, int(username[len(username)-1]))
					if _, err := io.ReadFull(server, password); err != nil {
						done <- err
						return
					}
					status := byte(0)
					if len(tc.response) == 3 {
						status = tc.response[2]
					}
					if _, err := server.Write([]byte{1, status}); err != nil {
						done <- err
						return
					}
				}
				// A health query must not send a CONNECT request afterwards.
				_ = server.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
				var extra [1]byte
				_, err := server.Read(extra[:])
				if err == nil {
					done <- errors.New("health query sent traffic beyond authentication")
					return
				}
				done <- nil
			}()
			err := authenticateSOCKS5(client, tc.user, tc.pass)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("wanted %q: %v", tc.want, err)
			}
			if err != nil && (strings.Contains(err.Error(), "secret-user") || strings.Contains(err.Error(), "secret-password")) {
				t.Fatal("diagnostic leaked credentials")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeCertificateDiagnosticsDetectInvalidMissingAndExpiredMaterial(t *testing.T) {
	cert, key := writeSelfSignedCert(t, t.TempDir(), "node-health", []string{"node-health.test"})
	if err := nodeCertificateError(cert, key, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := nodeCertificateError(cert, key, time.Now().Add(2*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry not detected: %v", err)
	}
	if err := nodeCertificateError(cert, key+"-missing", time.Now()); err == nil || !strings.Contains(err.Error(), "missing or invalid") {
		t.Fatalf("missing key not detected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := diagnosticUnitError(ctx, "no-side-effects.service"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe not reported as unknown: %v", err)
	}
}
