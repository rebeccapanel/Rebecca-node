package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
)

type proxyDiagnosticConfig struct {
	Outbounds []map[string]any `json:"outbounds"`
}

func (s *Server) setDiagnosticConfig(raw string) {
	// Decode only outbounds: copying every user's inbound credentials on every
	// health poll would make large node configurations needlessly expensive.
	var config proxyDiagnosticConfig
	if json.Unmarshal([]byte(raw), &config) != nil {
		return
	}
	s.mu.Lock()
	s.diagnosticConfig = config
	s.runtimeStopped = false
	s.mu.Unlock()
	s.diagnosticsMu.Lock()
	s.diagnosticsAt = time.Time{}
	s.diagnosticsMu.Unlock()
}

func (s *Server) recordNativeIssue(protocol, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nativeErrors == nil {
		s.nativeErrors = map[string]string{}
	}
	if message == "" {
		delete(s.nativeErrors, protocol)
	} else {
		s.nativeErrors[protocol] = message
	}
}

// serviceDiagnostics is bounded and read-only. It never installs packages,
// restarts services, changes ports, logs in, or tests traffic through an exit.
func (s *Server) serviceDiagnostics() []*nodev1.ProtocolStatus {
	s.diagnosticsMu.Lock()
	defer s.diagnosticsMu.Unlock()
	if !s.diagnosticsAt.IsZero() && time.Since(s.diagnosticsAt) < 15*time.Second {
		return s.diagnostics
	}
	s.mu.Lock()
	config := s.diagnosticConfig
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result := []*nodev1.ProtocolStatus{}
	for _, outbound := range config.Outbounds {
		kind := managedProxyKind(outbound)
		if kind == "" {
			tag := strings.ToLower(managedString(outbound["tag"]))
			if managedString(outbound["rebecca_proxy"]) == "psiphon" || tag == "psiphon" || strings.HasPrefix(tag, "psiphon-") {
				kind = "psiphon"
			}
		}
		if kind == "" {
			continue
		}
		state := &nodev1.ProtocolStatus{Protocol: kind + "/" + managedString(outbound["tag"]), State: "running", Inbounds: 1, Detail: "Native service and local SOCKS handshake are healthy; exit connectivity is not tested by this lightweight check"}
		if ctx.Err() != nil {
			state.State, state.Detail = "warning", "Service health check exceeded its time budget; status is unknown, not confirmed healthy"
		} else if err := managedServiceError(ctx, outbound, kind); err != nil {
			state.State, state.Detail = "error", err.Error()
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				state.State = "warning"
			}
		}
		result = append(result, state)
	}
	if s.settings.SSLCertFile != "" || s.settings.SSLKeyFile != "" {
		if err := nodeCertificateError(s.settings.SSLCertFile, s.settings.SSLKeyFile, time.Now()); err != nil {
			result = append(result, &nodev1.ProtocolStatus{Protocol: "certificate", State: "error", Detail: err.Error()})
		}
	}
	result = append(result, diskDiagnostics(s.settings.RebeccaDataDir)...)
	s.diagnostics, s.diagnosticsAt = result, time.Now()
	return result
}

func managedServiceError(ctx context.Context, outbound map[string]any, kind string) error {
	port, username, password, ok := localSocksDetails(outbound)
	if !ok {
		return fmt.Errorf("%s outbound %q uses protocol %q or an invalid server; its native service requires loopback SOCKS on port 1024–65535", kind, managedString(outbound["tag"]), managedString(outbound["protocol"]))
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("native %s service diagnostics are supported on Linux only", kind)
	}
	unit := ""
	switch kind {
	case "tor":
		if !commandExists("tor") {
			return fmt.Errorf("Tor is configured but the tor executable is not installed")
		}
		unit = fmt.Sprintf("rebecca-tor-%d.service", port)
		if !fileExists(filepath.Join("/etc/systemd/system", unit)) && managedProxyOwnsPort(managedProxy{kind: "tor", port: port}) {
			unit = "tor.service"
		}
	case "windscribe":
		if !commandExists("windscribe-cli") {
			return fmt.Errorf("Windscribe is configured but windscribe-cli is not installed")
		}
		marker, err := os.ReadFile(windscribeAccountMarker)
		if err != nil || strings.TrimSpace(string(marker)) == "" {
			return fmt.Errorf("Windscribe login/account information is missing; log in and configure this outbound on the node")
		}
		if username == "" || password == "" {
			return fmt.Errorf("Windscribe SOCKS proxy username/password are missing")
		}
		if !fileExists(windscribeConfigPath) {
			return fmt.Errorf("Windscribe proxy configuration file is missing")
		}
		if err := diagnosticUnitError(ctx, windscribeServiceName); err != nil {
			return err
		}
		statusCtx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
		status, statusErr := runWindscribeCLI(statusCtx, "status")
		statusTimeout := statusCtx.Err()
		cancel()
		if statusTimeout != nil {
			return fmt.Errorf("Windscribe login status query timed out; health is unknown: %w", statusTimeout)
		}
		if statusErr != nil {
			return statusErr
		}
		if !strings.Contains(strings.ToLower(status), "login state: logged in") {
			return fmt.Errorf("Windscribe CLI is installed but the account is not logged in; log in again on this node")
		}
		unit = windscribeRelayUnitName
	case "psiphon":
		if !fileExists(psiphonBinaryPath) {
			return fmt.Errorf("Psiphon is configured but its tunnel-core executable is missing")
		}
		units, err := filepath.Glob(fmt.Sprintf("/etc/systemd/system/rebecca-psiphon-*-%d.service", port))
		if err != nil || len(units) != 1 {
			return fmt.Errorf("Psiphon service for SOCKS port %d is missing or ambiguous", port)
		}
		unit = filepath.Base(units[0])
		if !fileExists(filepath.Join(psiphonConfigDir, strings.TrimSuffix(unit, ".service")+".json")) {
			return fmt.Errorf("Psiphon service configuration is missing for port %d", port)
		}
	}
	if commandExists("systemctl") {
		if err := diagnosticUnitError(ctx, unit); err != nil {
			return err
		}
	}
	dialer := net.Dialer{Timeout: 200 * time.Millisecond}
	settings, _ := outbound["settings"].(map[string]any)
	server := mapList(settings["servers"])[0]
	address := strings.Trim(strings.TrimSpace(managedString(server["address"])), "[]")
	if strings.EqualFold(address, "localhost") {
		address = "127.0.0.1"
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
	if err != nil {
		return fmt.Errorf("%s service is not listening on local SOCKS port %d: %w", kind, port, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(200 * time.Millisecond)
	if parentDeadline, ok := ctx.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	_ = conn.SetDeadline(deadline)
	if err := authenticateSOCKS5(conn, username, password); err != nil {
		return fmt.Errorf("%s local SOCKS service or credentials are invalid: %w", kind, err)
	}
	return nil
}

// authenticateSOCKS5 validates only the local protocol/authentication. No
// CONNECT command, DNS lookup or traffic through an exit is performed.
func authenticateSOCKS5(conn net.Conn, username, password string) error {
	method := byte(0)
	if username != "" || password != "" {
		if len(username) == 0 || len(password) == 0 || len(username) > 255 || len(password) > 255 {
			return fmt.Errorf("SOCKS username/password are missing or too long")
		}
		method = 2
	}
	if _, err := conn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 5 || response[1] != method {
		return fmt.Errorf("listener is not a compatible SOCKS5 service or rejected its authentication method")
	}
	if method == 0 {
		return nil
	}
	auth := append([]byte{1, byte(len(username))}, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return err
	}
	if response[0] != 1 || response[1] != 0 {
		return fmt.Errorf("SOCKS5 proxy rejected the saved credentials")
	}
	return nil
}

func diagnosticUnitError(ctx context.Context, unit string) error {
	checkCtx, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	defer cancel()
	output, err := exec.CommandContext(checkCtx, "systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,Result").CombinedOutput()
	if checkCtx.Err() != nil {
		return fmt.Errorf("service %s status query timed out; health is unknown: %w", unit, checkCtx.Err())
	}
	return unitStatusError(unit, string(output), err)
}

func unitStatusError(unit, output string, commandErr error) error {
	fields := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	if fields["LoadState"] == "not-found" {
		return fmt.Errorf("service %s was not found; its native setup is missing", unit)
	}
	if commandErr != nil {
		return fmt.Errorf("cannot inspect service %s: %w", unit, commandErr)
	}
	if fields["ActiveState"] != "active" {
		return fmt.Errorf("service %s is %s/%s (result: %s); check its configuration and service logs", unit, fields["ActiveState"], fields["SubState"], fields["Result"])
	}
	return nil
}

func nodeCertificateError(certFile, keyFile string, now time.Time) error {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("node control certificate/key is missing or invalid: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse node control certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("node control certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("node control certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}
