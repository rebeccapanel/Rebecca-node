package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGRPCVPNRuntimeClearsMissingAuxiliaryState(t *testing.T) {
	ov, l2tp, pptp, wg, ikev2, anyConnect, haproxy, extra, err := grpcVPNRuntime(&nodev1.RuntimeConfigRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if ov == nil || l2tp == nil || pptp == nil || wg == nil || ikev2 == nil || anyConnect == nil || haproxy == nil || extra == nil {
		t.Fatal("missing runtime payload must clear every auxiliary runtime")
	}
	if len(ov.Inbounds)+len(l2tp.Inbounds)+len(pptp.Inbounds)+len(wg.Inbounds)+len(ikev2.Inbounds)+len(anyConnect.Inbounds) != 0 {
		t.Fatal("missing runtime payload must not restore cached auxiliary inbounds")
	}
}

func TestXrayConfigUsesTProxy(t *testing.T) {
	for _, test := range []struct {
		raw  string
		want bool
	}{
		{`{"inbounds":[{"streamSettings":{"sockopt":{"tproxy":"tproxy"}}}]}`, true},
		{`{"inbounds":[{"streamSettings":{"sockopt":{"tproxy":"off"}}}]}`, false},
	} {
		cfg, err := xray.NewConfig(test.raw, "127.0.0.1", appconfig.Settings{})
		if err != nil {
			t.Fatal(err)
		}
		if got := xrayConfigUsesTProxy(cfg); got != test.want {
			t.Fatalf("xrayConfigUsesTProxy() = %v, want %v", got, test.want)
		}
	}
}

func TestGRPCVPNRuntimeCarriesManagedHAProxyCertificate(t *testing.T) {
	certificateFile, privateKeyFile := writeSelfSignedCert(t, t.TempDir(), "managed.example.test", []string{"managed.example.test"})
	certificate, _ := os.ReadFile(certificateFile)
	privateKey, _ := os.ReadFile(privateKeyFile)
	payload, err := json.Marshal(map[string]any{"haproxy": haproxyRuntime{Enabled: true, Sites: []haproxyRuntimeSite{{
		TLSMode: "managed", CertificatePEM: string(certificate), PrivateKeyPEM: string(privateKey),
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, _, runtime, _, err := grpcVPNRuntime(&nodev1.RuntimeConfigRequest{OvRuntimeJson: string(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if runtime == nil || len(runtime.Sites) != 1 || runtime.Sites[0].CertificatePEM != string(certificate) || runtime.Sites[0].PrivateKeyPEM != string(privateKey) {
		t.Fatal("managed certificate files did not reach the node runtime intact")
	}
	if _, err := tls.X509KeyPair([]byte(runtime.Sites[0].CertificatePEM), []byte(runtime.Sites[0].PrivateKeyPEM)); err != nil {
		t.Fatalf("transferred managed certificate cannot be loaded: %v", err)
	}
}

func TestGRPCVPNRuntimeCarriesAdditionalProxyState(t *testing.T) {
	payload, err := json.Marshal(map[string]any{"extra": extraRuntime{Inbounds: []extraRuntimeInbound{{
		Tag: "ssh", Protocol: "ssh", Listen: "127.0.0.1", Port: 2222,
		Users: []extraRuntimeUser{{UserID: 7, Username: "alice", Password: "secret"}},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, _, _, runtime, err := grpcVPNRuntime(&nodev1.RuntimeConfigRequest{OvRuntimeJson: string(payload)})
	if err != nil || runtime == nil || len(runtime.Inbounds) != 1 || runtime.Inbounds[0].Users[0].Username != "alice" {
		t.Fatalf("additional proxy runtime was lost: runtime=%#v err=%v", runtime, err)
	}
}

func TestRestartRuntimeRestartsUnchangedConfig(t *testing.T) {
	tempDir := t.TempDir()
	runsPath := filepath.Join(tempDir, "runs")
	executable := filepath.Join(tempDir, "xray")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'Xray 1.0.0'; exit 0; fi\nif [ \"$2\" = -test ]; then cat >/dev/null; exit 0; fi\necho $$ >> \"$XRAY_TEST_RUNS\"\ncat >/dev/null\nwhile :; do sleep 1; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_TEST_RUNS", runsPath)
	settings := appconfig.Settings{
		RebeccaDataDir:     tempDir,
		XrayExecutablePath: executable,
		XrayAssetsPath:     tempDir,
		XrayLogDir:         tempDir,
		XrayAPIHost:        "127.0.0.1",
		XrayAPIPort:        10085,
	}
	core, err := xray.NewCore(executable, tempDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	configJSON := `{"inbounds":[],"outbounds":[]}`
	cfg, err := xray.NewConfig(configJSON, "127.0.0.1", settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(cfg); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
		if runs, _ := os.ReadFile(runsPath); len(strings.Fields(string(runs))) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("initial Xray process did not start")
		}
	}
	server := &Server{settings: settings, core: core, sessions: make(map[string]time.Time)}
	server.saveConfigCache(configJSON, "127.0.0.1", nil, nil, nil, nil)

	response, err := (&grpcAPI{server: server}).RestartRuntime(context.Background(), &nodev1.RuntimeConfigRequest{ConfigJson: configJSON})
	if err != nil {
		t.Fatal(err)
	}
	if !response.GetAccepted() || response.GetMessage() != "runtime restarted" {
		t.Fatalf("unexpected restart response: %#v", response)
	}
	runs, err := os.ReadFile(runsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Fields(string(runs))); got != 2 {
		t.Fatalf("unchanged config started Xray %d times, want 2", got)
	}
}

func TestGRPCServerAcceptsMutualTLSClient(t *testing.T) {
	tempDir := t.TempDir()
	serverCertFile, serverKeyFile := writeSelfSignedCert(t, tempDir, "server", []string{"rebecca-node.test"})

	settings := appconfig.Settings{
		AppName:           "rebecca-node",
		InstallMode:       "binary",
		NodeVersion:       "0.2.2",
		SSLCertFile:       serverCertFile,
		SSLKeyFile:        serverKeyFile,
		SSLClientCertFile: serverCertFile,
	}
	tlsConfig, err := loadGRPCServerTLS(settings)
	if err != nil {
		t.Fatalf("failed to load gRPC TLS config: %v", err)
	}

	server := &Server{
		settings:   settings,
		core:       &xray.Core{},
		usage:      newUsageBuffer(),
		system:     newSystemSampler(),
		sessions:   make(map[string]time.Time),
		operations: newOperationDeduper(filepath.Join(tempDir, "operation-receipts.json")),
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(server.sessionUnaryInterceptor, server.operations.unaryServerInterceptor),
	)
	server.registerGRPC(grpcServer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			t.Logf("gRPC test server stopped: %v", err)
		}
	}()
	defer grpcServer.Stop()

	clientCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("failed to load client cert: %v", err)
	}
	serverRootPEM, err := os.ReadFile(serverCertFile)
	if err != nil {
		t.Fatalf("failed to read server cert: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(serverRootPEM) {
		t.Fatal("failed to add server cert root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(
		ctx,
		listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName:   "rebecca-node.test",
			RootCAs:      roots,
			Certificates: []tls.Certificate{clientCert},
			MinVersion:   tls.VersionTLS12,
		})),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("failed to dial gRPC server: %v", err)
	}
	defer conn.Close()

	control := nodev1.NewNodeControlServiceClient(conn)
	hello, err := control.Hello(ctx, &nodev1.HelloRequest{MasterId: "test-master"})
	if err != nil {
		t.Fatalf("hello failed: %v", err)
	}
	if hello.GetNodeVersion() != "0.2.2" || hello.GetInstallMode() != "binary" || !hello.GetRuntime().GetConnected() {
		t.Fatalf("unexpected hello response: %#v", hello)
	}
	t.Logf("hello: node_version=%s install_mode=%s started=%v", hello.GetNodeVersion(), hello.GetInstallMode(), hello.GetRuntime().GetStarted())

	connected, err := control.Connect(ctx, &nodev1.ConnectRequest{MasterId: "test-master"})
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	if connected.GetConnectionId() == "" || !connected.GetRuntime().GetConnected() {
		t.Fatalf("unexpected connect response: %#v", connected)
	}

	health, err := control.Health(ctx, &nodev1.HealthRequest{IncludeMetrics: true})
	if err != nil {
		t.Fatalf("health failed: %v", err)
	}
	if health.GetMetrics().GetSystem().GetCpuCores() == 0 {
		t.Fatalf("expected health metrics, got %#v", health)
	}
	metrics := health.GetMetrics().GetSystem()
	t.Logf(
		"health: connected=%v started=%v cpu_cores=%d cpu_usage=%.1f memory=%d/%d",
		health.GetRuntime().GetConnected(),
		health.GetRuntime().GetStarted(),
		metrics.GetCpuCores(),
		metrics.GetCpuUsagePercent(),
		metrics.GetMemoryUsed(),
		metrics.GetMemoryTotal(),
	)

	unauthenticatedCtx, unauthenticatedCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer unauthenticatedCancel()
	unauthenticated, err := grpc.DialContext(
		unauthenticatedCtx,
		listener.Addr().String(),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			ServerName: "rebecca-node.test",
			RootCAs:    roots,
			MinVersion: tls.VersionTLS12,
		})),
		grpc.WithBlock(),
	)
	if err == nil {
		_ = unauthenticated.Close()
		t.Fatal("gRPC accepted a client without the installer certificate")
	}
}

func TestGRPCServerRequiresClientCertificateConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	serverCertFile, serverKeyFile := writeSelfSignedCert(t, tempDir, "server", []string{"rebecca-node.test"})

	settings := appconfig.Settings{
		AppName:     "rebecca-node",
		InstallMode: "binary",
		NodeVersion: "0.2.2",
		SSLCertFile: serverCertFile,
		SSLKeyFile:  serverKeyFile,
	}
	if _, err := loadGRPCServerTLS(settings); err == nil || !strings.Contains(err.Error(), "SSL_CLIENT_CERT_FILE") {
		t.Fatalf("expected missing client certificate error, got %v", err)
	}
}

func TestGRPCNodeVersionPrefersBinaryMetadata(t *testing.T) {
	tempDir := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(tempDir, ".binary-release.json"),
		[]byte(`{"install_mode":"binary","tag":"dev-abcdef0","arch":"linux-amd64"}`),
		0o600,
	); err != nil {
		t.Fatalf("failed to write metadata: %v", err)
	}
	server := &Server{
		settings: appconfig.Settings{
			AppName:        "rebecca-node",
			InstallMode:    "binary",
			NodeVersion:    "0.2.2",
			RebeccaDataDir: tempDir,
		},
		core:     &xray.Core{},
		usage:    newUsageBuffer(),
		sessions: make(map[string]time.Time),
	}
	api := &grpcAPI{server: server}

	hello, err := api.Hello(context.Background(), &nodev1.HelloRequest{})
	if err != nil {
		t.Fatalf("hello failed: %v", err)
	}
	if hello.GetNodeVersion() != "dev-abcdef0" {
		t.Fatalf("expected metadata node version, got %q", hello.GetNodeVersion())
	}
	if hello.GetUpdateChannel() != "dev" {
		t.Fatalf("expected dev update channel, got %q", hello.GetUpdateChannel())
	}
	if hello.GetRuntime().GetNodeVersion() != "dev-abcdef0" {
		t.Fatalf("expected runtime metadata node version, got %q", hello.GetRuntime().GetNodeVersion())
	}
}

func TestGRPCTestOutboundRejectsMissingTag(t *testing.T) {
	api := &grpcAPI{server: &Server{core: &xray.Core{}}}
	response, err := api.TestOutbound(context.Background(), &nodev1.OutboundTestRequest{
		AllOutboundsJson: `[{"tag":"direct","protocol":"freedom"}]`,
	})
	if err != nil {
		t.Fatalf("test outbound failed: %v", err)
	}
	if response.GetSuccess() {
		t.Fatalf("expected unsuccessful outbound test")
	}
	if response.GetError() != "Outbound has no tag" {
		t.Fatalf("unexpected outbound test error: %q", response.GetError())
	}
}

func TestReplaceMarkedBlock(t *testing.T) {
	current := "Keep 1\n# BEGIN REBECCA TOR PROXY\nold\n# END REBECCA TOR PROXY\nKeep 2\n"
	got := replaceMarkedBlock(current, torRebeccaBlockStart, torRebeccaBlockEnd, "new")
	if got != "Keep 1\n\nKeep 2\n\nnew\n" {
		t.Fatalf("replaceMarkedBlock()=%q", got)
	}
}

func TestPublicIPValidation(t *testing.T) {
	if !isGlobalIP("8.8.8.8", true) {
		t.Fatal("expected 8.8.8.8 to be a global IPv4")
	}
	if isGlobalIP("10.0.0.1", true) {
		t.Fatal("expected private IPv4 to be rejected")
	}
	if !isGlobalIP("2001:4860:4860::8888", false) {
		t.Fatal("expected Google DNS IPv6 to be a global IPv6")
	}
	if isGlobalIP("::1", false) {
		t.Fatal("expected loopback IPv6 to be rejected")
	}
}

func TestCanonicalConfigTopologyKeepsReverseClients(t *testing.T) {
	base := `{"inbounds":[{"tag":"vless","settings":{"clients":[{"id":"user-1","email":"user"}]}}]}`
	withUser := `{"inbounds":[{"tag":"vless","settings":{"clients":[{"id":"user-2","email":"other"}]}}]}`
	withReverse := `{"inbounds":[{"tag":"vless","settings":{"clients":[{"id":"user-1","email":"user"},{"id":"reverse-1","reverse":{"tag":"reverse-out"}}]}}]}`

	baseTopology, ok := canonicalConfigTopologyJSON(base)
	if !ok {
		t.Fatal("failed to normalize base topology")
	}
	userTopology, ok := canonicalConfigTopologyJSON(withUser)
	if !ok || userTopology != baseTopology {
		t.Fatalf("ordinary users must not change topology: %q != %q", userTopology, baseTopology)
	}
	reverseTopology, ok := canonicalConfigTopologyJSON(withReverse)
	if !ok || reverseTopology == baseTopology {
		t.Fatal("reverse clients must trigger a topology update")
	}
}

func writeSelfSignedCert(t *testing.T, dir string, name string, dnsNames []string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certFile := filepath.Join(dir, name+".pem")
	keyFile := filepath.Join(dir, name+"-key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	return certFile, keyFile
}
