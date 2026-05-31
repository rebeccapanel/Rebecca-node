package node

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestGRPCServerAcceptsMutualTLSClient(t *testing.T) {
	tempDir := t.TempDir()
	serverCertFile, serverKeyFile := writeSelfSignedCert(t, tempDir, "server", []string{"rebecca-node.test"})
	clientCertFile, clientKeyFile := writeSelfSignedCert(t, tempDir, "client", nil)

	settings := appconfig.Settings{
		AppName:           "rebecca-node",
		InstallMode:       "binary",
		NodeVersion:       "0.2.0",
		SSLCertFile:       serverCertFile,
		SSLKeyFile:        serverKeyFile,
		SSLClientCertFile: clientCertFile,
	}
	tlsConfig, err := loadGRPCServerTLS(settings)
	if err != nil {
		t.Fatalf("failed to load gRPC TLS config: %v", err)
	}

	server := &Server{
		settings: settings,
		core:     &xray.Core{},
		usage:    newUsageBuffer(),
		system:   newSystemSampler(),
		sessions: make(map[string]time.Time),
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
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

	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
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
	if hello.GetNodeVersion() != "0.2.0" || hello.GetInstallMode() != "binary" {
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
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
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
