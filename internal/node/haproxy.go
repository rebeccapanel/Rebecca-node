package node

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type haproxyRuntime struct {
	Enabled    bool                 `json:"enabled"`
	ConfigText string               `json:"config_text"`
	Sites      []haproxyRuntimeSite `json:"sites"`
}

type haproxyRuntimeSite struct {
	Socket          string `json:"socket"`
	Hostname        string `json:"hostname"`
	Source          string `json:"source"`
	TemplateID      string `json:"template_id"`
	TemplateURL     string `json:"template_url"`
	Token           string `json:"token"`
	SHA256          string `json:"sha256"`
	TLSMode         string `json:"tls_mode"`
	CertificatePEM  string `json:"certificate_pem"`
	PrivateKeyPEM   string `json:"private_key_pem"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	NotFoundHTML    string `json:"not_found_html"`
}

type haproxySiteServer struct {
	server   *http.Server
	listener net.Listener
}

type haproxyManager struct {
	dir       string
	mu        sync.Mutex
	sites     []haproxySiteServer
	lastError string
}

const builtinHAProxySite = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#111;color:#eee;font:16px system-ui}main{text-align:center;padding:2rem}h1{font-size:2.4rem;margin:.2rem}</style><main><h1>Welcome</h1><p>This website is served through HAProxy.</p></main>`

func newHAProxyManager(dataDir string) *haproxyManager {
	return &haproxyManager{dir: filepath.Join(dataDir, "haproxy")}
}

func (m *haproxyManager) Apply(runtime *haproxyRuntime) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.applyLocked(runtime)
	if err != nil {
		m.lastError = err.Error()
	} else {
		m.lastError = ""
	}
	return err
}

func (m *haproxyManager) applyLocked(runtime *haproxyRuntime) error {
	if runtime == nil || !runtime.Enabled {
		return m.stopLocked()
	}
	if _, err := exec.LookPath("haproxy"); err != nil {
		return fmt.Errorf("HAProxy is not installed; update the Rebecca node first")
	}
	if len(runtime.ConfigText) == 0 || len(runtime.ConfigText) > 1<<20 || strings.ContainsRune(runtime.ConfigText, 0) {
		return fmt.Errorf("invalid HAProxy config payload")
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(m.dir, "haproxy-*.cfg")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.WriteString(runtime.ConfigText); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if output, err := exec.Command("haproxy", "-c", "-f", temporaryPath).CombinedOutput(); err != nil {
		return fmt.Errorf("invalid HAProxy config: %s", strings.TrimSpace(string(output)))
	}
	// Resolve templates and certificates before stopping the currently served
	// sites. A transient master/template failure must not turn a good runtime
	// into a blank listener.
	for _, site := range runtime.Sites {
		if _, err := m.siteRoot(site); err != nil {
			return err
		}
		if site.TLSMode != "" && site.TLSMode != "none" {
			if _, err := m.siteCertificate(site); err != nil {
				return err
			}
		}
	}
	if err := m.restartSitesLocked(runtime.Sites); err != nil {
		return err
	}
	configPath := filepath.Join(m.dir, "haproxy.cfg")
	if err := os.Rename(temporaryPath, configPath); err != nil {
		return err
	}
	pidPath := filepath.Join(m.dir, "haproxy.pid")
	args := []string{"-W", "-db", "-f", configPath, "-p", pidPath}
	if oldPID := readPID(pidPath); oldPID > 0 && processExists(oldPID) {
		args = append(args, "-sf", strconv.Itoa(oldPID))
	}
	command := exec.Command("haproxy", args...)
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			err = errors.New("HAProxy stopped during startup")
		}
		return err
	case <-time.After(300 * time.Millisecond):
		return nil
	}
}

func (m *haproxyManager) lastErrorMessage() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastError
}

func (m *haproxyManager) stopLocked() error {
	m.stopSitesLocked()
	pidPath := filepath.Join(m.dir, "haproxy.pid")
	pid := readPID(pidPath)
	if pid <= 0 || !processExists(pid) {
		_ = os.Remove(pidPath)
		return nil
	}
	if err := terminateHAProxyProcess(pid); err != nil {
		return err
	}
	_ = os.Remove(pidPath)
	return nil
}

func (m *haproxyManager) restartSitesLocked(sites []haproxyRuntimeSite) error {
	m.stopSitesLocked()
	started := make([]haproxySiteServer, 0, len(sites))
	for _, site := range sites {
		root, err := m.siteRoot(site)
		if err != nil {
			closeHAProxySites(started)
			return err
		}
		if !strings.HasPrefix(site.Socket, "/tmp/rebecca-haproxy-") || !strings.HasSuffix(site.Socket, ".sock") {
			closeHAProxySites(started)
			return fmt.Errorf("invalid HAProxy website socket")
		}
		_ = os.Remove(site.Socket)
		listener, err := net.Listen("unix", site.Socket)
		if err != nil {
			closeHAProxySites(started)
			return err
		}
		_ = os.Chmod(site.Socket, 0o600)
		server := &http.Server{Handler: haproxySiteHandler(root, site.NotFoundHTML), ReadHeaderTimeout: 5 * time.Second}
		serveListener := listener
		if site.TLSMode != "" && site.TLSMode != "none" {
			certificate, err := m.siteCertificate(site)
			if err != nil {
				_ = listener.Close()
				closeHAProxySites(started)
				return err
			}
			serveListener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		}
		started = append(started, haproxySiteServer{server: server, listener: listener})
		go func() { _ = server.Serve(serveListener) }()
	}
	m.sites = started
	return nil
}

func (m *haproxyManager) siteCertificate(site haproxyRuntimeSite) (tls.Certificate, error) {
	switch site.TLSMode {
	case "managed":
		return tls.X509KeyPair([]byte(site.CertificatePEM), []byte(site.PrivateKeyPEM))
	case "custom":
		if !validNodeCertificatePath(site.CertificatePath) || !validNodeCertificatePath(site.PrivateKeyPath) {
			return tls.Certificate{}, fmt.Errorf("invalid HAProxy custom certificate path")
		}
		return tls.LoadX509KeyPair(site.CertificatePath, site.PrivateKeyPath)
	case "self_signed":
		return m.selfSignedCertificate(site.Hostname)
	default:
		return tls.Certificate{}, fmt.Errorf("unsupported HAProxy website TLS mode")
	}
}

func validNodeCertificatePath(value string) bool {
	return filepath.IsAbs(value) && len(value) <= 1024 && !strings.ContainsAny(value, "\x00\r\n")
}

func (m *haproxyManager) selfSignedCertificate(hostname string) (tls.Certificate, error) {
	if hostname == "" || strings.ContainsAny(hostname, "\x00\r\n/\\") {
		return tls.Certificate{}, fmt.Errorf("invalid self-signed certificate hostname")
	}
	sum := sha256.Sum256([]byte(strings.ToLower(hostname)))
	dir := filepath.Join(m.dir, "certificates", hex.EncodeToString(sum[:8]))
	certPath, keyPath := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if certificate, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return certificate, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func (m *haproxyManager) stopSitesLocked() {
	closeHAProxySites(m.sites)
	m.sites = nil
}

func closeHAProxySites(sites []haproxySiteServer) {
	for _, site := range sites {
		_ = site.server.Close()
		_ = site.listener.Close()
		if address := site.listener.Addr(); address != nil {
			_ = os.Remove(address.String())
		}
	}
}

func (m *haproxyManager) siteRoot(site haproxyRuntimeSite) (string, error) {
	if site.Source == "builtin" {
		root := filepath.Join(m.dir, "templates", "builtin")
		if err := os.MkdirAll(root, 0o700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(root, "index.html"), []byte(builtinHAProxySite), 0o600); err != nil {
			return "", err
		}
		return root, nil
	}
	if site.Source != "templatemo" && site.Source != "upload" {
		return "", fmt.Errorf("unsupported HAProxy website source")
	}
	if err := validateHAProxyTemplateURL(site.TemplateURL, site.Token != ""); err != nil {
		return "", err
	}
	key := site.SHA256
	if key == "" {
		sum := sha256.Sum256([]byte(site.TemplateURL))
		key = hex.EncodeToString(sum[:])
	}
	base := filepath.Join(m.dir, "templates", key)
	marker := filepath.Join(base, ".root")
	if relative, err := os.ReadFile(marker); err == nil {
		root := filepath.Join(base, string(relative))
		if info, statErr := os.Stat(filepath.Join(root, "index.html")); statErr == nil && !info.IsDir() {
			return root, nil
		}
	}
	archive, err := downloadHAProxyTemplate(site)
	if err != nil {
		return "", err
	}
	if site.SHA256 != "" {
		sum := sha256.Sum256(archive)
		if !strings.EqualFold(hex.EncodeToString(sum[:]), site.SHA256) {
			return "", fmt.Errorf("HAProxy template checksum mismatch")
		}
	}
	return extractHAProxyTemplate(archive, base)
}

func validateHAProxyTemplateURL(raw string, trustedMaster bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("invalid HAProxy template URL")
	}
	if trustedMaster {
		return nil
	}
	if parsed.Scheme != "https" || !strings.EqualFold(parsed.Hostname(), "templatemo.com") || !strings.HasPrefix(parsed.Path, "/download/templatemo_") {
		return fmt.Errorf("untrusted HAProxy template URL")
	}
	return nil
}

func downloadHAProxyTemplate(site haproxyRuntimeSite) ([]byte, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, site.TemplateURL, nil)
	if err != nil {
		return nil, err
	}
	if site.Token != "" {
		request.Header.Set("Authorization", "Bearer "+site.Token)
	}
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download HAProxy template: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("download HAProxy template: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) == 0 || len(body) > 32<<20 {
		return nil, fmt.Errorf("HAProxy template download exceeds 32 MiB")
	}
	return body, nil
}

func extractHAProxyTemplate(archive []byte, target string) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) == 0 || len(reader.File) > 2048 {
		return "", fmt.Errorf("invalid HAProxy template ZIP")
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".haproxy-template-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stage)
	var total uint64
	indexPath := ""
	for _, file := range reader.File {
		clean := filepath.Clean(strings.ReplaceAll(file.Name, "\\", "/"))
		if clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
			return "", fmt.Errorf("HAProxy template ZIP contains an unsafe path")
		}
		destination := filepath.Join(stage, clean)
		if !strings.HasPrefix(destination, stage+string(filepath.Separator)) {
			return "", fmt.Errorf("HAProxy template ZIP escaped its directory")
		}
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(destination, 0o700); err != nil {
				return "", err
			}
			continue
		}
		total += file.UncompressedSize64
		if total > 128<<20 {
			return "", fmt.Errorf("extracted HAProxy template exceeds 128 MiB")
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return "", err
		}
		source, err := file.Open()
		if err != nil {
			return "", err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err == nil {
			_, err = io.Copy(output, io.LimitReader(source, int64(file.UncompressedSize64)+1))
			_ = output.Close()
		}
		_ = source.Close()
		if err != nil {
			return "", err
		}
		if strings.EqualFold(filepath.Base(destination), "index.html") && (indexPath == "" || len(destination) < len(indexPath)) {
			indexPath = destination
		}
	}
	if indexPath == "" {
		return "", fmt.Errorf("HAProxy template ZIP is missing index.html")
	}
	rootRelative, err := filepath.Rel(stage, filepath.Dir(indexPath))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(stage, ".root"), []byte(rootRelative), 0o600); err != nil {
		return "", err
	}
	_ = os.RemoveAll(target)
	if err := os.Rename(stage, target); err != nil {
		return "", err
	}
	return filepath.Join(target, rootRelative), nil
}

func haproxySiteHandler(root, notFoundHTML string) http.Handler {
	files := http.FileServer(http.Dir(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		if clean == "." {
			clean = "index.html"
		}
		path := filepath.Join(root, clean)
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			_, err = os.Stat(filepath.Join(path, "index.html"))
		}
		if err != nil {
			if notFoundHTML == "" {
				notFoundHTML = "<!doctype html><title>404 Not Found</title><h1>404 Not Found</h1>"
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, notFoundHTML)
			return
		}
		files.ServeHTTP(w, r)
	})
}

func readPID(path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return pid
}
