package node

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractHAProxyTemplateAndServeCustom404(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("site/index.html")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(file, "template-home")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := extractHAProxyTemplate(archive.Bytes(), filepath.Join(t.TempDir(), "templates", "template"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
	handler := haproxySiteHandler(root, "custom-not-found")
	home := httptest.NewRecorder()
	handler.ServeHTTP(home, httptest.NewRequest(http.MethodGet, "/", nil))
	if home.Code != http.StatusOK || !strings.Contains(home.Body.String(), "template-home") {
		t.Fatalf("unexpected home response: %d %q", home.Code, home.Body.String())
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if missing.Code != http.StatusNotFound || missing.Body.String() != "custom-not-found" {
		t.Fatalf("unexpected 404 response: %d %q", missing.Code, missing.Body.String())
	}
}

func TestValidateHAProxyTemplateURL(t *testing.T) {
	if err := validateHAProxyTemplateURL("https://templatemo.com/download/templatemo_582_tale_seo_agency", false); err != nil {
		t.Fatal(err)
	}
	if err := validateHAProxyTemplateURL("https://example.com/template.zip", false); err == nil {
		t.Fatal("untrusted public template source was accepted")
	}
}

func TestDownloadAndExtractHAProxyTemplate(t *testing.T) {
	rawURL := os.Getenv("HAPROXY_TEMPLATE_TEST_URL")
	if rawURL == "" {
		t.Skip("HAPROXY_TEMPLATE_TEST_URL is not set")
	}
	archive, err := downloadHAProxyTemplate(haproxyRuntimeSite{Source: "templatemo", TemplateURL: rawURL})
	if err != nil {
		t.Fatal(err)
	}
	root, err := extractHAProxyTemplate(archive, filepath.Join(t.TempDir(), "downloaded"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Fatal(err)
	}
}

func TestHAProxyManagerServesBuiltinWebsite(t *testing.T) {
	binary := os.Getenv("HAPROXY_TEST_BINARY")
	if binary == "" {
		t.Skip("HAPROXY_TEST_BINARY is not set")
	}
	t.Setenv("PATH", filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	socket := filepath.Join("/tmp", "rebecca-haproxy-test-"+strings.ReplaceAll(t.Name(), "/", "-")+".sock")
	config := "global\n    maxconn 128\ndefaults\n    mode tcp\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\nfrontend site_frontend\n    bind 127.0.0.1:" + fmt.Sprint(port) + "\n    mode tcp\n    tcp-request inspect-delay 1s\n    tcp-request content accept if { req.proto_http }\n    acl ordinary req.proto_http\n    use_backend site_backend if ordinary\nbackend site_backend\n    mode tcp\n    server target unix@" + socket + "\n"
	manager := newHAProxyManager(t.TempDir())
	runtime := &haproxyRuntime{Enabled: true, ConfigText: config, Sites: []haproxyRuntimeSite{{Socket: socket, Source: "builtin", TemplateID: "builtin", NotFoundHTML: "node-custom-404"}}}
	if err := manager.Apply(runtime); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Apply(&haproxyRuntime{}) }()
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "served through HAProxy") {
		t.Fatalf("unexpected website response: %d %q", response.StatusCode, body)
	}
	response, err = client.Get(fmt.Sprintf("http://127.0.0.1:%d/missing", port))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNotFound || string(body) != "node-custom-404" {
		t.Fatalf("unexpected custom 404 response: %d %q", response.StatusCode, body)
	}
}

func TestHAProxyManagerServesDefaultWebsiteOverHTTPAndHTTPS(t *testing.T) {
	binary := os.Getenv("HAPROXY_TEST_BINARY")
	if binary == "" {
		t.Skip("HAPROXY_TEST_BINARY is not set")
	}
	t.Setenv("PATH", filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	httpSocket := filepath.Join("/tmp", "rebecca-haproxy-test-default-http.sock")
	tlsSocket := filepath.Join("/tmp", "rebecca-haproxy-test-default-tls.sock")
	config := fmt.Sprintf(`global
    maxconn 128
defaults
    mode tcp
    timeout connect 1s
    timeout client 5s
    timeout server 5s
frontend default_site
    bind 127.0.0.1:%d
    tcp-request inspect-delay 1s
    tcp-request content accept if { req_ssl_hello_type 1 }
    tcp-request content accept if { req.proto_http }
    use_backend default_http if { req.proto_http }
    use_backend default_tls if { req_ssl_hello_type 1 }
backend default_http
    server target unix@%s
backend default_tls
    server target unix@%s
`, port, httpSocket, tlsSocket)
	manager := newHAProxyManager(t.TempDir())
	runtime := &haproxyRuntime{Enabled: true, ConfigText: config, Sites: []haproxyRuntimeSite{
		{Socket: httpSocket, Source: "builtin", TemplateID: "builtin"},
		{Socket: tlsSocket, Source: "builtin", TemplateID: "builtin", TLSMode: "self_signed", Hostname: "localhost"},
	}}
	if err := manager.Apply(runtime); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Apply(&haproxyRuntime{}) }()
	for _, client := range []*http.Client{
		{Timeout: 2 * time.Second},
		{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}},
	} {
		scheme := "http"
		if client.Transport != nil {
			scheme = "https"
		}
		response, err := client.Get(fmt.Sprintf("%s://127.0.0.1:%d/", scheme, port))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "served through HAProxy") {
			t.Fatalf("unexpected %s response: %d %q", scheme, response.StatusCode, body)
		}
	}
}

func TestHAProxyManagerRoutesMultipleTLSSitesBySNI(t *testing.T) {
	binary := os.Getenv("HAPROXY_TEST_BINARY")
	if binary == "" {
		t.Skip("HAPROXY_TEST_BINARY is not set")
	}
	t.Setenv("PATH", filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	firstSocket := filepath.Join("/tmp", "rebecca-haproxy-test-first.sock")
	secondSocket := filepath.Join("/tmp", "rebecca-haproxy-test-second.sock")
	config := fmt.Sprintf(`global
    maxconn 128
defaults
    mode tcp
    timeout connect 1s
    timeout client 5s
    timeout server 5s
frontend tls_sites
    bind 127.0.0.1:%d
    tcp-request inspect-delay 1s
    tcp-request content accept if { req_ssl_hello_type 1 }
    acl first req.ssl_sni -i first.example.test
    acl second req.ssl_sni -i second.example.test
    use_backend first_site if first
    use_backend second_site if second
backend first_site
    server target unix@%s
backend second_site
    server target unix@%s
`, port, firstSocket, secondSocket)
	manager := newHAProxyManager(t.TempDir())
	runtime := &haproxyRuntime{Enabled: true, ConfigText: config, Sites: []haproxyRuntimeSite{
		{Socket: firstSocket, Source: "builtin", TemplateID: "builtin", TLSMode: "self_signed", Hostname: "first.example.test", NotFoundHTML: "first-site"},
		{Socket: secondSocket, Source: "builtin", TemplateID: "builtin", TLSMode: "self_signed", Hostname: "second.example.test", NotFoundHTML: "second-site"},
	}}
	if err := manager.Apply(runtime); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = manager.Apply(&haproxyRuntime{}) }()
	for hostname, expected := range map[string]string{"first.example.test": "first-site", "second.example.test": "second-site"} {
		client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: hostname, InsecureSkipVerify: true}}}
		response, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/missing", port))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNotFound || string(body) != expected {
			t.Fatalf("SNI %s reached wrong website: %d %q", hostname, response.StatusCode, body)
		}
	}
}
