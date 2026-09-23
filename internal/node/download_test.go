package node

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDownloadXrayCoreArchiveFallsBackAfterHTMLError(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>bad gateway</body></html>`))
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(testZipArchive(t))
	}))
	defer good.Close()

	previousBases := xrayCoreDownloadBaseURLs
	previousValidator := validateXrayCoreDownloadURL
	xrayCoreDownloadBaseURLs = []string{good.URL + "/download"}
	validateXrayCoreDownloadURL = func(string) error { return nil }
	t.Cleanup(func() {
		xrayCoreDownloadBaseURLs = previousBases
		validateXrayCoreDownloadURL = previousValidator
	})
	t.Setenv("XRAY_CORE_DOWNLOAD_BASE_URL", bad.URL+"/download")

	body, err := downloadXrayCoreArchive("v1.2.3", "Xray-linux-64.zip", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatalf("fallback body is not a valid zip: %v", err)
	}
}

func TestDownloadXrayCoreArchiveReportsSanitizedHTML(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<!DOCTYPE html><html><body>bad gateway</body></html>`))
	}))
	defer bad.Close()

	previousBases := xrayCoreDownloadBaseURLs
	previousValidator := validateXrayCoreDownloadURL
	xrayCoreDownloadBaseURLs = []string{bad.URL + "/download"}
	validateXrayCoreDownloadURL = func(string) error { return nil }
	t.Cleanup(func() {
		xrayCoreDownloadBaseURLs = previousBases
		validateXrayCoreDownloadURL = previousValidator
	})

	_, err := downloadXrayCoreArchive("v1.2.3", "Xray-linux-64.zip", time.Second)
	if err == nil {
		t.Fatal("expected download error")
	}
	if strings.Contains(err.Error(), "<!DOCTYPE") {
		t.Fatalf("raw HTML leaked into error: %v", err)
	}
	if !strings.Contains(err.Error(), "HTML error page") {
		t.Fatalf("expected sanitized HTML error, got %v", err)
	}
}

func TestDownloadRejectsTruncatedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		_, _ = w.Write([]byte("short"))
	}))
	defer server.Close()

	_, err := download(server.URL, time.Second)
	if err == nil {
		t.Fatalf("expected truncated response error, got %v", err)
	}
}

func testZipArchive(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	file, err := writer.Create("xray")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("#!/bin/sh\n")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
