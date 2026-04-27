package node

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type Server struct {
	settings appconfig.Settings
	core     *xray.Core
	usage    *usageBuffer

	mu         sync.Mutex
	connected  bool
	clientIP   string
	sessionID  string
	lastConfig *xray.Config
}

var xrayVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:[-+._A-Za-z0-9]*)?$`)
var releaseVersionPattern = regexp.MustCompile(`^v?\d+(?:\.\d+){1,3}(?:[-+._A-Za-z0-9]*)?$`)
var allowedGeoFiles = map[string]struct{}{"geoip.dat": {}, "geosite.dat": {}}

func New(settings appconfig.Settings) (*Server, error) {
	core, err := xray.NewCore(settings.XrayExecutablePath, settings.XrayAssetsPath, settings.Debug)
	if err != nil {
		return nil, err
	}
	server := &Server{settings: settings, core: core, usage: newUsageBuffer()}
	server.startCachedConfig()
	return server, nil
}

func (s *Server) ListenAndServeTLS() error {
	if s.settings.SSLClientCertFile == "" || !fileExists(s.settings.SSLClientCertFile) {
		return errors.New("SSL_CLIENT_CERT_FILE is required for the REST service")
	}

	cert, err := tls.LoadX509KeyPair(s.settings.SSLCertFile, s.settings.SSLKeyFile)
	if err != nil {
		return err
	}
	clientCAPEM, err := os.ReadFile(s.settings.SSLClientCertFile)
	if err != nil {
		return err
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(clientCAPEM) {
		return errors.New("failed to load SSL_CLIENT_CERT_FILE")
	}

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.settings.ServiceHost, s.settings.ServicePort),
		Handler: s.routes(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    clientCAs,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
	}
	return server.ListenAndServeTLS("", "")
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleBase)
	mux.HandleFunc("/connect", s.handleConnect)
	mux.HandleFunc("/disconnect", s.handleDisconnect)
	mux.HandleFunc("/ping", s.handlePing)
	mux.HandleFunc("/start", s.handleStart)
	mux.HandleFunc("/stop", s.handleStop)
	mux.HandleFunc("/restart", s.handleRestart)
	mux.HandleFunc("/update_core", s.handleUpdateCore)
	mux.HandleFunc("/update_geo", s.handleUpdateGeo)
	mux.HandleFunc("/service/restart", s.handleServiceRestart)
	mux.HandleFunc("/service/update", s.handleServiceUpdate)
	mux.HandleFunc("/usage/users", s.handleUserUsage)
	mux.HandleFunc("/usage/users/ack", s.handleUserUsageAck)
	mux.HandleFunc("/usage/outbounds", s.handleOutboundUsage)
	mux.HandleFunc("/usage/outbounds/ack", s.handleOutboundUsageAck)
	mux.HandleFunc("/access_logs", s.handleAccessLogs)
	mux.HandleFunc("/logs", s.handleLogs)
	return mux
}

func (s *Server) handleBase(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, "Not Found")
		return
	}
	writeJSON(w, http.StatusOK, s.response(nil))
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	sessionID, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	clientIP := remoteIP(r)

	if s.core.Started() {
		s.snapshotRunningUsage()
		s.core.Stop()
	}

	s.mu.Lock()
	s.connected = true
	s.clientIP = clientIP
	s.sessionID = sessionID
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, s.response(map[string]any{"session_id": sessionID}))
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.connected = false
	s.clientIP = ""
	s.sessionID = ""
	s.mu.Unlock()
	if s.core.Started() {
		s.snapshotRunningUsage()
		s.core.Stop()
	}
	s.clearConfigCache()
	writeJSON(w, http.StatusOK, s.response(nil))
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if !s.matchRequestSession(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	payload, ok := s.readConfigPayload(w, r)
	if !ok {
		return
	}
	cfg, err := xray.NewConfig(payload.Config, s.currentClientIP(), s.settings)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": map[string]string{"config": "Failed to decode config: " + err.Error()}})
		return
	}
	if err := s.core.Start(cfg); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.mu.Lock()
	s.lastConfig = cfg
	s.mu.Unlock()
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
		return
	}
	s.saveConfigCache(payload.Config, s.currentClientIP())
	writeJSON(w, http.StatusOK, s.response(nil))
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	if !s.matchRequestSession(w, r) {
		return
	}
	s.snapshotRunningUsage()
	s.core.Stop()
	s.clearConfigCache()
	writeJSON(w, http.StatusOK, s.response(nil))
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	payload, ok := s.readConfigPayload(w, r)
	if !ok {
		return
	}
	cfg, err := xray.NewConfig(payload.Config, s.currentClientIP(), s.settings)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": map[string]string{"config": "Failed to decode config: " + err.Error()}})
		return
	}
	if err := s.core.Restart(cfg); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	s.mu.Lock()
	s.lastConfig = cfg
	s.mu.Unlock()
	time.Sleep(3 * time.Second)
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, strings.Join(s.core.Logs().Snapshot(), "\n"))
		return
	}
	s.saveConfigCache(payload.Config, s.currentClientIP())
	writeJSON(w, http.StatusOK, s.response(nil))
}

func (s *Server) handleUpdateCore(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	payload.Version = strings.TrimSpace(payload.Version)
	if payload.Version == "" {
		writeError(w, http.StatusUnprocessableEntity, "version is required")
		return
	}
	if !validXrayVersion(payload.Version) {
		writeError(w, http.StatusUnprocessableEntity, "invalid version")
		return
	}
	asset, err := detectXrayAsset()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", payload.Version, asset)
	if err := validatePublicHTTPURL(url); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	body, err := download(url, 120*time.Second)
	if err != nil {
		writeError(w, http.StatusBadGateway, "Download failed: "+err.Error())
		return
	}

	baseDir := filepath.Join(s.settings.RebeccaDataDir, "xray-core")
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.core.Started() {
		s.core.Stop()
	}
	extracted, err := installZipTo(body, baseDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	finalExe := filepath.Join(baseDir, executableName("xray"))
	if extracted != finalExe {
		_ = os.Remove(finalExe)
		if err := os.Rename(extracted, finalExe); err != nil {
			if copyErr := copyFile(extracted, finalExe); copyErr != nil {
				writeError(w, http.StatusInternalServerError, copyErr.Error())
				return
			}
		}
	}
	_ = os.Chmod(finalExe, 0o755)
	if err := s.core.SetExecutablePath(finalExe); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"detail": "Node core ready at " + finalExe, "version": s.core.Version()})
}

func (s *Server) handleUpdateGeo(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Files []downloadFile `json:"files"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if len(payload.Files) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "'files' must be a non-empty list of {name,url}.")
		return
	}
	assetsDir := filepath.Join(s.settings.RebeccaDataDir, "assets")
	if err := os.MkdirAll(assetsDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	saved := make([]map[string]string, 0, len(payload.Files))
	for _, file := range payload.Files {
		name := safeGeoFilename(file.Name)
		url := strings.TrimSpace(file.URL)
		if name == "" || url == "" {
			writeError(w, http.StatusUnprocessableEntity, "Each file must include non-empty 'name' and 'url'.")
			return
		}
		if err := validatePublicHTTPURL(url); err != nil {
			writeError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		body, err := download(url, 120*time.Second)
		if err != nil {
			writeError(w, http.StatusBadGateway, "Failed to download "+name+": "+err.Error())
			return
		}
		path := filepath.Join(assetsDir, name)
		if err := os.WriteFile(path, body, 0o644); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to save "+name+": "+err.Error())
			return
		}
		saved = append(saved, map[string]string{"name": name, "path": path})
	}
	s.core.SetAssetsPath(assetsDir)
	writeJSON(w, http.StatusOK, map[string]any{"detail": "Geo assets saved to " + assetsDir, "saved": saved})
}

func (s *Server) handleServiceRestart(w http.ResponseWriter, r *http.Request) {
	if !s.matchRequestSession(w, r) {
		return
	}
	if err := s.scheduleNodeCLI("restart", "-n"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted"})
}

func (s *Server) handleServiceUpdate(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		SessionID string `json:"session_id"`
		Channel   string `json:"channel"`
		Version   string `json:"version"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	args, err := nodeUpdateArgs(payload.Channel, payload.Version)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.scheduleNodeCLI(args...); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "accepted"})
}

func (s *Server) handleOutboundUsage(w http.ResponseWriter, r *http.Request) {
	if !s.matchRequestSession(w, r) {
		return
	}
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, "Xray is not started")
		return
	}
	stats, err := xray.QueryOutboundStats(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		10*time.Second,
		true,
	)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	batchID, pending := s.usage.addAndSnapshot(stats)
	writeJSON(w, http.StatusOK, map[string]any{"batch_id": batchID, "stats": pending})
}

func (s *Server) snapshotRunningUsage() {
	if !s.core.Started() {
		return
	}
	outboundStats, err := xray.QueryOutboundStats(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		5*time.Second,
		true,
	)
	if err == nil {
		s.usage.add(outboundStats)
	} else {
		log.Printf("failed to snapshot outbound usage before stopping xray: %v", err)
	}
	userStats, err := xray.QueryUserStats(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		5*time.Second,
		true,
	)
	if err == nil {
		s.usage.addUsers(userStats)
	} else {
		log.Printf("failed to snapshot user usage before stopping xray: %v", err)
	}
}

func (s *Server) handleUserUsage(w http.ResponseWriter, r *http.Request) {
	if !s.matchRequestSession(w, r) {
		return
	}
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, "Xray is not started")
		return
	}
	stats, err := xray.QueryUserStats(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		30*time.Second,
		true,
	)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	batchID, pending := s.usage.addUsersAndSnapshot(stats)
	writeJSON(w, http.StatusOK, map[string]any{"batch_id": batchID, "stats": pending})
}

func (s *Server) handleOutboundUsageAck(w http.ResponseWriter, r *http.Request) {
	s.handleUsageAck(w, r, s.usage.ack)
}

func (s *Server) handleUserUsageAck(w http.ResponseWriter, r *http.Request) {
	s.handleUsageAck(w, r, s.usage.ackUsers)
}

func (s *Server) handleUsageAck(w http.ResponseWriter, r *http.Request, ack func(string) bool) {
	var payload struct {
		SessionID string `json:"session_id"`
		BatchID   string `json:"batch_id"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	if payload.BatchID == "" {
		writeError(w, http.StatusUnprocessableEntity, "batch_id is required")
		return
	}
	if !ack(payload.BatchID) {
		writeError(w, http.StatusNotFound, "batch_id was not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "acknowledged"})
}

func (s *Server) scheduleNodeCLI(args ...string) error {
	cli, err := resolveNodeCLI(s.settings.AppName)
	if err != nil {
		return err
	}
	command, commandArgs := hostActionCommand(cli, args...)
	cmd := exec.Command(command, commandArgs...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

func hostActionCommand(cli string, args ...string) (string, []string) {
	if runtime.GOOS == "linux" {
		if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
			unit := fmt.Sprintf("rebecca-node-host-action-%d", time.Now().UnixNano())
			commandArgs := []string{
				"--unit", unit,
				"--collect",
				"--description", "Rebecca-node host action",
				"--",
				cli,
			}
			commandArgs = append(commandArgs, args...)
			return systemdRun, commandArgs
		}
	}
	return cli, args
}

func (s *Server) handleAccessLogs(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		SessionID string `json:"session_id"`
		MaxLines  int    `json:"max_lines"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if payload.MaxLines == 0 {
		payload.MaxLines = 500
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}

	logPath := ""
	s.mu.Lock()
	if s.lastConfig != nil {
		logPath = s.lastConfig.AccessLogPath()
	}
	s.mu.Unlock()
	if logPath == "" || strings.EqualFold(logPath, "none") {
		baseDir := s.settings.XrayLogDir
		if strings.TrimSpace(baseDir) == "" {
			baseDir = s.settings.XrayAssetsPath
		}
		if strings.TrimSpace(baseDir) == "" {
			baseDir = "/var/log"
		}
		logPath = filepath.Join(baseDir, "access.log")
	}
	lines, exists, err := tailFile(logPath, payload.MaxLines)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to read access logs: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"log_path":    logPath,
		"exists":      exists,
		"lines":       lines,
		"total_lines": len(lines),
	})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	if !s.sessionMatches(sessionID) {
		http.Error(w, "Session ID mismatch.", http.StatusForbidden)
		return
	}
	interval := 0 * time.Second
	if raw := r.URL.Query().Get("interval"); raw != "" {
		parsed, err := time.ParseDuration(raw + "s")
		if err != nil || parsed <= 0 || parsed > 10*time.Second {
			http.Error(w, "Invalid interval value", http.StatusBadRequest)
			return
		}
		interval = parsed
	}

	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		return
	}
	defer conn.Close()

	logs, cancel := s.core.Logs().Subscribe()
	defer cancel()

	if interval == 0 {
		for line := range logs {
			if !s.sessionMatches(sessionID) {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(line)); err != nil {
				return
			}
		}
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var buffer bytes.Buffer
	for {
		select {
		case line := <-logs:
			buffer.WriteString(line)
			buffer.WriteByte('\n')
		case <-ticker.C:
			if buffer.Len() > 0 {
				if err := conn.WriteMessage(websocket.TextMessage, buffer.Bytes()); err != nil {
					return
				}
				buffer.Reset()
			}
		}
	}
}

type configPayload struct {
	SessionID string `json:"session_id"`
	Config    string `json:"config"`
}

type cachedConfigPayload struct {
	Config string `json:"config"`
	PeerIP string `json:"peer_ip"`
}

func (s *Server) configCachePath() string {
	return filepath.Join(s.settings.RebeccaDataDir, "xray-config-cache.json")
}

func (s *Server) saveConfigCache(rawConfig string, peerIP string) {
	if strings.TrimSpace(rawConfig) == "" {
		return
	}
	payload, err := json.Marshal(cachedConfigPayload{Config: rawConfig, PeerIP: peerIP})
	if err != nil {
		return
	}
	path := s.configCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("failed to create config cache directory: %v", err)
		return
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		log.Printf("failed to save config cache: %v", err)
	}
}

func (s *Server) loadConfigCache() (cachedConfigPayload, bool) {
	var payload cachedConfigPayload
	raw, err := os.ReadFile(s.configCachePath())
	if err != nil {
		return payload, false
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, false
	}
	if strings.TrimSpace(payload.Config) == "" {
		return payload, false
	}
	if strings.TrimSpace(payload.PeerIP) == "" {
		payload.PeerIP = "127.0.0.1"
	}
	return payload, true
}

func (s *Server) clearConfigCache() {
	if err := os.Remove(s.configCachePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("failed to clear config cache: %v", err)
	}
}

func (s *Server) startCachedConfig() {
	payload, ok := s.loadConfigCache()
	if !ok {
		return
	}
	cfg, err := xray.NewConfig(payload.Config, payload.PeerIP, s.settings)
	if err != nil {
		log.Printf("failed to decode cached config: %v", err)
		return
	}
	if err := s.core.Start(cfg); err != nil {
		log.Printf("failed to start cached config: %v", err)
		return
	}
	s.mu.Lock()
	s.lastConfig = cfg
	s.mu.Unlock()
}

type downloadFile struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (s *Server) readConfigPayload(w http.ResponseWriter, r *http.Request) (configPayload, bool) {
	var payload configPayload
	if !decodeJSON(w, r, &payload) {
		return payload, false
	}
	if !s.matchSession(w, payload.SessionID) {
		return payload, false
	}
	return payload, true
}

func (s *Server) matchRequestSession(w http.ResponseWriter, r *http.Request) bool {
	var payload struct {
		SessionID string `json:"session_id"`
	}
	if !decodeJSON(w, r, &payload) {
		return false
	}
	return s.matchSession(w, payload.SessionID)
}

func (s *Server) matchSession(w http.ResponseWriter, sessionID string) bool {
	if !s.sessionMatches(sessionID) {
		writeError(w, http.StatusForbidden, "Session ID mismatch.")
		return false
	}
	return true
}

func (s *Server) sessionMatches(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sessionID != "" && sessionID == s.sessionID
}

func (s *Server) currentClientIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientIP
}

func (s *Server) response(extra map[string]any) map[string]any {
	s.mu.Lock()
	connected := s.connected
	s.mu.Unlock()
	binaryMetadata := s.binaryMetadata()
	payload := map[string]any{
		"connected":    connected,
		"started":      s.core.Started(),
		"core_version": s.core.Version(),
		"node_version": s.settings.NodeVersion,
		"install_mode": s.settings.InstallMode,
	}
	if binaryMetadata != nil {
		payload["binary"] = binaryMetadata
		if tag, ok := binaryMetadata["tag"].(string); ok && strings.TrimSpace(tag) != "" {
			payload["node_binary_tag"] = tag
			payload["binary_tag"] = tag
			payload["update_channel"] = updateChannelForTag(tag)
		}
	}
	for key, value := range extra {
		payload[key] = value
	}
	return payload
}

func (s *Server) binaryMetadata() map[string]any {
	path := strings.TrimSpace(os.Getenv("REBECCA_NODE_BINARY_METADATA_FILE"))
	if path == "" {
		path = filepath.Join(s.settings.RebeccaDataDir, ".binary-release.json")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return nil
	}
	return metadata
}

func updateChannelForTag(tag string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(tag)), "dev-") {
		return "dev"
	}
	if strings.TrimSpace(tag) != "" {
		return "latest"
	}
	return "unknown"
}

func nodeUpdateArgs(channel string, version string) ([]string, error) {
	args := []string{"update"}
	normalizedVersion := strings.TrimSpace(version)
	normalizedChannel := strings.ToLower(strings.TrimSpace(channel))
	if normalizedVersion != "" {
		switch normalizedVersion {
		case "latest":
			return append(args, "--version", "latest"), nil
		case "dev":
			return append(args, "--dev"), nil
		default:
			if !releaseVersionPattern.MatchString(normalizedVersion) {
				return nil, errors.New("invalid update version")
			}
			return append(args, "--version", normalizedVersion), nil
		}
	}
	switch normalizedChannel {
	case "", "current", "auto":
		return args, nil
	case "dev":
		return append(args, "--dev"), nil
	case "latest", "stable", "release":
		return append(args, "--version", "latest"), nil
	default:
		return nil, errors.New("invalid update channel")
	}
}

func detectXrayAsset() (string, error) {
	if runtime.GOOS != "linux" {
		return "", errors.New("Unsupported platform for node")
	}
	switch runtime.GOARCH {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	case "arm":
		return "Xray-linux-arm32-v7a.zip", nil
	case "riscv64":
		return "Xray-linux-riscv64.zip", nil
	default:
		return "", errors.New("Unsupported platform for node")
	}
}

func validXrayVersion(version string) bool {
	return xrayVersionPattern.MatchString(strings.TrimSpace(version))
}

func safeGeoFilename(name string) string {
	base := filepath.Base(strings.TrimSpace(name))
	if _, ok := allowedGeoFiles[base]; !ok {
		return ""
	}
	return base
}

func validatePublicHTTPURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return errors.New("url must be a valid http(s) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("url must use http or https")
	}
	addresses, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return fmt.Errorf("url hostname cannot be resolved: %w", err)
	}
	for _, address := range addresses {
		if address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
			return errors.New("url resolves to a private or reserved address")
		}
	}
	return nil
}

func resolveNodeCLI(appName string) (string, error) {
	if configured := strings.TrimSpace(os.Getenv("REBECCA_NODE_SCRIPT_BIN")); configured != "" {
		if fileExists(configured) {
			return configured, nil
		}
	}
	candidates := []string{}
	if strings.TrimSpace(appName) != "" {
		candidates = append(candidates, appName, filepath.Join("/usr/local/bin", appName))
	}
	candidates = append(candidates, "rebecca-node", "/usr/local/bin/rebecca-node")
	for _, candidate := range candidates {
		if strings.Contains(candidate, string(filepath.Separator)) {
			if fileExists(candidate) {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", errors.New("unable to locate rebecca-node CLI on this host")
}

func installZipTo(zipBytes []byte, targetDir string) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return "", err
	}
	var executable string
	for _, file := range reader.File {
		cleanName := filepath.Clean(file.Name)
		if filepath.IsAbs(cleanName) || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) {
			return "", errors.New("unsafe path in Xray archive")
		}
		name := filepath.Base(cleanName)
		if name == "." || name == string(filepath.Separator) {
			continue
		}
		dst := filepath.Join(targetDir, name)
		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return "", err
			}
			continue
		}
		src, err := file.Open()
		if err != nil {
			return "", err
		}
		data, readErr := io.ReadAll(src)
		_ = src.Close()
		if readErr != nil {
			return "", readErr
		}
		if err := os.WriteFile(dst, data, file.FileInfo().Mode()); err != nil {
			return "", err
		}
		if name == executableName("xray") || name == "Xray" || name == "Xray.exe" {
			executable = dst
			_ = os.Chmod(dst, 0o755)
		}
	}
	if executable == "" {
		return "", errors.New("xray binary not found in archive")
	}
	return executable, nil
}

func tailFile(path string, maxLines int) ([]string, bool, error) {
	body, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return []string{}, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if maxLines <= 0 {
		return []string{}, true, nil
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines, true, nil
}

func download(url string, timeout time.Duration) ([]byte, error) {
	client := http.Client{Timeout: timeout}
	res, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("http status %d", res.StatusCode)
	}
	return io.ReadAll(res.Body)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	if r.Body == nil {
		writeError(w, http.StatusUnprocessableEntity, "Request body is required")
		return false
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(target); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, detail any) {
	writeJSON(w, status, map[string]any{"detail": detail})
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func executableName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func emptyDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0o755)
}

func newUUID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32]), nil
}
