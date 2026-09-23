package node

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
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

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	settings     appconfig.Settings
	core         *xray.Core
	ov           *ovManager
	l2tp         *l2tpManager
	pptp         *pptpManager
	wg           *wgManager
	remoteAccess *remoteAccessManager
	haproxy      *haproxyManager
	sshProxy     *sshProxyManager
	external     *externalProxyManager
	extraVPN     *extraVPNManager
	ipBlocks     *sourceIPBlocker
	usage        *usageBuffer
	system       *systemSampler
	operations   *operationDeduper

	mu         sync.Mutex
	connected  bool
	clientIP   string
	sessions   map[string]time.Time
	lastConfig *xray.Config

	// runtimeMu serializes whole runtime operations (start/restart/stop/sync and
	// user add/update/remove) so two concurrent pushes from the master can never
	// interleave a core restart, a config-cache write, or a VPN apply. It is a
	// separate lock from mu (which only guards session/connection state) and is
	// taken only at the public entry points, never in the internal helpers they
	// call, so the operations do not deadlock on themselves.
	runtimeMu sync.Mutex

	userStatsMu sync.Mutex
	userStatsAt time.Time
}

const sessionTTL = 30 * time.Minute

var xrayVersionPattern = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:[-+._A-Za-z0-9]*)?$`)
var releaseVersionPattern = regexp.MustCompile(`^v?\d+(?:\.\d+){1,3}(?:[-+._A-Za-z0-9]*)?$`)
var allowedGeoFiles = map[string]struct{}{"geoip.dat": {}, "geosite.dat": {}}
var xrayCoreDownloadBaseURLs = []string{"https://github.com/XTLS/Xray-core/releases/download"}
var validateXrayCoreDownloadURL = validatePublicHTTPURL

func New(settings appconfig.Settings) (*Server, error) {
	core, err := xray.NewCore(settings.XrayExecutablePath, settings.XrayAssetsPath, settings.Debug)
	if err != nil {
		return nil, err
	}
	usage, err := newPersistentUsageBuffer(filepath.Join(settings.RebeccaDataDir, "usage-spool.json"))
	if err != nil {
		log.Printf("failed to load usage spool, starting with an empty usage buffer: %v", err)
		usage = newUsageBuffer()
	}
	server := &Server{
		settings:     settings,
		core:         core,
		ov:           newOVManager(settings.RebeccaDataDir, settings.InstallMode),
		l2tp:         newL2TPManager(settings.RebeccaDataDir, settings.InstallMode),
		pptp:         newPPTPManager(settings.RebeccaDataDir, settings.InstallMode),
		wg:           newWGManager(settings.RebeccaDataDir, settings.InstallMode),
		remoteAccess: newRemoteAccessManager(settings.RebeccaDataDir, settings.InstallMode),
		haproxy:      newHAProxyManager(settings.RebeccaDataDir),
		sshProxy:     newSSHProxyManager(settings.RebeccaDataDir),
		ipBlocks:     newSourceIPBlocker(settings.RebeccaDataDir, settings.InstallMode),
		usage:        usage,
		system:       newSystemSampler(),
		operations:   newOperationDeduper(filepath.Join(settings.RebeccaDataDir, "operation-receipts.json")),
		sessions:     make(map[string]time.Time),
	}
	server.external = newExternalProxyManager(settings.RebeccaDataDir, server.updateChannel)
	server.extraVPN = newExtraVPNManager(settings.RebeccaDataDir, settings.InstallMode, server.updateChannel)
	// Auxiliary VPN state is authoritative on the master. Never resurrect stale
	// WireGuard peers from disk while waiting for the first full sync.
	if err := server.wg.Apply(&wgRuntime{Inbounds: []wgRuntimeInbound{}}); err != nil {
		log.Printf("failed to clear cached WireGuard runtime on startup: %v", err)
	}
	if err := server.startCachedConfig(false); err != nil {
		log.Printf("failed to start cached runtime: %v", err)
	}
	return server, nil
}

func (s *Server) snapshotRunningUsage() {
	if stats := s.ov.CollectUsage(); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if stats := s.l2tp.CollectUsage(); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if stats := s.pptp.CollectUsage(); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if stats := s.wg.CollectUsage(); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if stats := s.remoteAccess.CollectUsage("ikev2"); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if stats := s.remoteAccess.CollectUsage("anyconnect"); len(stats) > 0 {
		s.usage.addUsers(stats)
	}
	if s.sshProxy != nil {
		if stats := s.sshProxy.CollectUsage(); len(stats) > 0 {
			s.usage.addUsers(stats)
		}
	}
	if s.extraVPN != nil {
		if stats := s.extraVPN.CollectUsage(); len(stats) > 0 {
			s.usage.addUsers(stats)
		}
	}
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
	inboundStats, err := xray.QueryInboundStats(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		5*time.Second,
		true,
	)
	if err == nil {
		s.usage.addInbound(inboundStats)
	} else {
		log.Printf("failed to snapshot inbound usage before stopping xray: %v", err)
	}
	userStats, _, err := s.collectXrayUserStats(5*time.Second, true)
	if err == nil {
		s.usage.addUsers(userStats)
	} else {
		log.Printf("failed to snapshot user usage before stopping xray: %v", err)
	}
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

func scheduleHostReboot() error {
	if runtime.GOOS == "windows" {
		return errors.New("host reboot is supported only on Linux")
	}
	reboot, err := exec.LookPath("reboot")
	if err != nil {
		reboot = "/sbin/reboot"
	}
	command := fmt.Sprintf("sleep 1; %s", reboot)
	if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
		unit := fmt.Sprintf("rebecca-node-host-reboot-%d", time.Now().UnixNano())
		return exec.Command(systemdRun, "--unit", unit, "--collect", "--description", "Rebecca-node host reboot", "--", "sh", "-c", command).Start()
	}
	return exec.Command("sh", "-c", command).Start()
}

type cachedConfigPayload struct {
	AppliedRevision   uint64               `json:"applied_revision,omitempty"`
	Config            string               `json:"config"`
	PeerIP            string               `json:"peer_ip"`
	OVRuntime         *ovRuntime           `json:"ov_runtime,omitempty"`
	L2TPRuntime       *l2tpRuntime         `json:"l2tp_runtime,omitempty"`
	PPTPRuntime       *pptpRuntime         `json:"pptp_runtime,omitempty"`
	WGRuntime         *wgRuntime           `json:"wg_runtime,omitempty"`
	IKEv2Runtime      *remoteAccessRuntime `json:"ikev2_runtime,omitempty"`
	AnyConnectRuntime *remoteAccessRuntime `json:"anyconnect_runtime,omitempty"`
	HAProxyRuntime    *haproxyRuntime      `json:"haproxy_runtime,omitempty"`
	ExtraRuntime      *extraRuntime        `json:"extra_runtime,omitempty"`
}

func (s *Server) configCachePath() string {
	return filepath.Join(s.settings.RebeccaDataDir, "xray-config-cache.json")
}

func (s *Server) saveConfigCache(rawConfig string, peerIP string, runtimeConfig *ovRuntime, l2tpRuntimeConfig *l2tpRuntime, pptpRuntimeConfig *pptpRuntime, wgRuntimeConfig *wgRuntime, remoteRuntimes ...*remoteAccessRuntime) {
	s.saveConfigCacheWithHAProxy(rawConfig, peerIP, runtimeConfig, l2tpRuntimeConfig, pptpRuntimeConfig, wgRuntimeConfig, s.cachedHAProxyRuntime(), s.cachedExtraRuntime(), remoteRuntimes...)
}

func (s *Server) saveConfigCacheWithHAProxy(rawConfig string, peerIP string, runtimeConfig *ovRuntime, l2tpRuntimeConfig *l2tpRuntime, pptpRuntimeConfig *pptpRuntime, wgRuntimeConfig *wgRuntime, haproxyRuntimeConfig *haproxyRuntime, extraRuntimeConfig *extraRuntime, remoteRuntimes ...*remoteAccessRuntime) {
	if strings.TrimSpace(rawConfig) == "" {
		return
	}
	var ikev2Runtime, anyConnectRuntime *remoteAccessRuntime
	if len(remoteRuntimes) > 0 {
		ikev2Runtime = remoteRuntimes[0]
	}
	if len(remoteRuntimes) > 1 {
		anyConnectRuntime = remoteRuntimes[1]
	}
	appliedRevision := uint64(0)
	if cached, ok := s.loadConfigCache(); ok {
		appliedRevision = cached.AppliedRevision
	}
	payload, err := json.Marshal(cachedConfigPayload{AppliedRevision: appliedRevision, Config: rawConfig, PeerIP: peerIP, OVRuntime: runtimeConfig, L2TPRuntime: l2tpRuntimeConfig, PPTPRuntime: pptpRuntimeConfig, WGRuntime: wgRuntimeConfig, IKEv2Runtime: ikev2Runtime, AnyConnectRuntime: anyConnectRuntime, HAProxyRuntime: haproxyRuntimeConfig, ExtraRuntime: extraRuntimeConfig})
	if err != nil {
		return
	}
	path := s.configCachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		log.Printf("failed to create config cache directory: %v", err)
		return
	}
	if err := writeFileAtomic(path, payload, 0o600); err != nil {
		log.Printf("failed to save config cache: %v", err)
	}
}

func (s *Server) appliedRevision() uint64 {
	payload, ok := s.loadConfigCache()
	if !ok {
		return 0
	}
	return payload.AppliedRevision
}

func (s *Server) setAppliedRevision(revision uint64) {
	if revision == 0 {
		return
	}
	payload, ok := s.loadConfigCache()
	if !ok || revision <= payload.AppliedRevision {
		return
	}
	payload.AppliedRevision = revision
	raw, err := json.Marshal(payload)
	if err != nil {
		return
	}
	if err := writeFileAtomic(s.configCachePath(), raw, 0o600); err != nil {
		log.Printf("failed to save applied revision: %v", err)
	}
}

func (s *Server) validateDesiredRevision(req *nodev1.RuntimeConfigRequest) error {
	if req == nil || req.GetDesiredRevision() == 0 {
		return nil
	}
	if applied := s.appliedRevision(); req.GetDesiredRevision() < applied {
		return status.Errorf(codes.FailedPrecondition, "stale desired revision %d; node already applied %d", req.GetDesiredRevision(), applied)
	}
	return nil
}

func (s *Server) recordAppliedRevision(req *nodev1.RuntimeConfigRequest, err error) {
	if err == nil && req != nil {
		s.setAppliedRevision(req.GetDesiredRevision())
	}
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rebecca-cache-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err = tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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

func (s *Server) cachedOVRuntime() *ovRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.OVRuntime
}

func (s *Server) cachedL2TPRuntime() *l2tpRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.L2TPRuntime
}

func (s *Server) cachedPPTPRuntime() *pptpRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.PPTPRuntime
}

func (s *Server) cachedWGRuntime() *wgRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.WGRuntime
}

func (s *Server) cachedIKEv2Runtime() *remoteAccessRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.IKEv2Runtime
}

func (s *Server) cachedAnyConnectRuntime() *remoteAccessRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.AnyConnectRuntime
}

func (s *Server) cachedHAProxyRuntime() *haproxyRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.HAProxyRuntime
}

func (s *Server) cachedExtraRuntime() *extraRuntime {
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	return payload.ExtraRuntime
}

func (s *Server) applyL2TPRuntime(runtimeConfig *l2tpRuntime) string {
	if err := s.l2tp.Apply(runtimeConfig); err != nil {
		warning := "L2TP runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyPPTPRuntime(runtimeConfig *pptpRuntime) string {
	if err := s.pptp.Apply(runtimeConfig); err != nil {
		warning := "PPTP runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyWGRuntime(runtimeConfig *wgRuntime) string {
	if err := s.wg.Apply(runtimeConfig); err != nil {
		warning := "WireGuard runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyIKEv2Runtime(runtimeConfig *remoteAccessRuntime) string {
	if err := s.remoteAccess.ApplyIKEv2(runtimeConfig); err != nil {
		warning := "IKEv2 runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) prepareIKEv2Runtime(runtimeConfig *remoteAccessRuntime) string {
	if runtimeConfig == nil || len(runtimeConfig.Inbounds) == 0 {
		return ""
	}
	if err := ensureIKEv2Prerequisites(); err != nil {
		warning := "IKEv2 prerequisite preparation failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyAnyConnectRuntime(runtimeConfig *remoteAccessRuntime) string {
	if err := s.remoteAccess.ApplyAnyConnect(runtimeConfig); err != nil {
		warning := "AnyConnect runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyHAProxyRuntime(runtimeConfig *haproxyRuntime) string {
	if s.haproxy == nil {
		if runtimeConfig == nil || !runtimeConfig.Enabled {
			return ""
		}
		return "HAProxy runtime apply failed: HAProxy manager is unavailable"
	}
	if err := s.haproxy.Apply(runtimeConfig); err != nil {
		warning := "HAProxy runtime apply failed: " + err.Error()
		log.Print(warning)
		return warning
	}
	return ""
}

func (s *Server) applyExtraRuntime(runtimeConfig *extraRuntime) string {
	warnings := []string{}
	hasSSH, hasExternal, hasExtraVPN := false, false, false
	if runtimeConfig != nil {
		for _, inbound := range runtimeConfig.Inbounds {
			switch strings.ToLower(strings.TrimSpace(inbound.Protocol)) {
			case "ssh":
				hasSSH = true
			case "mtproto", "web":
				hasExternal = true
			case "sstp", "amneziawg", "gre":
				hasExtraVPN = true
			}
		}
	}
	if s.sshProxy == nil {
		if hasSSH {
			warnings = append(warnings, "SSH runtime apply failed: SSH manager is unavailable")
		}
	} else if err := s.sshProxy.Apply(runtimeConfig); err != nil {
		warning := "SSH runtime apply failed: " + err.Error()
		log.Print(warning)
		warnings = append(warnings, warning)
	}
	if s.external == nil {
		if hasExternal {
			warnings = append(warnings, "external proxy runtime apply failed: manager is unavailable")
		}
	} else if err := s.external.Apply(runtimeConfig); err != nil {
		warning := "external proxy runtime apply failed: " + err.Error()
		log.Print(warning)
		warnings = append(warnings, warning)
	}
	if s.extraVPN == nil {
		if hasExtraVPN {
			warnings = append(warnings, "extra VPN runtime apply failed: manager is unavailable")
		}
	} else if err := s.extraVPN.Apply(runtimeConfig); err != nil {
		warning := "extra VPN runtime apply failed: " + err.Error()
		log.Print(warning)
		warnings = append(warnings, warning)
	}
	return joinedWarnings(warnings...)
}

func joinedWarnings(values ...string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			parts = append(parts, value)
		}
	}
	return strings.Join(parts, "; ")
}

func (s *Server) clearConfigCache() {
	if err := os.Remove(s.configCachePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("failed to clear config cache: %v", err)
	}
}

func (s *Server) startCachedConfig(restart bool) error {
	payload, ok := s.loadConfigCache()
	if !ok {
		s.clearCachedAuxiliaryRuntimes()
		if restart {
			return errors.New("runtime config cache is unavailable; sync config first")
		}
		return nil
	}
	if err := s.reconcileManagedProxyServices(context.Background(), payload.Config); err != nil {
		log.Printf("managed proxy reconciliation failed: %v", err)
		return err
	}
	cfg, err := xray.NewConfig(payload.Config, payload.PeerIP, s.settings)
	if err != nil {
		log.Printf("failed to decode cached config: %v", err)
		if warning := s.applyHAProxyRuntime(payload.HAProxyRuntime); warning != "" {
			log.Print(warning)
		}
		return err
	}
	prepareTProxyConfig(cfg)
	if restart {
		err = s.core.Restart(cfg)
	} else {
		err = s.core.Start(cfg)
	}
	if err != nil {
		log.Printf("failed to start cached config: %v", err)
		if warning := s.applyHAProxyRuntime(payload.HAProxyRuntime); warning != "" {
			log.Print(warning)
		}
		return err
	}
	s.mu.Lock()
	s.lastConfig = cfg
	s.mu.Unlock()
	if err := s.ov.Apply(payload.OVRuntime); err != nil {
		log.Printf("OpenVPN cached runtime apply failed: %v", err)
	}
	s.prepareIKEv2Runtime(payload.IKEv2Runtime)
	s.applyL2TPRuntime(payload.L2TPRuntime)
	s.applyPPTPRuntime(payload.PPTPRuntime)
	s.applyWGRuntime(payload.WGRuntime)
	s.applyIKEv2Runtime(payload.IKEv2Runtime)
	s.applyAnyConnectRuntime(payload.AnyConnectRuntime)
	s.applyHAProxyRuntime(payload.HAProxyRuntime)
	s.applyExtraRuntime(payload.ExtraRuntime)
	return nil
}

// clearCachedAuxiliaryRuntimes prevents a missing/removed cache from leaving
// native protocol daemons alive after Rebecca-node restarts.
func (s *Server) clearCachedAuxiliaryRuntimes() {
	if err := s.reconcileManagedProxyServices(context.Background(), "{}"); err != nil {
		log.Printf("managed proxy startup cleanup failed: %v", err)
	}
	if err := s.ov.Apply(&ovRuntime{Inbounds: []ovRuntimeInbound{}}); err != nil {
		log.Printf("OpenVPN startup cleanup failed: %v", err)
	}
	if err := s.l2tp.Apply(&l2tpRuntime{Inbounds: []l2tpRuntimeInbound{}}); err != nil {
		log.Printf("L2TP startup cleanup failed: %v", err)
	}
	if err := s.pptp.Apply(&pptpRuntime{Inbounds: []pptpRuntimeInbound{}}); err != nil {
		log.Printf("PPTP startup cleanup failed: %v", err)
	}
	if err := s.wg.Apply(&wgRuntime{Inbounds: []wgRuntimeInbound{}}); err != nil {
		log.Printf("WireGuard startup cleanup failed: %v", err)
	}
	if err := s.remoteAccess.ApplyIKEv2(&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}}); err != nil {
		log.Printf("IKEv2 startup cleanup failed: %v", err)
	}
	if err := s.remoteAccess.ApplyAnyConnect(&remoteAccessRuntime{Inbounds: []remoteAccessRuntimeInbound{}}); err != nil {
		log.Printf("AnyConnect startup cleanup failed: %v", err)
	}
	if s.haproxy != nil {
		if err := s.haproxy.Apply(&haproxyRuntime{}); err != nil {
			log.Printf("HAProxy startup cleanup failed: %v", err)
		}
	}
	if s.sshProxy != nil {
		if err := s.sshProxy.Apply(&extraRuntime{}); err != nil {
			log.Printf("SSH startup cleanup failed: %v", err)
		}
	}
	if s.external != nil {
		if err := s.external.Apply(&extraRuntime{}); err != nil {
			log.Printf("external proxy startup cleanup failed: %v", err)
		}
	}
	if s.extraVPN != nil {
		if err := s.extraVPN.Apply(&extraRuntime{}); err != nil {
			log.Printf("extra VPN startup cleanup failed: %v", err)
		}
	}
	if err := s.ipBlocks.Clear(context.Background()); err != nil {
		log.Printf("source IP startup cleanup failed: %v", err)
	}
}

type downloadFile struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

func (s *Server) sessionMatches(sessionID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sessionID == "" {
		return false
	}
	now := time.Now()
	s.pruneSessionsLocked(now)
	if _, ok := s.sessions[sessionID]; !ok {
		return false
	}
	s.sessions[sessionID] = now
	s.connected = true
	return true
}

func (s *Server) currentClientIP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientIP
}

func (s *Server) addSession(sessionID string, clientIP string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.sessions == nil {
		s.sessions = make(map[string]time.Time)
	}
	s.pruneSessionsLocked(now)
	s.connected = true
	s.clientIP = clientIP
	s.sessions[sessionID] = now
}

func (s *Server) pruneSessionsLocked(now time.Time) {
	for sessionID, seenAt := range s.sessions {
		if now.Sub(seenAt) > sessionTTL {
			delete(s.sessions, sessionID)
		}
	}
	if len(s.sessions) == 0 {
		s.connected = false
	}
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

func (s *Server) nodeVersion() string {
	if metadata := s.binaryMetadata(); metadata != nil {
		if tag, ok := metadata["tag"].(string); ok && strings.TrimSpace(tag) != "" {
			return strings.TrimSpace(tag)
		}
	}
	return s.settings.NodeVersion
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
			if strings.HasPrefix(strings.ToLower(normalizedVersion), "dev-") {
				return append(args, "--version", normalizedVersion), nil
			}
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
	return xrayVersionPattern.MatchString(normalizeXrayVersion(version))
}

func normalizeXrayVersion(version string) string {
	version = strings.TrimSpace(version)
	if version != "" && !strings.HasPrefix(strings.ToLower(version), "v") {
		return "v" + version
	}
	return version
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Rebecca-node")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
		return nil, fmt.Errorf("http status %d: %s", res.StatusCode, summarizeDownloadBody(body))
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.ContentLength >= 0 && int64(len(body)) != res.ContentLength {
		return nil, fmt.Errorf("incomplete download: received %d of %d bytes", len(body), res.ContentLength)
	}
	return body, nil
}

func downloadXrayCoreArchive(version string, asset string, timeout time.Duration) ([]byte, error) {
	urls := xrayCoreDownloadURLs(version, asset)
	failures := make([]string, 0, len(urls))
	for _, candidate := range urls {
		if err := validateXrayCoreDownloadURL(candidate); err != nil {
			failures = append(failures, candidate+": "+err.Error())
			continue
		}
		body, err := download(candidate, timeout)
		if err != nil {
			failures = append(failures, candidate+": "+err.Error())
			continue
		}
		if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
			failures = append(failures, candidate+": invalid Xray archive: "+summarizeDownloadBody(body))
			continue
		}
		return body, nil
	}
	return nil, errors.New(strings.Join(failures, "; "))
}

func xrayCoreDownloadURLs(version string, asset string) []string {
	version = strings.TrimSpace(version)
	asset = strings.TrimSpace(asset)
	bases := make([]string, 0, len(xrayCoreDownloadBaseURLs)+1)
	if custom := strings.TrimSpace(os.Getenv("XRAY_CORE_DOWNLOAD_BASE_URL")); custom != "" {
		bases = append(bases, custom)
	}
	bases = append(bases, xrayCoreDownloadBaseURLs...)
	urls := make([]string, 0, len(bases))
	seen := map[string]struct{}{}
	for _, base := range bases {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		candidate := base + "/" + version + "/" + asset
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		urls = append(urls, candidate)
	}
	return urls
}

func summarizeDownloadBody(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return "empty response"
	}
	lower := strings.ToLower(text)
	if strings.HasPrefix(lower, "<!doctype html") || strings.HasPrefix(lower, "<html") {
		return "HTML error page from upstream"
	}
	text = strings.Join(strings.Fields(text), " ")
	if len(text) > 240 {
		text = text[:240] + "..."
	}
	return text
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
