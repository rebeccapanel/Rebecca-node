package node

import (
	"fmt"
	"os/exec"
	"path/filepath"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"golang.zx2c4.com/wireguard/wgctrl"
)

func protocolState(protocol string, configured, running int, version string) *nodev1.ProtocolStatus {
	state := "idle"
	if configured > 0 {
		state = "stopped"
	}
	if running == configured && configured > 0 {
		state = "running"
	} else if running > 0 {
		state = "error"
	}
	detail := ""
	if configured > 0 {
		detail = fmt.Sprintf("%d/%d running", running, configured)
	}
	return &nodev1.ProtocolStatus{Protocol: protocol, State: state, Detail: detail, Inbounds: uint32(configured), Version: version}
}

func (s *Server) protocolStatuses() []*nodev1.ProtocolStatus {
	s.mu.Lock()
	config := s.lastConfig
	s.mu.Unlock()
	xrayInbounds := 0
	if config != nil {
		xrayInbounds = config.InboundCount()
	}
	xrayRunning := 0
	if s.core.Started() {
		xrayRunning = xrayInbounds
	}
	statuses := []*nodev1.ProtocolStatus{protocolState("xray", xrayInbounds, xrayRunning, s.core.Version())}

	ovConfigured, ovRunning := 0, 0
	if s.ov != nil {
		if configured := s.ov.currentRuntime(); configured != nil {
			ovConfigured = len(configured.Inbounds)
			for _, inbound := range configured.Inbounds {
				dir := filepath.Join(s.ov.baseDir, safeName(inbound.Tag))
				if ok, _ := openvpnPIDRunning(filepath.Join(dir, "openvpn.pid"), filepath.Join(dir, "openvpn.log")); ok {
					ovRunning++
				}
			}
		}
	}
	statuses = append(statuses, protocolState("openvpn", ovConfigured, ovRunning, ""))

	l2tpConfigured, l2tpRunning := 0, 0
	if s.l2tp != nil {
		if configured := s.l2tp.currentRuntime(); configured != nil {
			l2tpConfigured = len(configured.Inbounds)
			if l2tpConfigured > 0 && l2tpServicesRunning() {
				l2tpRunning = l2tpConfigured
			}
		}
	}
	statuses = append(statuses, protocolState("l2tp", l2tpConfigured, l2tpRunning, ""))

	pptpConfigured, pptpRunning := 0, 0
	if s.pptp != nil {
		if configured := s.pptp.currentRuntime(); configured != nil {
			pptpConfigured = len(configured.Inbounds)
			if pptpConfigured > 0 && pptpServiceRunning() {
				pptpRunning = pptpConfigured
			}
		}
	}
	statuses = append(statuses, protocolState("pptp", pptpConfigured, pptpRunning, ""))

	wgConfigured, wgRunning := 0, 0
	if s.wg != nil {
		if configured := s.wg.currentRuntime(); configured != nil {
			wgConfigured = len(configured.Inbounds)
			wgRunning = runningWireGuardInbounds(configured)
		}
	}
	statuses = append(statuses, protocolState("wireguard", wgConfigured, wgRunning, ""))

	for _, protocol := range []string{"ikev2", "anyconnect"} {
		configuredCount, running := 0, 0
		if s.remoteAccess != nil {
			configured := s.remoteAccess.runtimeConfig(protocol)
			if configured != nil {
				configuredCount = len(configured.Inbounds)
				if protocol == "ikev2" {
					if configuredCount > 0 && (exec.Command("pgrep", "-x", "charon").Run() == nil || exec.Command("pgrep", "-x", "charon-systemd").Run() == nil) {
						running = configuredCount
					}
				} else {
					for _, inbound := range configured.Inbounds {
						if anyConnectRunning(filepath.Join(s.remoteAccess.baseDir, protocol, safeName(inbound.Tag))) {
							running++
						}
					}
				}
			}
		}
		statuses = append(statuses, protocolState(protocol, configuredCount, running, ""))
	}

	haproxyConfigured, haproxyRunning := 0, 0
	haproxyError := ""
	if s.haproxy != nil {
		haproxyError = s.haproxy.lastErrorMessage()
		if configured := s.cachedHAProxyRuntime(); configured != nil {
			if configured.Enabled {
				haproxyConfigured = 1
			}
			if haproxyConfigured > 0 && processExists(readPID(filepath.Join(s.haproxy.dir, "haproxy.pid"))) {
				haproxyRunning = 1
			}
		}
	}
	haproxyStatus := protocolState("haproxy", haproxyConfigured, haproxyRunning, "")
	if haproxyError != "" {
		if haproxyStatus.Detail != "" {
			haproxyStatus.Detail += "; "
		}
		haproxyStatus.Detail += "last error: " + haproxyError
	}
	statuses = append(statuses, haproxyStatus)
	sshConfigured, sshRunning := 0, 0
	if s.sshProxy != nil {
		sshConfigured, sshRunning = s.sshProxy.State()
	}
	statuses = append(statuses, protocolState("ssh", sshConfigured, sshRunning, ""))
	for _, protocol := range []string{"mtproto", "web"} {
		configured, running := 0, 0
		if s.external != nil {
			configured, running = s.external.State(protocol)
		}
		statuses = append(statuses, protocolState(protocol, configured, running, ""))
	}
	for _, protocol := range []string{"sstp", "amneziawg", "gre"} {
		configured, running := 0, 0
		if s.extraVPN != nil {
			configured, running = s.extraVPN.State(protocol)
		}
		statuses = append(statuses, protocolState(protocol, configured, running, ""))
	}
	return statuses
}

func runningWireGuardInbounds(runtime *wgRuntime) int {
	if runtime == nil || len(runtime.Inbounds) == 0 {
		return 0
	}
	client, err := wgctrl.New()
	if err != nil {
		return 0
	}
	defer client.Close()
	running := 0
	for _, inbound := range runtime.Inbounds {
		if _, err := client.Device(wgIfaceName(inbound.Tag)); err == nil {
			running++
		}
	}
	return running
}
