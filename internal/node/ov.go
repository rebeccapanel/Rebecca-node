package node

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type ovRuntime struct {
	GeneratedAt     string              `json:"generated_at"`
	Target          string              `json:"target,omitempty"`
	SessionCallback *vpnSessionCallback `json:"session_callback,omitempty"`
	Inbounds        []ovRuntimeInbound  `json:"inbounds"`
}

type ovRuntimeInbound struct {
	Tag        string           `json:"tag"`
	TunnelTag  string           `json:"tunnel_tag"`
	Port       int              `json:"port"`
	Transport  string           `json:"transport"`
	TunnelPort int              `json:"tunnel_port"`
	Settings   map[string]any   `json:"settings"`
	Users      []vpnRuntimeUser `json:"users"`
}

type vpnRuntimeUser struct {
	UserID      int64  `json:"user_id"`
	Username    string `json:"username"`
	VPNUsername string `json:"vpn_username"`
	Password    string `json:"password"`
	IPv4Address string `json:"ipv4_address"`
	Status      string `json:"status"`
	UsedTraffic int64  `json:"used_traffic"`
	DataLimit   *int64 `json:"data_limit,omitempty"`
	Expire      *int64 `json:"expire,omitempty"`
	DeviceLimit int64  `json:"device_limit,omitempty"`
}

type ovManager struct {
	baseDir     string
	installMode string
	mu          sync.Mutex
}

const ovDCODataCiphers = "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"

type ovUserSnapshot struct {
	UserID      string
	Username    string
	UsedTraffic int64
	DataLimit   int64
}

type ovLiveSession struct {
	SessionID string
	Username  string
	UserID    string
	Total     int64
	Base      int64
	Limit     int64
}

type ovAccountingRecord struct {
	UserID string
	Total  int64
	Base   int64
}

func newOVManager(dataDir string, installMode string) *ovManager {
	return &ovManager{
		baseDir:     filepath.Join(dataDir, "openvpn"),
		installMode: strings.ToLower(strings.TrimSpace(installMode)),
	}
}

func (m *ovManager) Apply(runtimeConfig *ovRuntime) error {
	if m == nil {
		return nil
	}
	if runtimeConfig == nil {
		return nil
	}
	if len(runtimeConfig.Inbounds) > 0 && m.installMode != "binary" {
		return fmt.Errorf("OV is supported only on binary Rebecca-node installs")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(runtimeConfig.Inbounds) > 0 {
		if err := ensureOVPrerequisites(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(m.baseDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(runtimeConfig, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "runtime.json"), raw, 0o600); err != nil {
		return err
	}
	desired := make(map[string]struct{}, len(runtimeConfig.Inbounds))
	for _, inbound := range runtimeConfig.Inbounds {
		desired[safeName(inbound.Tag)] = struct{}{}
	}
	if err := m.pruneRemovedInbounds(desired); err != nil {
		return err
	}
	for _, inbound := range runtimeConfig.Inbounds {
		name := safeName(inbound.Tag)
		dir := filepath.Join(m.baseDir, name)
		oldConfig, _ := os.ReadFile(filepath.Join(dir, "server.conf"))
		wasRunning, _ := openvpnPIDRunning(filepath.Join(dir, "openvpn.pid"), filepath.Join(dir, "openvpn.log"))
		if err := validateOVDCOSettings(inbound); err != nil {
			return err
		}
		if boolValue(inbound.Settings["require_dco"], false) {
			if err := ensureOVDCOSupport(); err != nil {
				return fmt.Errorf("OV inbound %s requires DCO: %w", inbound.Tag, err)
			}
		}
		if err := m.writeInbound(inbound, runtimeConfig.SessionCallback); err != nil {
			return err
		}
		newConfig, _ := os.ReadFile(filepath.Join(dir, "server.conf"))
		restart := !wasRunning || string(oldConfig) != string(newConfig)
		if restart {
			m.stopInboundName(name)
		}
		if err := m.applyInbound(inbound, restart); err != nil {
			return err
		}
	}
	return nil
}

func (m *ovManager) currentRuntime() *ovRuntime {
	if m == nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(m.baseDir, "runtime.json"))
	if err != nil {
		return nil
	}
	var payload ovRuntime
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return &payload
}

func (m *ovManager) CollectUsage() []xray.UserStat {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	totals := map[userUsageKey]int64{}
	path := filepath.Join(m.baseDir, "usage.tsv")
	file, err := os.Open(path)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			parts := strings.Split(scanner.Text(), "\t")
			if len(parts) < 2 {
				continue
			}
			uid := strings.TrimSpace(parts[0])
			value, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			if uid == "" || value <= 0 {
				continue
			}
			inboundTag := ""
			if len(parts) >= 3 {
				encodedTag := strings.TrimSpace(parts[2])
				if strings.HasPrefix(encodedTag, "rb1_") {
					if decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encodedTag, "rb1_")); err == nil {
						inboundTag = string(decoded)
					}
				} else {
					inboundTag = encodedTag
				}
			}
			addUserUsage(totals, uid, inboundTag, value)
		}
		_ = os.WriteFile(path, nil, 0o600)
	}
	m.collectLiveUsageLocked(totals)
	return userUsageStats(totals)
}

func (m *ovManager) writeInbound(inbound ovRuntimeInbound, callback *vpnSessionCallback) error {
	name := safeName(inbound.Tag)
	dir := filepath.Join(m.baseDir, name)
	ccdDir := filepath.Join(dir, "ccd")
	if err := os.MkdirAll(ccdDir, 0o700); err != nil {
		return err
	}
	_, poolMask := ovNetworkMask(firstString(inbound.Settings["ipv4_pool_cidr"], "10.66.0.0/16"))
	usersPath := filepath.Join(dir, "users.tsv")
	if err := writeFileIfChanged(usersPath, []byte(vpnUsersTSV(inbound.Users)), 0o600); err != nil {
		return err
	}
	callbackPath := vpnSessionCallbackPath(dir)
	if err := writeVPNSessionCallback(callbackPath, callback); err != nil {
		return err
	}
	desiredCCD := map[string]struct{}{}
	for _, user := range inbound.Users {
		if strings.TrimSpace(user.VPNUsername) == "" || strings.TrimSpace(user.IPv4Address) == "" {
			continue
		}
		desiredCCD[safeName(user.VPNUsername)] = struct{}{}
		ccd := fmt.Sprintf("ifconfig-push %s %s\n", user.IPv4Address, poolMask)
		if err := writeFileIfChanged(filepath.Join(ccdDir, safeName(user.VPNUsername)), []byte(ccd), 0o600); err != nil {
			return err
		}
	}
	if entries, err := os.ReadDir(ccdDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if _, ok := desiredCCD[entry.Name()]; !ok {
				_ = os.Remove(filepath.Join(ccdDir, entry.Name()))
			}
		}
	}
	for path, content := range map[string]string{
		filepath.Join(dir, "auth.sh"):              authScript(usersPath, filepath.Join(m.baseDir, "usage.tsv"), callbackPath, vpnSessionsPath(m.baseDir), inbound.Tag),
		filepath.Join(dir, "client-disconnect.sh"): disconnectScript(usersPath, filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "accounting.tsv"), callbackPath, vpnSessionsPath(m.baseDir), inbound.Tag),
		filepath.Join(dir, "nftables.nft"):         nftScript(inbound, tunName(inbound.Tag)),
		filepath.Join(dir, "server.conf"):          serverConfig(inbound, dir, ccdDir),
	} {
		mode := os.FileMode(0o600)
		if strings.HasSuffix(path, ".sh") {
			mode = 0o700
		}
		if err := writeFileIfChanged(path, []byte(content), mode); err != nil {
			return err
		}
	}
	return nil
}

func (m *ovManager) applyInbound(inbound ovRuntimeInbound, restart bool) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := validateServerCredentials(inbound); err != nil {
		return err
	}
	name := safeName(inbound.Tag)
	dir := filepath.Join(m.baseDir, name)
	tproxyEnabled := inbound.TunnelPort > 0 && boolValue(inbound.Settings["tproxy_enabled"], true)
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.66.0.0/16")
	if tproxyEnabled {
		enableVPNTProxyHostNetworking(pool)
		nft, err := exec.LookPath("nft")
		if err != nil {
			return fmt.Errorf("nft executable not found")
		}
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_openvpn_"+safeName(inbound.Tag)).Run()
		if output, err := exec.Command(nft, "-f", filepath.Join(dir, "nftables.nft")).CombinedOutput(); err != nil {
			return fmt.Errorf("apply OV nftables %s: %v: %s", inbound.Tag, err, strings.TrimSpace(string(output)))
		}
		if err := applyTProxyRouting(); err != nil {
			return err
		}
		_ = vpnRemoveDirectNAT("openvpn-" + inbound.Tag)
	} else {
		if nft, err := exec.LookPath("nft"); err == nil {
			_ = exec.Command(nft, "delete", "table", "inet", "rebecca_openvpn_"+safeName(inbound.Tag)).Run()
		}
		if err := vpnApplyDirectNAT("openvpn-"+inbound.Tag, tunName(inbound.Tag), pool); err != nil {
			return fmt.Errorf("apply OV direct NAT %s: %w", inbound.Tag, err)
		}
	}
	if !restart {
		return nil
	}
	openvpn, err := exec.LookPath("openvpn")
	if err != nil {
		return fmt.Errorf("OV executable not found")
	}
	pidPath := filepath.Join(dir, "openvpn.pid")
	_ = os.Remove(filepath.Join(dir, "openvpn.log"))
	_ = os.Remove(filepath.Join(dir, "management.sock"))
	cmd := exec.Command(openvpn, "--config", filepath.Join(dir, "server.conf"), "--daemon", "rebecca-openvpn-"+name, "--writepid", pidPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("start OV %s: %v: %s", inbound.Tag, err, startOVErrorDetail(output, filepath.Join(dir, "openvpn.log")))
	}
	time.Sleep(500 * time.Millisecond)
	if running, detail := openvpnPIDRunning(pidPath, filepath.Join(dir, "openvpn.log")); !running {
		return fmt.Errorf("start OV %s: process stopped after launch: %s", inbound.Tag, detail)
	}
	if boolValue(inbound.Settings["require_dco"], false) {
		if reason := ovDCOInactiveReason(tailOVFile(filepath.Join(dir, "openvpn.log"), 8192)); reason != "" {
			m.stopInboundName(name)
			return fmt.Errorf("start OV %s: DCO was required but is inactive: %s", inbound.Tag, reason)
		}
	}
	return nil
}

func (m *ovManager) pruneRemovedInbounds(desired map[string]struct{}) error {
	entries, err := os.ReadDir(m.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if _, ok := desired[name]; ok {
			continue
		}
		m.stopInboundName(name)
		if err := os.RemoveAll(filepath.Join(m.baseDir, name)); err != nil {
			return err
		}
	}
	return nil
}

func (m *ovManager) stopInboundName(name string) {
	if runtime.GOOS == "windows" {
		return
	}
	dir := filepath.Join(m.baseDir, safeName(name))
	pidPath := filepath.Join(dir, "openvpn.pid")
	if raw, err := os.ReadFile(pidPath); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && pid > 1 {
			_ = exec.Command("kill", strconv.Itoa(pid)).Run()
			for range 40 {
				if !processAlive(pid) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if processAlive(pid) {
				_ = exec.Command("kill", "-KILL", strconv.Itoa(pid)).Run()
			}
		}
		_ = os.Remove(pidPath)
	}
	if nft, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_openvpn_"+safeName(name)).Run()
	}
	_ = vpnRemoveDirectNAT("openvpn-" + name)
	m.dropInboundSessions(name)
}

func (m *ovManager) dropInboundSessions(name string) {
	path := vpnSessionsPath(m.baseDir)
	tag := safeName(name)
	_ = withVPNSessionLock(path, func() {
		records := vpnSessionRecordsLocked(path)
		if len(records) == 0 {
			return
		}
		kept := make([][]string, 0, len(records))
		for _, record := range records {
			if len(record) >= 3 && record[1] == "ov" && record[2] == tag {
				continue
			}
			kept = append(kept, record)
		}
		vpnWriteSessionRecordsLocked(path, kept)
	})
}

func (m *ovManager) collectLiveUsageLocked(stats map[userUsageKey]int64) {
	accountingPath := filepath.Join(m.baseDir, "accounting.tsv")
	_ = withVPNFileLock(accountingPath+".lock", func() {
		records := readOVAccounting(accountingPath)
		tagByDir := map[string]string{}
		if runtimeConfig := m.currentRuntime(); runtimeConfig != nil {
			for _, inbound := range runtimeConfig.Inbounds {
				tagByDir[safeName(inbound.Tag)] = inbound.Tag
			}
		}
		if entries, err := os.ReadDir(m.baseDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				dir := filepath.Join(m.baseDir, entry.Name())
				inboundTag := tagByDir[entry.Name()]
				users := readOVUsers(filepath.Join(dir, "users.tsv"))
				for _, session := range readOVStatus(filepath.Join(dir, "status.log"), users) {
					record := records[session.SessionID]
					if record.UserID == "" {
						record.UserID = session.UserID
					}
					if record.Base <= 0 {
						record.Base = session.Base
					}
					if session.Total > record.Total {
						addUserUsage(stats, "openvpn:"+session.UserID, inboundTag, session.Total-record.Total)
					}
					record.Total = session.Total
					records[session.SessionID] = record
					if session.Limit > 0 && record.Base+session.Total >= session.Limit {
						killOVClient(dir, session.Username)
					}
				}
			}
		}
		writeOVAccounting(accountingPath, records)
	})
}

func readOVUsers(path string) map[string]ovUserSnapshot {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	users := map[string]ovUserSnapshot{}
	for _, lineText := range strings.Split(string(raw), "\n") {
		parts := strings.Split(strings.TrimSpace(lineText), "\t")
		if len(parts) < 6 {
			continue
		}
		used, _ := strconv.ParseInt(parts[4], 10, 64)
		limit, _ := strconv.ParseInt(parts[5], 10, 64)
		if parts[1] == "" || parts[0] == "" {
			continue
		}
		users[parts[1]] = ovUserSnapshot{
			UserID:      parts[0],
			Username:    parts[1],
			UsedTraffic: used,
			DataLimit:   limit,
		}
	}
	return users
}

func readOVStatus(path string, users map[string]ovUserSnapshot) []ovLiveSession {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	var sessions []ovLiveSession
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		if len(record) < 6 || record[0] != "CLIENT_LIST" {
			continue
		}
		user, ok := users[strings.TrimSpace(record[1])]
		if !ok {
			continue
		}
		rx, tx := ovStatusBytes(record)
		total := rx + tx
		if total <= 0 {
			continue
		}
		sessionID := safeName("ov:" + strings.TrimSpace(record[2]) + ":" + user.Username)
		sessions = append(sessions, ovLiveSession{
			SessionID: sessionID,
			Username:  user.Username,
			UserID:    user.UserID,
			Total:     total,
			Base:      user.UsedTraffic,
			Limit:     user.DataLimit,
		})
	}
	return sessions
}

func ovStatusBytes(record []string) (int64, int64) {
	if len(record) >= 7 {
		rx, rxErr := strconv.ParseInt(strings.TrimSpace(record[5]), 10, 64)
		tx, txErr := strconv.ParseInt(strings.TrimSpace(record[6]), 10, 64)
		if rxErr == nil && txErr == nil {
			return rx, tx
		}
	}
	rx, _ := strconv.ParseInt(strings.TrimSpace(record[4]), 10, 64)
	tx, _ := strconv.ParseInt(strings.TrimSpace(record[5]), 10, 64)
	return rx, tx
}

func readOVAccounting(path string) map[string]ovAccountingRecord {
	raw, err := os.ReadFile(path)
	if err != nil {
		return map[string]ovAccountingRecord{}
	}
	records := map[string]ovAccountingRecord{}
	for _, lineText := range strings.Split(string(raw), "\n") {
		parts := strings.Split(strings.TrimSpace(lineText), "\t")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			continue
		}
		total, _ := strconv.ParseInt(parts[2], 10, 64)
		base := int64(0)
		if len(parts) >= 4 {
			base, _ = strconv.ParseInt(parts[3], 10, 64)
		}
		records[parts[0]] = ovAccountingRecord{UserID: parts[1], Total: total, Base: base}
	}
	return records
}

func writeOVAccounting(path string, records map[string]ovAccountingRecord) {
	var b strings.Builder
	for session, record := range records {
		if session == "" || record.UserID == "" {
			continue
		}
		b.WriteString(session)
		b.WriteByte('\t')
		b.WriteString(record.UserID)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatInt(record.Total, 10))
		b.WriteByte('\t')
		b.WriteString(strconv.FormatInt(record.Base, 10))
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o600)
}

func killOVClient(dir string, username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		return
	}
	username = strings.NewReplacer("\r", "", "\n", "").Replace(username)
	conn, err := net.DialTimeout("unix", filepath.Join(dir, "management.sock"), 2*time.Second)
	if err != nil {
		if port := ovManagementPort(filepath.Join(dir, "server.conf")); port > 0 {
			conn, err = net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
		}
		if err != nil {
			return
		}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = fmt.Fprintf(conn, "kill %s\nquit\n", username)
}

func ovManagementPort(configPath string) int {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return 0
	}
	for _, lineText := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(lineText)
		if len(fields) >= 3 && fields[0] == "management" && fields[1] == "127.0.0.1" {
			port, _ := strconv.Atoi(fields[2])
			return port
		}
	}
	return 0
}

func serverConfig(inbound ovRuntimeInbound, dir string, ccdDir string) string {
	settings := inbound.Settings
	transport := strings.ToLower(firstString(settings["transport"], inbound.Transport, "udp"))
	if transport != "tcp" && transport != "udp" {
		transport = "udp"
	}
	pool := firstString(settings["ipv4_pool_cidr"], "10.66.0.0/16")
	network, mask := ovNetworkMask(pool)
	var b strings.Builder
	line(&b, "port "+strconv.Itoa(inbound.Port))
	if transport == "tcp" {
		line(&b, "proto tcp-server")
	} else {
		line(&b, "proto udp")
		if boolValue(settings["fast_io"], true) {
			line(&b, "fast-io")
		}
	}
	line(&b, "dev "+tunName(inbound.Tag))
	line(&b, "dev-type tun")
	line(&b, "topology subnet")
	line(&b, "server "+network+" "+mask)
	line(&b, "client-config-dir "+ccdDir)
	line(&b, "verify-client-cert none")
	line(&b, "username-as-common-name")
	line(&b, "duplicate-cn")
	line(&b, "script-security 3")
	line(&b, "auth-user-pass-verify "+filepath.Join(dir, "auth.sh")+" via-env")
	line(&b, "client-disconnect "+filepath.Join(dir, "client-disconnect.sh"))
	line(&b, "keepalive 10 300")
	line(&b, "persist-key")
	line(&b, "persist-tun")
	line(&b, "status-version 2")
	line(&b, "status "+filepath.Join(dir, "status.log")+" 5")
	line(&b, "log-append "+filepath.Join(dir, "openvpn.log"))
	line(&b, "verb 3")
	if boolValue(settings["redirect_gateway"], true) {
		line(&b, "push \"redirect-gateway def1\"")
	}
	line(&b, "push \"block-ipv6\"")
	for _, dns := range stringList(settings["dns_servers"]) {
		line(&b, "push \"dhcp-option DNS "+dns+"\"")
	}
	if cipher := firstString(settings["cipher"]); cipher != "" {
		line(&b, "cipher "+cipher)
	}
	if boolValue(settings["require_dco"], false) {
		line(&b, "data-ciphers "+ovDCODataCiphers)
	}
	if auth := firstString(settings["auth"]); auth != "" {
		line(&b, "auth "+auth)
	}
	if ca := firstString(settings["ca"]); ca != "" {
		inline(&b, "ca", ca)
	}
	if cert := firstString(settings["server_certificate"], settings["serverCertificate"]); cert != "" {
		inline(&b, "cert", cert)
	}
	if key := firstString(settings["server_key"], settings["serverKey"]); key != "" {
		inline(&b, "key", key)
	}
	if dh := firstString(settings["dh"]); dh != "" {
		inline(&b, "dh", dh)
	} else {
		line(&b, "dh none")
	}
	if tlsCrypt := firstString(settings["tls_crypt"]); tlsCrypt != "" {
		inline(&b, "tls-crypt", tlsCrypt)
	}
	if tlsAuth := firstString(settings["tls_auth"]); tlsAuth != "" {
		inline(&b, "tls-auth", tlsAuth)
		line(&b, "key-direction 0")
	}
	if managementPort := intValue(settings["management_port"]); managementPort > 0 {
		line(&b, "management 127.0.0.1 "+strconv.Itoa(managementPort))
	} else {
		line(&b, "management "+filepath.Join(dir, "management.sock")+" unix")
	}
	return b.String()
}

func nftScript(inbound ovRuntimeInbound, iface string) string {
	if inbound.TunnelPort <= 0 || !boolValue(inbound.Settings["tproxy_enabled"], true) {
		return ""
	}
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.66.0.0/16")
	blockedV4, blockedV6 := ovBlockedDestinations()
	var rules strings.Builder
	if len(blockedV4) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "%s" ip daddr { %s } drop`, iface, strings.Join(blockedV4, ", ")))
	}
	if len(blockedV6) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "%s" ip6 daddr { %s } drop`, iface, strings.Join(blockedV6, ", ")))
	}
	return fmt.Sprintf(`table inet rebecca_openvpn_%s {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
%s
    iifname "%s" meta mark != 0xff meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%d meta mark set 1 accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr %s oifname != "%s" meta l4proto icmp masquerade
  }
}
`, safeName(inbound.Tag), strings.TrimRight(rules.String(), "\n"), iface, inbound.TunnelPort, pool, iface)
}

func ensureOVPrerequisites() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	missing := missingExecutables("openvpn", "nft", "ip", "iptables")
	if len(missing) > 0 {
		if err := installOVPackages(); err != nil {
			return err
		}
	}
	for _, executable := range []string{"openvpn", "nft", "ip", "iptables"} {
		if _, err := exec.LookPath(executable); err != nil {
			return fmt.Errorf("OV prerequisite %s was not found after automatic install", executable)
		}
	}
	if modprobe, err := exec.LookPath("modprobe"); err == nil {
		_ = exec.Command(modprobe, "tun").Run()
		_ = exec.Command(modprobe, "nf_tproxy_ipv4").Run()
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("TUN device is unavailable: %w", err)
	}
	return nil
}

func missingExecutables(names ...string) []string {
	missing := []string{}
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			missing = append(missing, name)
		}
	}
	return missing
}

func installOVPackages() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("OV prerequisites are missing and automatic install requires root")
	}
	switch {
	case commandExists("apt-get"):
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
			return err
		}
		return runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "openvpn", "nftables", "iproute2", "iptables", "kmod")
	case commandExists("dnf"):
		return runInstallCommand(nil, "dnf", "install", "-y", "openvpn", "nftables", "iproute", "iptables", "kmod")
	case commandExists("yum"):
		return runInstallCommand(nil, "yum", "install", "-y", "openvpn", "nftables", "iproute", "iptables", "kmod")
	case commandExists("apk"):
		return runInstallCommand(nil, "apk", "add", "openvpn", "nftables", "iproute2", "iptables", "kmod")
	default:
		return fmt.Errorf("OV prerequisites are missing and no supported package manager was found")
	}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func runInstallCommand(env []string, name string, args ...string) error {
	command, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	args = noninteractivePackageArgs(filepath.Base(command), args)
	cmd := exec.Command(command, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func noninteractivePackageArgs(name string, args []string) []string {
	for _, arg := range args {
		if name == "apt-get" && arg == "install" {
			return append([]string{"-o", "Dpkg::Options::=--force-confold"}, args...)
		}
		if name == "dpkg" && arg == "--configure" {
			return append([]string{"--force-confold"}, args...)
		}
	}
	return args
}

func ovBlockedDestinations() ([]string, []string) {
	v4 := orderedSet("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16")
	v6 := orderedSet("::/128", "::1/128", "fc00::/7", "fe80::/10")
	ifaces, err := net.InterfaceAddrs()
	if err == nil {
		for _, item := range ifaces {
			prefix, err := netip.ParsePrefix(item.String())
			if err != nil {
				continue
			}
			addr := prefix.Addr()
			if addr.Is4() {
				v4.add(addr.String())
			} else if addr.Is6() {
				v6.add(addr.String())
			}
		}
	}
	return v4.values, v6.values
}

type stringSet struct {
	seen   map[string]struct{}
	values []string
}

func orderedSet(values ...string) *stringSet {
	set := &stringSet{seen: map[string]struct{}{}}
	for _, value := range values {
		set.add(value)
	}
	return set
}

func (s *stringSet) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if _, ok := s.seen[value]; ok {
		return
	}
	s.seen[value] = struct{}{}
	s.values = append(s.values, value)
}

func applyTProxyRouting() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	enableVPNTProxyHostNetworking()
	ip, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("ip executable not found")
	}
	if output, err := exec.Command(ip, "rule", "show").CombinedOutput(); err != nil {
		return fmt.Errorf("%s rule show: %v: %s", ip, err, strings.TrimSpace(string(output)))
	} else if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		if err := runCommandIgnoreExists(ip, "rule", "add", "fwmark", "1", "lookup", "100"); err != nil {
			return err
		}
	}
	if output, err := exec.Command(ip, "route", "show", "table", "100").CombinedOutput(); err != nil {
		if isMissingRouteTableOutput(output) {
			if err := runCommandIgnoreExists(ip, "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"); err != nil {
				return err
			}
			return nil
		}
		return fmt.Errorf("%s route show table 100: %v: %s", ip, err, strings.TrimSpace(string(output)))
	} else if strings.TrimSpace(string(output)) != "local default dev lo scope host" {
		if err := runCommandIgnoreExists(ip, "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"); err != nil {
			return err
		}
	}
	return nil
}

func isMissingRouteTableOutput(output []byte) bool {
	text := strings.ToLower(string(output))
	return strings.Contains(text, "fib table does not exist") ||
		strings.Contains(text, "dump terminated")
}

func runCommandIgnoreExists(command string, args ...string) error {
	output, err := exec.Command(command, args...).CombinedOutput()
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(string(output)), "file exists") {
		return nil
	}
	return fmt.Errorf("%s %s: %v: %s", command, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
}

func validateServerCredentials(inbound ovRuntimeInbound) error {
	settings := inbound.Settings
	if firstString(settings["ca"]) == "" {
		return fmt.Errorf("OV inbound %s requires ca", inbound.Tag)
	}
	if firstString(settings["server_certificate"], settings["serverCertificate"]) == "" {
		return fmt.Errorf("OV inbound %s requires server_certificate", inbound.Tag)
	}
	if firstString(settings["server_key"], settings["serverKey"]) == "" {
		return fmt.Errorf("OV inbound %s requires server_key", inbound.Tag)
	}
	return nil
}

func validateOVDCOSettings(inbound ovRuntimeInbound) error {
	if !boolValue(inbound.Settings["require_dco"], false) {
		return nil
	}
	if cipher := strings.TrimSpace(firstString(inbound.Settings["cipher"])); cipher != "" && !ovDCOCipherAllowed(cipher) {
		return fmt.Errorf("OV inbound %s requires DCO but cipher %s is not DCO-compatible", inbound.Tag, cipher)
	}
	if dataCiphers := strings.TrimSpace(firstString(inbound.Settings["data_ciphers"], inbound.Settings["data-ciphers"])); dataCiphers != "" {
		for _, cipher := range strings.Split(dataCiphers, ":") {
			if !ovDCOCipherAllowed(cipher) {
				return fmt.Errorf("OV inbound %s requires DCO but data cipher %s is not DCO-compatible", inbound.Tag, strings.TrimSpace(cipher))
			}
		}
	}
	return nil
}

func ovDCOCipherAllowed(cipher string) bool {
	switch strings.ToUpper(strings.TrimSpace(cipher)) {
	case "", "AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305":
		return true
	default:
		return false
	}
}

func ensureOVDCOSupport() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("DCO is only supported on Linux nodes")
	}
	loadOVDCOModules()
	if openvpnSupportsDCO() && ovDCOModuleAvailable() {
		return nil
	}
	if err := installOVDCOPackages(); err != nil {
		return err
	}
	loadOVDCOModules()
	if !openvpnSupportsDCO() {
		return fmt.Errorf("installed OpenVPN binary was built without DCO support")
	}
	if !ovDCOModuleAvailable() {
		return fmt.Errorf("kernel DCO module is unavailable after automatic install")
	}
	return nil
}

func openvpnSupportsDCO() bool {
	openvpn, err := exec.LookPath("openvpn")
	if err != nil {
		return false
	}
	output, err := exec.Command(openvpn, "--version").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(output)), "dco")
}

func ovDCOModuleAvailable() bool {
	for _, path := range []string{"/sys/module/ovpn", "/sys/module/ovpn_dco_v2", "/sys/module/ovpn_dco"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func loadOVDCOModules() {
	modprobe, err := exec.LookPath("modprobe")
	if err != nil {
		return
	}
	for _, module := range []string{"ovpn", "ovpn-dco-v2", "ovpn-dco"} {
		_ = exec.Command(modprobe, module).Run()
	}
}

func installOVDCOPackages() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("automatic DCO install requires root")
	}
	kernelRelease := strings.TrimSpace(commandOutput("uname", "-r"))
	switch {
	case commandExists("apt-get"):
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
			return err
		}
		if !aptPackageAvailable("openvpn-dco-dkms") {
			if err := configureOpenVPN26APTRepository(); err != nil {
				return err
			}
			if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
				return err
			}
		}
		packages := []string{"openvpn", "dkms", "openvpn-dco-dkms"}
		if kernelRelease != "" {
			packages = append([]string{"linux-headers-" + kernelRelease}, packages...)
		}
		args := append([]string{"install", "-y", "--no-install-recommends"}, packages...)
		return runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", args...)
	case commandExists("dnf"):
		packages := []string{"dkms", "openvpn-dco-dkms"}
		if kernelRelease != "" {
			packages = append([]string{"kernel-devel-" + kernelRelease}, packages...)
		}
		return runInstallCommand(nil, "dnf", append([]string{"install", "-y"}, packages...)...)
	case commandExists("yum"):
		packages := []string{"dkms", "openvpn-dco-dkms"}
		if kernelRelease != "" {
			packages = append([]string{"kernel-devel-" + kernelRelease}, packages...)
		}
		return runInstallCommand(nil, "yum", append([]string{"install", "-y"}, packages...)...)
	default:
		return fmt.Errorf("no supported package manager was found for DCO module install")
	}
}

func aptPackageAvailable(name string) bool {
	output, err := exec.Command("apt-cache", "policy", name).CombinedOutput()
	return err == nil && bytes.Contains(output, []byte("Candidate:")) && !bytes.Contains(output, []byte("Candidate: (none)"))
}

func configureOpenVPN26APTRepository() error {
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		return fmt.Errorf("OpenVPN DCO packages are unavailable for %s", runtime.GOARCH)
	}
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	codename := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VERSION_CODENAME=") {
			codename = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), `"'`)
			break
		}
	}
	if !map[string]bool{"bullseye": true, "bookworm": true, "trixie": true, "focal": true, "jammy": true, "noble": true}[codename] {
		return fmt.Errorf("OpenVPN DCO packages are unavailable for %s", codename)
	}
	key, err := download("https://swupdate.openvpn.net/repos/repo-public.gpg", 30*time.Second)
	if err != nil {
		return fmt.Errorf("download OpenVPN repository key: %w", err)
	}
	if err := os.MkdirAll("/etc/apt/keyrings", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/apt/keyrings/openvpn-repo-public.asc", key, 0o644); err != nil {
		return err
	}
	source := fmt.Sprintf("deb [arch=%s signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] https://build.openvpn.net/debian/openvpn/release/2.6 %s main\n", arch, codename)
	return os.WriteFile("/etc/apt/sources.list.d/openvpn-aptrepo.list", []byte(source), 0o644)
}

func ovDCOInactiveReason(logText string) string {
	lower := strings.ToLower(logText)
	for _, marker := range []string{
		"disabling data channel offload",
		"kernel support for ovpn-dco missing",
		"dco disabled",
		"cannot use dco",
		"dco will be disabled",
	} {
		if strings.Contains(lower, marker) {
			return marker
		}
	}
	return ""
}

func authScript(usersPath string, usagePath string, callbackPath string, sessionsPath string, inboundTag string) string {
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
USAGE=%q
MANAGEMENT="$(dirname "$USERS")/management.sock"
now=$(date +%%s)
%s
touch "$USAGE" 2>/dev/null || true
info=$(awk -F '\t' -v u="$username" -v p="$password" -v now="$now" '
  FILENAME == ARGV[1] {
    id=$1
    sub(/^openvpn:/, "", id)
    if (id != "" && $2 > 0) pending[id] += $2
    next
  }
  $2 == u && $3 == p && ($7 == "" || $7 == "active" || $7 == "on_hold") {
    used = $5 + pending[$1]
    if ($6 != "" && used >= $6) exit 2
    if ($8 != "" && now >= $8) exit 3
    print $1 "\t" $4 "\t" $9
    found=1
    exit 0
  }
  END { exit found ? 0 : 1 }
' "$USAGE" "$USERS") || exit 1
uid=$(printf '%%s' "$info" | awk -F '\t' '{print $1}')
assigned_ip=$(printf '%%s' "$info" | awk -F '\t' '{print $2}')
device_limit=$(printf '%%s' "$info" | awk -F '\t' '{print $3}')
remote_ip=${trusted_ip:-${untrusted_ip:-unknown}}
remote_port=${trusted_port:-${untrusted_port:-0}}
session=$(vpn_safe "ov:${remote_ip}:${remote_port}:${username}")
old_endpoint=$(awk -F '\t' -v uid="$uid" -v tag=%q -v sid="$session" -v ip="$assigned_ip" '
  $1 == uid && $2 == "ov" && $3 == tag && $4 != sid && $5 == ip && $8 ~ /^[0-9]+$/ {
    if (index($6, ":")) print "[" $6 "]:" $8; else print $6 ":" $8
    exit
  }
' "$VPN_SESSIONS" 2>/dev/null)
vpn_admit "$uid" "ov" %q "$session" "$assigned_ip" "$remote_ip" "$device_limit" "$remote_port" || exit 1
if [ -n "$old_endpoint" ] && [ -S "$MANAGEMENT" ] && command -v curl >/dev/null 2>&1; then
  (printf 'kill %%s\nquit\n' "$old_endpoint" | curl -sS -N --max-time 5 --unix-socket "$MANAGEMENT" -T - telnet://localhost >/dev/null 2>&1 || true) &
fi
`, usersPath, usagePath, vpnSessionShell(callbackPath, sessionsPath), safeName(inboundTag), safeName(inboundTag))
}

func disconnectScript(usersPath string, usagePath string, accountingPath string, callbackPath string, sessionsPath string, inboundTag string) string {
	encodedInboundTag := "rb1_" + base64.RawURLEncoding.EncodeToString([]byte(inboundTag))
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
USAGE=%q
INBOUND_TAG=%q
ACCOUNTING=%q
ACCOUNTING_LOCK="${ACCOUNTING}.lock"
%s
info=$(awk -F '\t' -v u="$username" '$2 == u { print $1 "\t" $4; exit }' "$USERS")
uid=$(printf '%%s' "$info" | awk -F '\t' '{print $1}')
assigned_ip=$(printf '%%s' "$info" | awk -F '\t' '{print $2}')
rx=${bytes_received:-0}
tx=${bytes_sent:-0}
total=$((rx + tx))
remote_ip=${trusted_ip:-${untrusted_ip:-unknown}}
remote_port=${trusted_port:-${untrusted_port:-0}}
session=$(vpn_safe "ov:${remote_ip}:${remote_port}:${username}")
if [ -n "$uid" ] && [ "$total" -gt 0 ]; then
  mkdir -p "$(dirname "$ACCOUNTING")"
  touch "$ACCOUNTING"
  (
    flock -x 9 || exit 0
    previous=$(awk -F '\t' -v sid="$session" '$1 == sid { print $3; found=1; exit } END { if (!found) print 0 }' "$ACCOUNTING")
    case "$previous" in ''|*[!0-9]*) previous=0 ;; esac
    delta=$((total - previous))
    if [ "$delta" -gt 0 ]; then
      printf 'openvpn:%%s\t%%s\t%%s\n' "$uid" "$delta" "$INBOUND_TAG" >> "$USAGE"
    fi
    tmp="${ACCOUNTING}.$$"
    awk -F '\t' -v sid="$session" '$1 != sid { print }' "$ACCOUNTING" > "$tmp"
    mv "$tmp" "$ACCOUNTING"
    chmod 600 "$ACCOUNTING"
  ) 9>"$ACCOUNTING_LOCK"
fi
vpn_release "$uid" "ov" %q "$session" "$assigned_ip" "$remote_ip"
`, usersPath, usagePath, encodedInboundTag, accountingPath, vpnSessionShell(callbackPath, sessionsPath), safeName(inboundTag))
}

func vpnUsersTSV(users []vpnRuntimeUser) string {
	var b strings.Builder
	for _, user := range users {
		limit := ""
		if user.DataLimit != nil {
			limit = strconv.FormatInt(*user.DataLimit, 10)
		}
		expire := ""
		if user.Expire != nil {
			expire = strconv.FormatInt(*user.Expire, 10)
		}
		fields := []string{
			strconv.FormatInt(user.UserID, 10),
			user.VPNUsername,
			user.Password,
			user.IPv4Address,
			strconv.FormatInt(user.UsedTraffic, 10),
			limit,
			user.Status,
			expire,
			strconv.FormatInt(user.DeviceLimit, 10),
		}
		b.WriteString(strings.Join(fields, "\t"))
		b.WriteByte('\n')
	}
	return b.String()
}

func writeFileIfChanged(path string, content []byte, mode os.FileMode) error {
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(current, content) {
		return os.Chmod(path, mode)
	}
	return os.WriteFile(path, content, mode)
}

func ovNetworkMask(cidr string) (string, string) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil || !prefix.Addr().Is4() {
		return "10.66.0.0", "255.255.0.0"
	}
	bits := prefix.Bits()
	mask := netip.PrefixFrom(netip.AddrFrom4([4]byte{255, 255, 255, 255}), bits).Masked().Addr().As4()
	return prefix.Masked().Addr().String(), fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func tunName(tag string) string {
	sum := sha1.Sum([]byte(tag))
	return "rbov" + hex.EncodeToString(sum[:])[:8]
}

func safeName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "openvpn"
	}
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "openvpn"
	}
	return out
}

func line(b *strings.Builder, value string) {
	b.WriteString(value)
	b.WriteByte('\n')
}

func inline(b *strings.Builder, name string, content string) {
	line(b, "<"+name+">")
	b.WriteString(strings.TrimSpace(content))
	b.WriteByte('\n')
	line(b, "</"+name+">")
}

func startOVErrorDetail(output []byte, logPath string) string {
	parts := []string{}
	if text := strings.TrimSpace(string(output)); text != "" {
		parts = append(parts, text)
	}
	if text := tailOVFile(logPath, 4096); text != "" {
		parts = append(parts, text)
	}
	if len(parts) == 0 {
		return "no output"
	}
	return strings.Join(parts, "\n")
}

func openvpnPIDRunning(pidPath string, logPath string) (bool, string) {
	raw, err := os.ReadFile(pidPath)
	if err != nil {
		return false, startOVErrorDetail(nil, logPath)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 1 {
		return false, startOVErrorDetail(nil, logPath)
	}
	if err := exec.Command("kill", "-0", strconv.Itoa(pid)).Run(); err != nil {
		return false, startOVErrorDetail(nil, logPath)
	}
	return true, ""
}

func tailOVFile(path string, limit int) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return ""
	}
	if limit > 0 && len(raw) > limit {
		raw = raw[len(raw)-limit:]
	}
	return strings.TrimSpace(string(raw))
}

func firstString(values ...any) string {
	for _, value := range values {
		text := strings.TrimSpace(fmt.Sprint(value))
		if text != "" && text != "<nil>" {
			return text
		}
	}
	return ""
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := firstString(item); text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		parts := strings.FieldsFunc(typed, func(r rune) bool {
			return r == ',' || r == '\n' || r == '\r'
		})
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if text := strings.TrimSpace(part); text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		if text := firstString(value); text != "" {
			return []string{text}
		}
		return nil
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func boolValue(value any, fallback bool) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	}
	return fallback
}
