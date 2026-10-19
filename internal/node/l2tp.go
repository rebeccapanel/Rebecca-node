package node

import (
	"bufio"
	"encoding/json"
	"fmt"
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

const (
	l2tpFixedIPSecIKEPort = 500
	l2tpFixedIPSecNATPort = 4500
	l2tpFixedPort         = 1701
	l2tpFixedTunnelPort   = 1702
)

type l2tpRuntime struct {
	GeneratedAt     string               `json:"generated_at"`
	Target          string               `json:"target,omitempty"`
	SessionCallback *vpnSessionCallback  `json:"session_callback,omitempty"`
	Inbounds        []l2tpRuntimeInbound `json:"inbounds"`
}

type l2tpRuntimeInbound struct {
	Tag        string           `json:"tag"`
	TunnelTag  string           `json:"tunnel_tag"`
	Port       int              `json:"port"`
	TunnelPort int              `json:"tunnel_port"`
	Settings   map[string]any   `json:"settings"`
	Users      []vpnRuntimeUser `json:"users"`
}

type l2tpManager struct {
	baseDir     string
	installMode string
	mu          sync.Mutex
}

func newL2TPManager(dataDir string, installMode string) *l2tpManager {
	return &l2tpManager{
		baseDir:     filepath.Join(dataDir, "l2tp"),
		installMode: strings.ToLower(strings.TrimSpace(installMode)),
	}
}

func (m *l2tpManager) Apply(runtimeConfig *l2tpRuntime) error {
	if m == nil || runtimeConfig == nil {
		return nil
	}
	if len(runtimeConfig.Inbounds) > 0 && m.installMode != "binary" {
		return fmt.Errorf("L2TP/IPsec is supported only on binary Rebecca-node installs")
	}
	if len(runtimeConfig.Inbounds) > 1 {
		return fmt.Errorf("only one L2TP/IPsec inbound is supported per node because IPsec UDP 500/4500 are node-wide ports")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(runtimeConfig.Inbounds) > 0 {
		if err := ensureL2TPPrerequisites(); err != nil {
			return err
		}
		runtimeConfig.Inbounds[0] = normalizeL2TPRuntimeInbound(runtimeConfig.Inbounds[0])
	}
	if err := os.MkdirAll(m.baseDir, 0o700); err != nil {
		return err
	}
	previousUsersFingerprint := ""
	if previous := m.currentRuntime(); previous != nil && len(previous.Inbounds) > 0 {
		previousUsersFingerprint = l2tpUsersFingerprint(previous.Inbounds[0].Users)
	}
	raw, err := json.MarshalIndent(runtimeConfig, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "runtime.json"), raw, 0o600); err != nil {
		return err
	}
	if len(runtimeConfig.Inbounds) == 0 {
		m.stop()
		return nil
	}
	inbound := runtimeConfig.Inbounds[0]
	if err := m.writeInbound(inbound, runtimeConfig.SessionCallback); err != nil {
		return err
	}
	if previousUsersFingerprint == "" || previousUsersFingerprint != l2tpUsersFingerprint(inbound.Users) {
		m.disconnectStaleSessions(inbound.Users)
	}
	return m.applyInbound(inbound)
}

func (m *l2tpManager) currentRuntime() *l2tpRuntime {
	if m == nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(m.baseDir, "runtime.json"))
	if err != nil {
		return nil
	}
	var payload l2tpRuntime
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return &payload
}

func (m *l2tpManager) CollectUsage() []xray.UserStat {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inboundTag := ""
	if runtimeConfig := m.currentRuntime(); runtimeConfig != nil && len(runtimeConfig.Inbounds) > 0 {
		inboundTag = runtimeConfig.Inbounds[0].Tag
	}
	stats := map[string]int64{}
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
			stats[uid] += value
		}
		_ = os.WriteFile(path, nil, 0o600)
	}
	collectPPPLiveUsage(m.baseDir, "l2tp", stats)
	out := make([]xray.UserStat, 0, len(stats))
	for uid, value := range stats {
		out = append(out, xray.UserStat{UID: uid, Value: value, InboundTag: inboundTag})
	}
	return out
}

func (m *l2tpManager) writeInbound(inbound l2tpRuntimeInbound, callback *vpnSessionCallback) error {
	inbound = normalizeL2TPRuntimeInbound(inbound)
	if err := os.MkdirAll(m.baseDir, 0o700); err != nil {
		return err
	}
	callbackPath := vpnSessionCallbackPath(m.baseDir)
	if err := writeVPNSessionCallback(callbackPath, callback); err != nil {
		return err
	}
	usersPath := filepath.Join(m.baseDir, "users.tsv")
	if err := os.WriteFile(usersPath, []byte(vpnUsersTSV(inbound.Users)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "nftables.nft"), []byte(l2tpNFTScript(inbound)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "ip-down.sh"), []byte(l2tpIPDownScript(usersPath, filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "accounting.tsv"), filepath.Join(m.baseDir, "sessions.tsv"), callbackPath, vpnSessionsPath(m.baseDir), inbound.Tag)), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "ip-up.sh"), []byte(l2tpIPUpScript(usersPath, filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "sessions.tsv"), callbackPath, vpnSessionsPath(m.baseDir), inbound.Tag)), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "options.xl2tpd"), []byte(l2tpPPPOptions(inbound)), 0o600); err != nil {
		return err
	}
	return nil
}

func (m *l2tpManager) applyInbound(inbound l2tpRuntimeInbound) error {
	inbound = normalizeL2TPRuntimeInbound(inbound)
	if runtime.GOOS == "windows" {
		return nil
	}
	if strings.TrimSpace(firstString(inbound.Settings["ipsec_psk"])) == "" {
		return fmt.Errorf("L2TP inbound %s requires ipsec_psk", inbound.Tag)
	}
	beforeSystemConfig := l2tpSystemConfigSnapshot()
	tproxyEnabled := inbound.TunnelPort > 0 && boolValue(inbound.Settings["tproxy_enabled"], true)
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.67.0.0/16")
	if tproxyEnabled {
		enableVPNTProxyHostNetworking(pool)
		nft, err := exec.LookPath("nft")
		if err != nil {
			return fmt.Errorf("nft executable not found")
		}
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_l2tp").Run()
		if output, err := exec.Command(nft, "-f", filepath.Join(m.baseDir, "nftables.nft")).CombinedOutput(); err != nil {
			return fmt.Errorf("apply L2TP nftables %s: %v: %s", inbound.Tag, err, strings.TrimSpace(string(output)))
		}
		if err := applyTProxyRouting(); err != nil {
			return err
		}
		_ = vpnRemoveDirectNAT("l2tp")
	} else {
		if nft, err := exec.LookPath("nft"); err == nil {
			_ = exec.Command(nft, "delete", "table", "inet", "rebecca_l2tp").Run()
		}
		if err := vpnApplyDirectNAT("l2tp", "ppp+", pool); err != nil {
			return fmt.Errorf("apply L2TP direct NAT %s: %w", inbound.Tag, err)
		}
	}
	if err := m.writeSystemConfig(inbound); err != nil {
		return err
	}
	if beforeSystemConfig != l2tpSystemConfigSnapshot() || !l2tpServicesRunning() {
		return restartL2TPServices()
	}
	return nil
}

func (m *l2tpManager) stop() {
	if runtime.GOOS == "windows" {
		return
	}
	_ = updateManagedBlock("/etc/ipsec.conf", "# BEGIN REBECCA L2TP IPSEC", "# END REBECCA L2TP IPSEC", "")
	_ = updateManagedBlock("/etc/ipsec.secrets", "# BEGIN REBECCA L2TP IPSEC", "# END REBECCA L2TP IPSEC", "")
	_ = runOptional("ipsec", "rereadsecrets")
	_ = runOptional("ipsec", "reload")
	stopL2TPService()
	if nft, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_l2tp").Run()
	}
	_ = vpnRemoveDirectNAT("l2tp")
	_ = os.WriteFile(filepath.Join(m.baseDir, "sessions.tsv"), nil, 0o600)
}

func (m *l2tpManager) writeSystemConfig(inbound l2tpRuntimeInbound) error {
	inbound = normalizeL2TPRuntimeInbound(inbound)
	settings := inbound.Settings
	psk := firstString(settings["ipsec_psk"])
	localIP, ipRange := l2tpPoolRange(firstString(settings["ipv4_pool_cidr"], "10.67.0.0/16"))
	ipsecBlock := l2tpIPSecConfig(l2tpFixedPort)
	if err := updateManagedBlock("/etc/ipsec.conf", "# BEGIN REBECCA L2TP IPSEC", "# END REBECCA L2TP IPSEC", ipsecBlock); err != nil {
		return fmt.Errorf("update /etc/ipsec.conf: %w", err)
	}
	if err := updateManagedBlock("/etc/ipsec.secrets", "# BEGIN REBECCA L2TP IPSEC", "# END REBECCA L2TP IPSEC", fmt.Sprintf("%%any %%any : PSK %q\n", psk)); err != nil {
		return fmt.Errorf("update /etc/ipsec.secrets: %w", err)
	}
	if err := os.MkdirAll("/etc/xl2tpd", 0o755); err != nil {
		return err
	}
	xl2tpd := fmt.Sprintf(`[global]
port = %d
access control = no

[lns rebecca-l2tp]
lac = 0.0.0.0 - 255.255.255.255
ip range = %s
local ip = %s
pppoptfile = %s
length bit = yes
`, l2tpFixedPort, ipRange, localIP, filepath.Join(m.baseDir, "options.xl2tpd"))
	if err := os.WriteFile("/etc/xl2tpd/xl2tpd.conf", []byte(xl2tpd), 0o600); err != nil {
		return fmt.Errorf("write /etc/xl2tpd/xl2tpd.conf: %w", err)
	}
	if err := updateManagedBlock("/etc/ppp/chap-secrets", "# BEGIN REBECCA L2TP USERS", "# END REBECCA L2TP USERS", l2tpChapSecrets(inbound.Users)); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/ppp/ip-up.d", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/ppp/ip-up.d/rebecca-l2tp-sessions", []byte(l2tpIPUpScript(filepath.Join(m.baseDir, "users.tsv"), filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "sessions.tsv"), vpnSessionCallbackPath(m.baseDir), vpnSessionsPath(m.baseDir), inbound.Tag)), 0o700); err != nil {
		return fmt.Errorf("write /etc/ppp/ip-up.d/rebecca-l2tp-sessions: %w", err)
	}
	if err := os.MkdirAll("/etc/ppp/ip-down.d", 0o755); err != nil {
		return err
	}
	return os.WriteFile("/etc/ppp/ip-down.d/rebecca-l2tp-accounting", []byte(l2tpIPDownScript(filepath.Join(m.baseDir, "users.tsv"), filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "accounting.tsv"), filepath.Join(m.baseDir, "sessions.tsv"), vpnSessionCallbackPath(m.baseDir), vpnSessionsPath(m.baseDir), inbound.Tag)), 0o700)
}

func l2tpIPSecConfig(l2tpPort int) string {
	if l2tpIPSecImplementation() == "libreswan" {
		return l2tpLibreswanConfig(l2tpPort)
	}
	return fmt.Sprintf(`conn rebecca-l2tp
  auto=add
  keyexchange=ikev1
  authby=secret
  type=transport
  left=%%any
  leftprotoport=17/%d
  right=%%any
  rightprotoport=17/%%any
  rekey=no
  forceencaps=yes
  fragmentation=yes
  ike=aes256-sha2_256-modp2048,aes128-sha2_256-modp2048,aes256-sha1-modp2048,aes128-sha1-modp2048,3des-sha1-modp2048!
  esp=aes256-sha2_256,aes128-sha2_256,aes256-sha1,aes128-sha1,3des-sha1!
`, l2tpPort)
}

func l2tpLibreswanConfig(l2tpPort int) string {
	major, minor, ok := libreswanVersion()
	ikev1PolicySupported := ok && (major > 4 || (major == 4 && minor >= 2))
	keyexchangeV1 := ok && major >= 5
	ike := "aes256-sha2;modp2048,aes128-sha2;modp2048,aes256-sha1;modp2048,aes128-sha1;modp2048,3des-sha1;modp2048," +
		"aes256-sha2;modp1536,aes128-sha2;modp1536,aes256-sha1;modp1536,aes128-sha1;modp1536,3des-sha1;modp1536,3des-md5;modp1536," +
		"aes256-sha2;dh20,aes256-sha2;dh19,aes128-sha2;dh19"
	if ipsecSupportsModp1024() {
		ike += ",aes256-sha2;modp1024,aes128-sha2;modp1024,aes256-sha1;modp1024,aes128-sha1;modp1024,3des-sha1;modp1024,3des-md5;modp1024"
	}
	var b strings.Builder
	line(&b, "config setup")
	line(&b, "  uniqueids=no")
	if ikev1PolicySupported {
		line(&b, "  ikev1-policy=accept")
	}
	line(&b, "")
	line(&b, "conn rebecca-l2tp-nat")
	line(&b, "  rightsubnet=vhost:%no,%priv")
	line(&b, "  also=rebecca-l2tp")
	line(&b, "")
	line(&b, "conn rebecca-l2tp")
	line(&b, "  auto=add")
	line(&b, fmt.Sprintf("  leftprotoport=17/%d", l2tpPort))
	line(&b, "  rightprotoport=17/%any")
	line(&b, "  type=transport")
	line(&b, "  authby=secret")
	line(&b, "  encapsulation=yes")
	line(&b, "  pfs=no")
	line(&b, "  rekey=no")
	line(&b, "  dpddelay=40")
	line(&b, "  dpdtimeout=130")
	if keyexchangeV1 {
		line(&b, "  keyexchange=ikev1")
	} else {
		line(&b, "  keyexchange=ike")
		line(&b, "  ikev2=no")
	}
	line(&b, "  ike="+ike)
	line(&b, "  phase2alg=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,3des-sha1,aes256-md5,aes128-md5,3des-md5")
	line(&b, "  left=%defaultroute")
	line(&b, "  right=%any")
	return b.String()
}

func l2tpIPSecImplementation() string {
	version := strings.ToLower(commandOutput("ipsec", "--version"))
	if strings.Contains(version, "libreswan") {
		return "libreswan"
	}
	return "strongswan"
}

func libreswanVersion() (int, int, bool) {
	version := strings.ToLower(commandOutput("ipsec", "--version"))
	if !strings.Contains(version, "libreswan") {
		return 0, 0, false
	}
	for _, field := range strings.Fields(version) {
		field = strings.Trim(field, "v,;()[]")
		parts := strings.Split(field, ".")
		if len(parts) < 2 {
			continue
		}
		major, err1 := strconv.Atoi(parts[0])
		minor, err2 := strconv.Atoi(parts[1])
		if err1 == nil && err2 == nil {
			return major, minor, true
		}
	}
	return 0, 0, false
}

func ipsecSupportsModp1024() bool {
	if l2tpIPSecImplementation() != "libreswan" {
		return false
	}
	output, _ := exec.Command("ipsec", "pluto", "--selftest").CombinedOutput()
	return strings.Contains(strings.ToUpper(string(output)), "MODP1024")
}

func l2tpPPPOptions(inbound l2tpRuntimeInbound) string {
	inbound = normalizeL2TPRuntimeInbound(inbound)
	var b strings.Builder
	line(&b, "ipcp-accept-local")
	line(&b, "ipcp-accept-remote")
	dnsServers := stringList(inbound.Settings["dns_servers"])
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1"}
	}
	for _, dns := range dnsServers {
		line(&b, "ms-dns "+dns)
	}
	line(&b, "asyncmap 0")
	line(&b, "auth")
	line(&b, "require-mschap-v2")
	line(&b, "noccp")
	line(&b, "noipv6")
	line(&b, "name rebecca-l2tp")
	if mtu := boundedInt(inbound.Settings["mtu"], 1410, 576, 1500); mtu > 0 {
		line(&b, fmt.Sprintf("mtu %d", mtu))
	}
	if mru := boundedInt(inbound.Settings["mru"], 1410, 576, 1500); mru > 0 {
		line(&b, fmt.Sprintf("mru %d", mru))
	}
	line(&b, fmt.Sprintf("lcp-echo-interval %d", boundedInt(inbound.Settings["lcp_echo_interval"], 30, 1, 3600)))
	line(&b, fmt.Sprintf("lcp-echo-failure %d", boundedInt(inbound.Settings["lcp_echo_failure"], 4, 1, 20)))
	line(&b, "ipparam rebecca-l2tp")
	return b.String()
}

func boundedInt(value any, fallback int, min int, max int) int {
	parsed := intValue(value)
	if parsed < min || parsed > max {
		return fallback
	}
	return parsed
}

func l2tpChapSecrets(users []vpnRuntimeUser) string {
	var b strings.Builder
	now := time.Now().Unix()
	for _, user := range users {
		if strings.TrimSpace(user.VPNUsername) == "" || strings.TrimSpace(user.Password) == "" || !runtimeUserAvailable(user.Status, user.UsedTraffic, user.DataLimit, user.Expire, now) {
			continue
		}
		line(&b, fmt.Sprintf("%q rebecca-l2tp %q %s", user.VPNUsername, user.Password, firstString(user.IPv4Address, "*")))
	}
	return b.String()
}

func l2tpUsersFingerprint(users []vpnRuntimeUser) string {
	var b strings.Builder
	for _, user := range users {
		b.WriteString(strconv.FormatInt(user.UserID, 10))
		b.WriteByte('\t')
		b.WriteString(user.VPNUsername)
		b.WriteByte('\t')
		b.WriteString(user.Password)
		b.WriteByte('\t')
		b.WriteString(user.IPv4Address)
		b.WriteByte('\t')
		b.WriteString(user.Status)
		b.WriteByte('\t')
		if user.DataLimit != nil {
			b.WriteString(strconv.FormatInt(*user.DataLimit, 10))
		}
		b.WriteByte('\t')
		if user.Expire != nil {
			b.WriteString(strconv.FormatInt(*user.Expire, 10))
		}
		b.WriteByte('\t')
		b.WriteString(strconv.FormatInt(user.DeviceLimit, 10))
		b.WriteByte('\n')
	}
	return b.String()
}

func l2tpNFTScript(inbound l2tpRuntimeInbound) string {
	inbound = normalizeL2TPRuntimeInbound(inbound)
	if inbound.TunnelPort <= 0 || !boolValue(inbound.Settings["tproxy_enabled"], true) {
		return ""
	}
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.67.0.0/16")
	blockedV4, blockedV6 := ovBlockedDestinations()
	var rules strings.Builder
	if len(blockedV4) > 0 {
		line(&rules, fmt.Sprintf(`    ip saddr %s ip daddr { %s } drop`, pool, strings.Join(blockedV4, ", ")))
	}
	if len(blockedV6) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "ppp*" ip6 daddr { %s } drop`, strings.Join(blockedV6, ", ")))
	}
	return fmt.Sprintf(`table inet rebecca_l2tp {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
%s
    ip saddr %s meta mark != 0xff meta l4proto { tcp, udp } tproxy ip to 127.0.0.1:%d meta mark set 1 accept
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr %s meta l4proto icmp masquerade
  }
}
`, strings.TrimRight(rules.String(), "\n"), pool, inbound.TunnelPort, pool)
}

func normalizeL2TPRuntimeInbound(inbound l2tpRuntimeInbound) l2tpRuntimeInbound {
	if inbound.Settings == nil {
		inbound.Settings = map[string]any{}
	}
	inbound.Port = l2tpFixedPort
	inbound.TunnelPort = l2tpFixedTunnelPort
	inbound.Settings["l2tp_port"] = l2tpFixedPort
	inbound.Settings["ipsec_ike_port"] = l2tpFixedIPSecIKEPort
	inbound.Settings["ipsec_nat_port"] = l2tpFixedIPSecNATPort
	inbound.Settings["tunnel_port"] = l2tpFixedTunnelPort
	delete(inbound.Settings, "xray_tunnel_port")
	delete(inbound.Settings, "tproxy_port")
	delete(inbound.Settings, "management_port")
	return inbound
}

func (m *l2tpManager) disconnectStaleSessions(users []vpnRuntimeUser) {
	if runtime.GOOS == "windows" {
		return
	}
	allowed := map[string]struct{}{}
	now := time.Now().Unix()
	for _, user := range users {
		username := strings.TrimSpace(user.VPNUsername)
		if username != "" && runtimeUserAvailable(user.Status, user.UsedTraffic, user.DataLimit, user.Expire, now) {
			allowed[username] = struct{}{}
		}
	}
	sessionsPath := filepath.Join(m.baseDir, "sessions.tsv")
	raw, err := os.ReadFile(sessionsPath)
	if err != nil {
		return
	}
	var kept strings.Builder
	for _, lineText := range strings.Split(string(raw), "\n") {
		lineText = strings.TrimSpace(lineText)
		if lineText == "" {
			continue
		}
		parts := strings.Split(lineText, "\t")
		if len(parts) < 2 {
			continue
		}
		username := strings.TrimSpace(parts[0])
		if _, ok := allowed[username]; ok {
			kept.WriteString(lineText)
			kept.WriteByte('\n')
			continue
		}
		if len(parts) >= 3 {
			killL2TPProcess(strings.TrimSpace(parts[2]))
		}
		deleteL2TPInterface(strings.TrimSpace(parts[1]))
	}
	_ = os.WriteFile(sessionsPath, []byte(kept.String()), 0o600)
}

func killL2TPProcess(pid string) {
	if pid == "" {
		return
	}
	if _, err := strconv.Atoi(pid); err != nil {
		return
	}
	_ = exec.Command("kill", "-TERM", pid).Run()
}

func deleteL2TPInterface(ifname string) {
	if ifname == "" || strings.ContainsAny(ifname, "/ \t\r\n") {
		return
	}
	if ip, err := exec.LookPath("ip"); err == nil {
		_ = exec.Command(ip, "link", "delete", ifname).Run()
	}
}

var pppNetStatRoot = "/sys/class/net"

type pppUserSnapshot struct {
	UserID      string
	Username    string
	UsedTraffic int64
	DataLimit   int64
}

type pppSessionSnapshot struct {
	Username string
	IFName   string
	PID      string
}

func collectPPPLiveUsage(baseDir string, protocol string, stats map[string]int64) {
	users := readPPPUsers(filepath.Join(baseDir, "users.tsv"))
	if len(users) == 0 {
		return
	}
	sessions := readPPPSessions(filepath.Join(baseDir, "sessions.tsv"))
	if len(sessions) == 0 {
		return
	}
	accountingPath := filepath.Join(baseDir, "accounting.tsv")
	_ = withVPNFileLock(accountingPath+".lock", func() {
		records := readOVAccounting(accountingPath)
		active := map[string]struct{}{}
		for _, session := range sessions {
			user, ok := users[session.Username]
			if !ok {
				continue
			}
			total, ok := pppInterfaceBytes(session.IFName)
			if !ok || total <= 0 {
				continue
			}
			sessionID := pppSessionID(protocol, session.PID, session.IFName, session.Username)
			active[sessionID] = struct{}{}
			record := records[sessionID]
			if record.UserID == "" {
				record.UserID = user.UserID
			}
			if record.Base <= 0 {
				record.Base = user.UsedTraffic
			}
			if total > record.Total {
				stats[protocol+":"+user.UserID] += total - record.Total
			}
			record.Total = total
			records[sessionID] = record
			if user.DataLimit > 0 && record.Base+total >= user.DataLimit {
				killL2TPProcess(session.PID)
				deleteL2TPInterface(session.IFName)
			}
		}
		for sessionID := range records {
			if strings.HasPrefix(sessionID, protocol+":") {
				if _, ok := active[sessionID]; !ok {
					delete(records, sessionID)
				}
			}
		}
		writeOVAccounting(accountingPath, records)
	})
}

func readPPPUsers(path string) map[string]pppUserSnapshot {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	users := map[string]pppUserSnapshot{}
	for _, lineText := range strings.Split(string(raw), "\n") {
		parts := strings.Split(strings.TrimSpace(lineText), "\t")
		if len(parts) < 6 || parts[0] == "" || parts[1] == "" {
			continue
		}
		used, _ := strconv.ParseInt(parts[4], 10, 64)
		limit, _ := strconv.ParseInt(parts[5], 10, 64)
		users[parts[1]] = pppUserSnapshot{
			UserID:      parts[0],
			Username:    parts[1],
			UsedTraffic: used,
			DataLimit:   limit,
		}
	}
	return users
}

func readPPPSessions(path string) []pppSessionSnapshot {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var sessions []pppSessionSnapshot
	for _, lineText := range strings.Split(string(raw), "\n") {
		parts := strings.Split(strings.TrimSpace(lineText), "\t")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			continue
		}
		sessions = append(sessions, pppSessionSnapshot{Username: parts[0], IFName: parts[1], PID: parts[2]})
	}
	return sessions
}

func pppInterfaceBytes(ifname string) (int64, bool) {
	if ifname == "" || strings.ContainsAny(ifname, "/ \t\r\n") {
		return 0, false
	}
	rx, ok1 := readInt64File(filepath.Join(pppNetStatRoot, ifname, "statistics", "rx_bytes"))
	tx, ok2 := readInt64File(filepath.Join(pppNetStatRoot, ifname, "statistics", "tx_bytes"))
	return rx + tx, ok1 || ok2
}

func readInt64File(path string) (int64, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	return value, err == nil
}

func pppSessionID(protocol string, pid string, ifname string, username string) string {
	return pppSafe(protocol + ":" + strings.TrimSpace(pid) + ":" + strings.TrimSpace(ifname) + ":" + strings.TrimSpace(username))
}

func pppSafe(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == ':' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func l2tpIPUpScript(usersPath string, usagePath string, sessionsPath string, callbackPath string, vpnSessions string, inboundTag string) string {
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
USAGE=%q
SESSIONS=%q
now=$(date +%%s)
%s
touch "$USAGE" 2>/dev/null || true
peer=${PEERNAME:-}
ifname=${IFNAME:-}
pid=${PPPD_PID:-}
[ -n "$pid" ] || pid=$$
remote_ip=${IPREMOTE:-}
info=$(awk -F '\t' -v u="$peer" -v now="$now" '
  FILENAME == ARGV[1] {
    id=$1
    sub(/^l2tp:/, "", id)
    if (id != "" && $2 > 0) pending[id] += $2
    next
  }
  $2 == u && ($7 == "" || $7 == "active" || $7 == "on_hold") {
    if ($8 != "" && now >= $8) exit 3
    used = $5 + pending[$1]
    if ($6 != "" && used >= $6) exit 2
    print $1 "\t" $9
    found=1
    exit 0
  }
  END { exit found ? 0 : 1 }
' "$USAGE" "$USERS") || {
  [ -n "$pid" ] && kill -TERM "$pid" >/dev/null 2>&1 || true
  exit 1
}
uid=$(printf '%%s' "$info" | awk -F '\t' '{print $1}')
device_limit=$(printf '%%s' "$info" | awk -F '\t' '{print $2}')
session=$(vpn_safe "l2tp:${pid}:${ifname}:${peer}")
if ! vpn_admit "$uid" "l2tp" %q "$session" "$remote_ip" "" "$device_limit"; then
  [ -n "$pid" ] && kill -TERM "$pid" >/dev/null 2>&1 || true
  exit 1
fi
if [ -n "$peer" ] && [ -n "$ifname" ]; then
  mkdir -p "$(dirname "$SESSIONS")"
  tmp="${SESSIONS}.$$"
  if [ -f "$SESSIONS" ]; then
    awk -F '\t' -v u="$peer" '$1 != u { print }' "$SESSIONS" > "$tmp"
  else
    : > "$tmp"
  fi
  printf '%%s\t%%s\t%%s\n' "$peer" "$ifname" "$pid" >> "$tmp"
  mv "$tmp" "$SESSIONS"
  chmod 600 "$SESSIONS"
fi
`, usersPath, usagePath, sessionsPath, vpnSessionShell(callbackPath, vpnSessions), safeName(inboundTag))
}

func l2tpIPDownScript(usersPath string, usagePath string, accountingPath string, sessionsPath string, callbackPath string, vpnSessions string, inboundTag string) string {
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
USAGE=%q
ACCOUNTING=%q
ACCOUNTING_LOCK="${ACCOUNTING}.lock"
SESSIONS=%q
%s
uid=$(awk -F '\t' -v u="$PEERNAME" '$2 == u { print $1; exit }' "$USERS")
rx=${BYTES_RCVD:-0}
tx=${BYTES_SENT:-0}
total=$((rx + tx))
if [ -n "$uid" ] && [ "$total" -gt 0 ]; then
  mkdir -p "$(dirname "$ACCOUNTING")"
  touch "$ACCOUNTING"
  session=$(vpn_safe "l2tp:${PPPD_PID:-$$}:${IFNAME:-}:${PEERNAME:-}")
  (
    flock -x 9 || exit 0
    previous=$(awk -F '\t' -v sid="$session" '$1 == sid { print $3; found=1; exit } END { if (!found) print 0 }' "$ACCOUNTING")
    case "$previous" in ''|*[!0-9]*) previous=0 ;; esac
    delta=$((total - previous))
    if [ "$delta" -gt 0 ]; then
      printf 'l2tp:%%s\t%%s\n' "$uid" "$delta" >> "$USAGE"
    fi
    tmp="${ACCOUNTING}.$$"
    awk -F '\t' -v sid="$session" '$1 != sid { print }' "$ACCOUNTING" > "$tmp"
    mv "$tmp" "$ACCOUNTING"
    chmod 600 "$ACCOUNTING"
  ) 9>"$ACCOUNTING_LOCK"
fi
if [ -n "$PEERNAME" ] && [ -f "$SESSIONS" ]; then
  tmp="${SESSIONS}.$$"
  awk -F '\t' -v u="$PEERNAME" '$1 != u { print }' "$SESSIONS" > "$tmp"
  mv "$tmp" "$SESSIONS"
  chmod 600 "$SESSIONS"
fi
session=$(vpn_safe "l2tp:${PPPD_PID:-$$}:${IFNAME:-}:${PEERNAME:-}")
vpn_release "$uid" "l2tp" %q "$session" "${IPREMOTE:-}" ""
`, usersPath, usagePath, accountingPath, sessionsPath, vpnSessionShell(callbackPath, vpnSessions), safeName(inboundTag))
}

func l2tpPoolRange(pool string) (string, string) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool))
	if err != nil || !prefix.Addr().Is4() {
		prefix, _ = netip.ParsePrefix("10.67.0.0/16")
	}
	network := ipv4ToUint32(prefix.Masked().Addr())
	size := uint64(1) << uint(32-prefix.Bits())
	if size < 4 {
		local := uint32ToIPv4(network)
		return local.String(), local.String() + "-" + local.String()
	}
	broadcast := network + uint32(size-1)
	local := network + 1
	start := network + 10
	end := broadcast - 1
	if start > end {
		start = network + 2
	}
	if start > end {
		start = local
	}
	localAddr := uint32ToIPv4(local)
	startAddr := uint32ToIPv4(start)
	endAddr := uint32ToIPv4(end)
	return localAddr.String(), startAddr.String() + "-" + endAddr.String()
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	raw := addr.As4()
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}

func uint32ToIPv4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}

func ensureL2TPPrerequisites() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if commandExists("dpkg-query") && commandExists("ipsec") && !l2tpDebianPackagesReady() {
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--configure", "strongswan-starter", "strongswan"); err != nil {
			return err
		}
	}
	missing := missingExecutables("ipsec", "xl2tpd", "pppd", "nft", "ip", "iptables")
	if len(missing) > 0 {
		if err := installL2TPPackages(); err != nil {
			return err
		}
	}
	for _, executable := range []string{"ipsec", "xl2tpd", "pppd", "nft", "ip", "iptables"} {
		if _, err := exec.LookPath(executable); err != nil {
			return fmt.Errorf("L2TP prerequisite %s was not found after automatic install", executable)
		}
	}
	if err := loadL2TPKernelModules(); err != nil {
		if installErr := installL2TPKernelModulePackages(); installErr != nil {
			return fmt.Errorf("%w; automatic kernel module package install failed: %v", err, installErr)
		}
		if retryErr := loadL2TPKernelModules(); retryErr != nil {
			return retryErr
		}
	}
	return nil
}

func l2tpDebianPackagesReady() bool {
	for _, name := range []string{"strongswan-starter", "strongswan"} {
		output, err := exec.Command("dpkg-query", "-W", "-f=${db:Status-Abbrev}", name).CombinedOutput()
		if err != nil || !strings.HasPrefix(string(output), "ii ") {
			return false
		}
	}
	return true
}

func installL2TPPackages() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("L2TP prerequisites are missing and automatic install requires root")
	}
	switch {
	case commandExists("apt-get"):
		if commandExists("dpkg") {
			if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--configure", "-a"); err != nil {
				return err
			}
		}
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(commandOutput("ipsec", "--version")), "strongswan") {
			return runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "strongswan", "xl2tpd", "ppp", "nftables", "iproute2", "iptables", "kmod")
		}
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "libreswan", "xl2tpd", "ppp", "nftables", "iproute2", "iptables", "kmod"); err == nil {
			return nil
		}
		return runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "strongswan", "xl2tpd", "ppp", "nftables", "iproute2", "iptables", "kmod")
	case commandExists("dnf"):
		return runInstallCommand(nil, "dnf", "install", "-y", "libreswan", "xl2tpd", "ppp", "nftables", "iproute", "iptables", "kmod")
	case commandExists("yum"):
		return runInstallCommand(nil, "yum", "install", "-y", "libreswan", "xl2tpd", "ppp", "nftables", "iproute", "iptables", "kmod")
	case commandExists("apk"):
		return runInstallCommand(nil, "apk", "add", "strongswan", "xl2tpd", "ppp", "nftables", "iproute2", "iptables", "kmod")
	default:
		return fmt.Errorf("L2TP prerequisites are missing and no supported package manager was found")
	}
}

func loadL2TPKernelModules() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	for _, module := range []string{"ppp_generic", "pppox", "l2tp_ppp"} {
		if output, err := exec.Command("modprobe", module).CombinedOutput(); err != nil {
			return fmt.Errorf("load kernel module %s: %v: %s", module, err, strings.TrimSpace(string(output)))
		}
	}
	for _, module := range []string{"pppol2tp", "af_key", "nf_tproxy_ipv4"} {
		_ = exec.Command("modprobe", module).Run()
	}
	return nil
}

func installL2TPKernelModulePackages() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("automatic kernel module package install requires root")
	}
	kernel := strings.TrimSpace(commandOutput("uname", "-r"))
	switch {
	case commandExists("apt-get"):
		if commandExists("dpkg") {
			_ = runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--configure", "-a")
		}
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
			return err
		}
		if kernel == "" {
			return fmt.Errorf("kernel release is empty")
		}
		err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "linux-modules-extra-"+kernel)
		if err == nil {
			return nil
		}
		if fallbackErr := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "linux-generic"); fallbackErr != nil {
			return fmt.Errorf("%w; fallback linux-generic install failed: %v", err, fallbackErr)
		}
		return fmt.Errorf("%w; installed generic kernel module packages, reboot into the new kernel is required", err)
	case commandExists("dnf"):
		return runInstallCommand(nil, "dnf", "install", "-y", "kernel-modules-extra")
	case commandExists("yum"):
		return runInstallCommand(nil, "yum", "install", "-y", "kernel-modules-extra")
	default:
		return fmt.Errorf("no supported package manager was found")
	}
}

func restartL2TPServices() error {
	if exec.Command("pgrep", "-x", "charon").Run() != nil && exec.Command("pgrep", "-x", "pluto").Run() != nil {
		if err := runOptional("ipsec", "start"); err != nil {
			return err
		}
	} else {
		if err := runOptional("ipsec", "rereadsecrets"); err != nil {
			return err
		}
		if err := runOptional("ipsec", "reload"); err != nil {
			return err
		}
	}
	stopL2TPService()
	if commandExists("systemctl") {
		if err := runOptional("systemctl", "start", "xl2tpd"); err == nil {
			return nil
		}
	}
	return runOptional("service", "xl2tpd", "start")
}

func stopL2TPService() {
	if commandExists("systemctl") {
		_ = runOptional("systemctl", "stop", "xl2tpd")
	} else {
		_ = runOptional("service", "xl2tpd", "stop")
	}
	_ = exec.Command("pkill", "-TERM", "-x", "xl2tpd").Run()
	for range 40 {
		if exec.Command("pgrep", "-x", "xl2tpd").Run() != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = exec.Command("pkill", "-KILL", "-x", "xl2tpd").Run()
}

func l2tpSystemConfigSnapshot() string {
	paths := []string{
		"/etc/ipsec.conf",
		"/etc/ipsec.secrets",
		"/etc/xl2tpd/xl2tpd.conf",
	}
	var b strings.Builder
	for _, path := range paths {
		raw, _ := os.ReadFile(path)
		b.WriteString(path)
		b.WriteByte(0)
		b.Write(raw)
		b.WriteByte(0)
	}
	return b.String()
}

func l2tpServicesRunning() bool {
	ipsecRunning := exec.Command("pgrep", "-x", "charon").Run() == nil || exec.Command("pgrep", "-x", "pluto").Run() == nil
	return exec.Command("pgrep", "-x", "xl2tpd").Run() == nil && ipsecRunning
}

func commandOutput(name string, args ...string) string {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(output)
}

func runOptional(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	output, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func updateManagedBlock(path string, start string, end string, body string) error {
	existing, _ := os.ReadFile(path)
	text := string(existing)
	startIdx := strings.Index(text, start)
	endIdx := strings.Index(text, end)
	block := start + "\n" + strings.TrimRight(body, "\n") + "\n" + end + "\n"
	if startIdx >= 0 && endIdx > startIdx {
		endIdx += len(end)
		text = strings.TrimRight(text[:startIdx], "\n") + "\n" + block + strings.TrimLeft(text[endIdx:], "\n")
	} else {
		if strings.TrimSpace(text) != "" {
			text = strings.TrimRight(text, "\n") + "\n"
		}
		text += block
	}
	return os.WriteFile(path, []byte(text), 0o600)
}
