package node

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type pptpRuntime struct {
	GeneratedAt string               `json:"generated_at"`
	Target      string               `json:"target,omitempty"`
	Inbounds    []pptpRuntimeInbound `json:"inbounds"`
}

type pptpRuntimeInbound struct {
	Tag        string           `json:"tag"`
	TunnelTag  string           `json:"tunnel_tag"`
	Port       int              `json:"port"`
	TunnelPort int              `json:"tunnel_port"`
	Settings   map[string]any   `json:"settings"`
	Users      []vpnRuntimeUser `json:"users"`
}

type pptpManager struct {
	baseDir     string
	installMode string
	mu          sync.Mutex
}

func newPPTPManager(dataDir string, installMode string) *pptpManager {
	return &pptpManager{
		baseDir:     filepath.Join(dataDir, "pptp"),
		installMode: strings.ToLower(strings.TrimSpace(installMode)),
	}
}

func (m *pptpManager) Apply(runtimeConfig *pptpRuntime) error {
	if m == nil || runtimeConfig == nil {
		return nil
	}
	if len(runtimeConfig.Inbounds) > 0 && m.installMode != "binary" {
		return fmt.Errorf("PPTP is supported only on binary Rebecca-node installs")
	}
	if len(runtimeConfig.Inbounds) > 1 {
		return fmt.Errorf("only one PPTP inbound is supported per node because TCP 1723/GRE are node-wide")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(runtimeConfig.Inbounds) > 0 {
		if err := ensurePPTPPrerequisites(); err != nil {
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
	if len(runtimeConfig.Inbounds) == 0 {
		m.stop()
		return nil
	}
	inbound := runtimeConfig.Inbounds[0]
	if err := m.writeInbound(inbound); err != nil {
		return err
	}
	m.disconnectStaleSessions(inbound.Users)
	return m.applyInbound(inbound)
}

func (m *pptpManager) currentRuntime() *pptpRuntime {
	if m == nil {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(m.baseDir, "runtime.json"))
	if err != nil {
		return nil
	}
	var payload pptpRuntime
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return &payload
}

func (m *pptpManager) CollectUsage() []xray.UserStat {
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
	collectPPPLiveUsage(m.baseDir, "pptp", stats)
	out := make([]xray.UserStat, 0, len(stats))
	for uid, value := range stats {
		out = append(out, xray.UserStat{UID: uid, Value: value, InboundTag: inboundTag})
	}
	return out
}

func (m *pptpManager) writeInbound(inbound pptpRuntimeInbound) error {
	if err := os.MkdirAll(m.baseDir, 0o700); err != nil {
		return err
	}
	if err := writeVPNSessionCallback(vpnSessionCallbackPath(m.baseDir), nil); err != nil {
		return err
	}
	usersPath := filepath.Join(m.baseDir, "users.tsv")
	if err := os.WriteFile(usersPath, []byte(vpnUsersTSV(inbound.Users)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "nftables.nft"), []byte(pptpNFTScript(inbound)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(m.baseDir, "options.pptpd"), []byte(pptpPPPOptions(inbound)), 0o600); err != nil {
		return err
	}
	return nil
}

func (m *pptpManager) applyInbound(inbound pptpRuntimeInbound) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	beforeSystemConfig := pptpSystemConfigSnapshot()
	tproxyEnabled := inbound.TunnelPort > 0 && boolValue(inbound.Settings["tproxy_enabled"], true)
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.68.0.0/16")
	if tproxyEnabled {
		enableVPNTProxyHostNetworking(pool)
		nft, err := exec.LookPath("nft")
		if err != nil {
			return fmt.Errorf("nft executable not found")
		}
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_pptp").Run()
		if output, err := exec.Command(nft, "-f", filepath.Join(m.baseDir, "nftables.nft")).CombinedOutput(); err != nil {
			return fmt.Errorf("apply PPTP nftables %s: %v: %s", inbound.Tag, err, strings.TrimSpace(string(output)))
		}
		if err := applyTProxyRouting(); err != nil {
			return err
		}
		_ = vpnRemoveDirectNAT("pptp")
	} else {
		if nft, err := exec.LookPath("nft"); err == nil {
			_ = exec.Command(nft, "delete", "table", "inet", "rebecca_pptp").Run()
		}
		if err := vpnApplyDirectNAT("pptp", "ppp+", pool); err != nil {
			return fmt.Errorf("apply PPTP direct NAT %s: %w", inbound.Tag, err)
		}
	}
	if err := m.writeSystemConfig(inbound); err != nil {
		return err
	}
	if beforeSystemConfig != pptpSystemConfigSnapshot() || !pptpServiceRunning() {
		return restartPPTPService()
	}
	return nil
}

func (m *pptpManager) stop() {
	if runtime.GOOS == "windows" {
		return
	}
	_ = runOptional("systemctl", "stop", "pptpd")
	_ = runOptional("service", "pptpd", "stop")
	if nft, err := exec.LookPath("nft"); err == nil {
		_ = exec.Command(nft, "delete", "table", "inet", "rebecca_pptp").Run()
	}
	_ = vpnRemoveDirectNAT("pptp")
	_ = os.WriteFile(filepath.Join(m.baseDir, "sessions.tsv"), nil, 0o600)
}

func (m *pptpManager) writeSystemConfig(inbound pptpRuntimeInbound) error {
	localIP, ipRange := l2tpPoolRange(firstString(inbound.Settings["ipv4_pool_cidr"], "10.68.0.0/24"))
	ipRange = pptpPoolRange(ipRange)
	pptpdConf := fmt.Sprintf(`option /etc/ppp/pptpd-options
localip %s
remoteip %s
`, localIP, ipRange)
	if err := updateManagedBlock("/etc/pptpd.conf", "# BEGIN REBECCA PPTP", "# END REBECCA PPTP", pptpdConf); err != nil {
		return fmt.Errorf("update /etc/pptpd.conf: %w", err)
	}
	if err := updateManagedBlock("/etc/ppp/chap-secrets", "# BEGIN REBECCA PPTP USERS", "# END REBECCA PPTP USERS", pptpChapSecrets(inbound.Users)); err != nil {
		return err
	}
	if err := os.MkdirAll("/etc/ppp/ip-up.d", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/ppp/ip-up.d/rebecca-pptp-sessions", []byte(strings.ReplaceAll(l2tpIPUpScript(filepath.Join(m.baseDir, "users.tsv"), filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "sessions.tsv"), vpnSessionCallbackPath(m.baseDir), vpnSessionsPath(m.baseDir), inbound.Tag), "l2tp", "pptp")), 0o700); err != nil {
		return fmt.Errorf("write /etc/ppp/ip-up.d/rebecca-pptp-sessions: %w", err)
	}
	if err := os.MkdirAll("/etc/ppp/ip-down.d", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/ppp/ip-down.d/rebecca-pptp-accounting", []byte(pptpIPDownScript(filepath.Join(m.baseDir, "users.tsv"), filepath.Join(m.baseDir, "usage.tsv"), filepath.Join(m.baseDir, "accounting.tsv"), filepath.Join(m.baseDir, "sessions.tsv"))), 0o700); err != nil {
		return fmt.Errorf("write /etc/ppp/ip-down.d/rebecca-pptp-accounting: %w", err)
	}
	return updateManagedBlock("/etc/ppp/pptpd-options", "# BEGIN REBECCA PPTP OPTIONS", "# END REBECCA PPTP OPTIONS", pptpPPPOptions(inbound))
}

func pptpPoolRange(ipRange string) string {
	start, end, ok := strings.Cut(strings.TrimSpace(ipRange), "-")
	if !ok {
		return ipRange
	}
	lastDot := strings.LastIndex(start, ".")
	if lastDot < 0 {
		return ipRange
	}
	prefix := start[:lastDot+1]
	if strings.HasPrefix(end, prefix) {
		return start + "-" + strings.TrimPrefix(end, prefix)
	}
	return ipRange
}

func pptpPPPOptions(inbound pptpRuntimeInbound) string {
	var b strings.Builder
	line(&b, "name pptpd")
	line(&b, "auth")
	line(&b, "require-mschap-v2")
	line(&b, "refuse-pap")
	line(&b, "refuse-chap")
	line(&b, "refuse-mschap")
	line(&b, "require-mppe-128")
	line(&b, "noipv6")
	line(&b, "proxyarp")
	line(&b, "nodefaultroute")
	line(&b, "lock")
	dnsServers := stringList(inbound.Settings["dns_servers"])
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1"}
	}
	for _, dns := range dnsServers {
		line(&b, "ms-dns "+dns)
	}
	line(&b, fmt.Sprintf("mtu %d", boundedInt(inbound.Settings["mtu"], 1410, 576, 1500)))
	line(&b, fmt.Sprintf("mru %d", boundedInt(inbound.Settings["mru"], 1410, 576, 1500)))
	line(&b, fmt.Sprintf("lcp-echo-interval %d", boundedInt(inbound.Settings["lcp_echo_interval"], 30, 1, 3600)))
	line(&b, fmt.Sprintf("lcp-echo-failure %d", boundedInt(inbound.Settings["lcp_echo_failure"], 4, 1, 20)))
	line(&b, "ipparam rebecca-pptp")
	return b.String()
}

func pptpChapSecrets(users []vpnRuntimeUser) string {
	var b strings.Builder
	for _, user := range users {
		if strings.TrimSpace(user.VPNUsername) == "" || strings.TrimSpace(user.Password) == "" {
			continue
		}
		line(&b, fmt.Sprintf("%q pptpd %q %s", user.VPNUsername, user.Password, firstString(user.IPv4Address, "*")))
	}
	return b.String()
}

func pptpNFTScript(inbound pptpRuntimeInbound) string {
	if inbound.TunnelPort <= 0 || !boolValue(inbound.Settings["tproxy_enabled"], true) {
		return ""
	}
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.68.0.0/16")
	blockedV4, blockedV6 := ovBlockedDestinations()
	var rules strings.Builder
	if len(blockedV4) > 0 {
		line(&rules, fmt.Sprintf(`    ip saddr %s ip daddr { %s } drop`, pool, strings.Join(blockedV4, ", ")))
	}
	if len(blockedV6) > 0 {
		line(&rules, fmt.Sprintf(`    iifname "ppp*" ip6 daddr { %s } drop`, strings.Join(blockedV6, ", ")))
	}
	return fmt.Sprintf(`table inet rebecca_pptp {
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

func (m *pptpManager) disconnectStaleSessions(users []vpnRuntimeUser) {
	allowed := map[string]struct{}{}
	for _, user := range users {
		username := strings.TrimSpace(user.VPNUsername)
		if username != "" {
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

func pptpIPDownScript(usersPath string, usagePath string, accountingPath string, sessionsPath string) string {
	return strings.ReplaceAll(l2tpIPDownScript(usersPath, usagePath, accountingPath, sessionsPath, vpnSessionCallbackPath(filepath.Dir(usersPath)), vpnSessionsPath(filepath.Dir(usersPath)), "pptp"), "l2tp", "pptp")
}

func ensurePPTPPrerequisites() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	missing := missingExecutables("pptpd", "pppd", "nft", "ip", "iptables")
	if len(missing) > 0 || !debianPackageConfigured("pptpd") {
		if err := installPPTPPackages(); err != nil {
			return err
		}
	}
	for _, executable := range []string{"pptpd", "pppd", "nft", "ip", "iptables"} {
		if _, err := exec.LookPath(executable); err != nil {
			return fmt.Errorf("PPTP prerequisite %s was not found after automatic install", executable)
		}
	}
	if err := loadPPTPKernelModules(); err != nil {
		return err
	}
	return nil
}

func debianPackageConfigured(name string) bool {
	if !commandExists("dpkg-query") {
		return true
	}
	output, err := exec.Command("dpkg-query", "-W", "-f=${db:Status-Status}", name).CombinedOutput()
	return err == nil && strings.TrimSpace(string(output)) == "installed"
}

func installPPTPPackages() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("PPTP prerequisites are missing and automatic install requires root")
	}
	switch {
	case commandExists("apt-get"):
		if commandExists("dpkg") {
			_ = runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "dpkg", "--configure", "-a")
		}
		if commandExists("pptpd") && !debianPackageConfigured("pptpd") {
			return installDebianPPTPD()
		}
		if err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "update"); err != nil {
			return err
		}
		err := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "pptpd", "ppp", "nftables", "iproute2", "iptables", "kmod")
		if err == nil {
			return nil
		}
		if baseErr := runInstallCommand([]string{"DEBIAN_FRONTEND=noninteractive"}, "apt-get", "install", "-y", "--no-install-recommends", "ppp", "nftables", "iproute2", "iptables", "kmod", "curl", "ca-certificates"); baseErr != nil {
			return fmt.Errorf("%w; installing PPTP base dependencies failed: %v", err, baseErr)
		}
		if debErr := installDebianPPTPD(); debErr != nil {
			return fmt.Errorf("%w; Debian pptpd fallback failed: %v", err, debErr)
		}
		return nil
	case commandExists("dnf"):
		return runInstallCommand(nil, "dnf", "install", "-y", "pptpd", "ppp", "nftables", "iproute", "iptables", "kmod")
	case commandExists("yum"):
		return runInstallCommand(nil, "yum", "install", "-y", "pptpd", "ppp", "nftables", "iproute", "iptables", "kmod")
	case commandExists("apk"):
		return runInstallCommand(nil, "apk", "add", "pptpd", "ppp", "nftables", "iproute2", "iptables", "kmod")
	default:
		return fmt.Errorf("PPTP prerequisites are missing and no supported package manager was found")
	}
}

func installDebianPPTPD() error {
	if runtime.GOARCH != "amd64" {
		return fmt.Errorf("Debian pptpd fallback is only available for amd64")
	}
	const script = `set -eu
tmp=/tmp/rebecca-pptpd-debs
mkdir -p "$tmp"
cd "$tmp"
curl -fsSL -o bcrelay.deb https://deb.debian.org/debian/pool/main/p/pptpd/bcrelay_1.5.0-1+b2_amd64.deb
curl -fsSL -o pptpd.deb https://deb.debian.org/debian/pool/main/p/pptpd/pptpd_1.5.0-1+b2_amd64.deb
echo "c33700203fcd2adc0e153fcfb2d2a14ae0a74ac141fb4dd44691b821abe893c2  bcrelay.deb" | sha256sum -c -
echo "a270fe57f4212b414f0c02e365cd568ac27701c0e9dea5f6294af432d474d601  pptpd.deb" | sha256sum -c -
dpkg --force-confdef --force-confold -i bcrelay.deb || dpkg --force-confdef --force-confold --force-depends -i bcrelay.deb
dpkg --force-confdef --force-confold -i pptpd.deb || dpkg --force-confdef --force-confold --force-depends -i pptpd.deb
dpkg --force-confdef --force-confold --force-depends --configure bcrelay pptpd
`
	return runInstallCommand(nil, "sh", "-c", script)
}

func loadPPTPKernelModules() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	for _, module := range []string{"ppp_generic", "ppp_mppe"} {
		if output, err := exec.Command("modprobe", module).CombinedOutput(); err != nil {
			return fmt.Errorf("load kernel module %s: %v: %s", module, err, strings.TrimSpace(string(output)))
		}
	}
	for _, module := range []string{"nf_conntrack_pptp", "ip_gre", "nf_tproxy_ipv4"} {
		_ = exec.Command("modprobe", module).Run()
	}
	return nil
}

func restartPPTPService() error {
	if commandExists("systemctl") {
		if err := runOptional("systemctl", "restart", "pptpd"); err == nil {
			return nil
		}
	}
	return runOptional("service", "pptpd", "restart")
}

func pptpSystemConfigSnapshot() string {
	paths := []string{
		"/etc/pptpd.conf",
		"/etc/ppp/pptpd-options",
		"/etc/ppp/chap-secrets",
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

func pptpServiceRunning() bool {
	return exec.Command("pgrep", "-x", "pptpd").Run() == nil
}
