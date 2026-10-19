//go:build linux

package node

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func (m *extraVPNManager) applySSTPLocked(inbounds []extraRuntimeInbound, callback *vpnSessionCallback) error {
	for tag, process := range m.sstpProcesses {
		stopManagedProcess(process)
		_ = removeExtraVPNNetworking("sstp_" + safeName(tag))
		delete(m.sstpProcesses, tag)
	}
	if len(inbounds) == 0 {
		return nil
	}
	if err := m.installAccelBundle(); err != nil {
		return err
	}
	for _, inbound := range inbounds {
		if err := m.startSSTPLocked(inbound, callback); err != nil {
			return fmt.Errorf("SSTP inbound %s: %w", inbound.Tag, err)
		}
	}
	return nil
}

func (m *extraVPNManager) startSSTPLocked(inbound extraRuntimeInbound, callback *vpnSessionCallback) error {
	if inbound.Port < 1 || inbound.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	dir := filepath.Join(m.baseDir, "sstp", safeName(inbound.Tag))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	cert := stringSetting(inbound.Settings, "server_certificate")
	key := stringSetting(inbound.Settings, "server_key")
	if !strings.Contains(cert, "BEGIN CERTIFICATE") || !strings.Contains(key, "PRIVATE KEY") {
		return fmt.Errorf("server certificate and private key are required")
	}
	if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
		return fmt.Errorf("server certificate and key do not match: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "server.crt"), []byte(cert), 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "server.key"), []byte(key), 0o600); err != nil {
		return err
	}
	users := make([]vpnRuntimeUser, 0, len(inbound.Users))
	for _, user := range inbound.Users {
		users = append(users, vpnRuntimeUser{UserID: user.UserID, VPNUsername: user.Username, Password: user.Password, IPv4Address: user.IPv4Address, Status: user.Status, UsedTraffic: user.UsedTraffic, DataLimit: user.DataLimit, Expire: user.Expire, DeviceLimit: user.DeviceLimit})
	}
	usersPath := filepath.Join(dir, "users.tsv")
	if err := writeFileAtomic(usersPath, []byte(vpnUsersTSV(users)), 0o600); err != nil {
		return err
	}
	if err := writeVPNSessionCallback(vpnSessionCallbackPath(dir), callback); err != nil {
		return err
	}
	chap := strings.Builder{}
	for _, user := range inbound.Users {
		if !extraVPNUserActive(user) {
			continue
		}
		address := wgPeerAddressHost(user.IPv4Address)
		if parsed, err := netip.ParseAddr(address); err != nil || !parsed.Is4() {
			return fmt.Errorf("user %d has an invalid IPv4 address", user.UserID)
		}
		fmt.Fprintf(&chap, "%q * %q %s\n", user.Username, user.Password, address)
	}
	if err := writeFileAtomic(filepath.Join(dir, "chap-secrets"), []byte(chap.String()), 0o600); err != nil {
		return err
	}
	cliPort := deterministicPort("sstp-cli:"+inbound.Tag, 22000, 39999)
	sessionsPath := vpnSessionsPath(m.baseDir)
	if err := writeFileAtomic(filepath.Join(dir, "ip-up.sh"), []byte(sstpIPUpScript(dir, sessionsPath, inbound.Tag, cliPort)), 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "ip-down.sh"), []byte(sstpIPDownScript(dir, sessionsPath, inbound.Tag)), 0o700); err != nil {
		return err
	}
	config, err := sstpConfig(inbound, dir)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, "accel-ppp.conf"), []byte(config), 0o600); err != nil {
		return err
	}
	converted := remoteAccessRuntimeInbound{Tag: "sstp_" + inbound.Tag, TunnelTag: inbound.TunnelTag, Port: inbound.Port, TunnelPort: inbound.TunnelPort, Settings: inbound.Settings}
	iface := ""
	if inbound.TunnelPort <= 0 || !boolValue(inbound.Settings["tproxy_enabled"], true) {
		iface = "rbss+"
	}
	if err := applyRemoteAccessNetworking("sstp_"+safeName(inbound.Tag), iface, converted); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "accel.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	command := exec.Command(filepath.Join(accelRoot, "sbin", "accel-pppd"), "-c", filepath.Join(dir, "accel-ppp.conf"))
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return err
	}
	m.sstpProcesses[inbound.Tag] = managedProcess{pid: command.Process.Pid}
	go func() { _ = command.Wait(); _ = logFile.Close() }()
	return nil
}

func sstpConfig(inbound extraRuntimeInbound, dir string) (string, error) {
	pool := firstString(inbound.Settings["ipv4_pool_cidr"], "10.72.0.0/16")
	gateway, addressRange, err := extraVPNPoolRange(pool)
	if err != nil {
		return "", err
	}
	mtu := intSetting(inbound.Settings, "mtu", 1400)
	cliPort := deterministicPort("sstp-cli:"+inbound.Tag, 22000, 39999)
	dns := stringListSetting(inbound.Settings, "dns_servers")
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	return fmt.Sprintf(`[modules]
path=%s/lib/accel-ppp
log_file
sstp
auth_mschap_v2
auth_mschap_v1
chap-secrets
ippool
pppd_compat

[core]
thread-count=2

[common]
sid-source=urandom

[log]
log-file=%s/accel.log
level=3

[sstp]
bind=%s
port=%d
accept=ssl
ssl-protocol=tls1.2,tls1.3
ssl-ciphers=DEFAULT@SECLEVEL=1
ssl-pemfile=%s/server.crt
ssl-keyfile=%s/server.key
ppp-max-mtu=%d
ip-pool=sstp
ifname=rbss%%d

[ppp]
mtu=%d
mru=%d
mppe=deny
ipv4=require
lcp-echo-interval=30
lcp-echo-failure=3

[dns]
dns1=%s
dns2=%s

[client-ip-range]
0.0.0.0/0

[ip-pool]
gw-ip-address=%s
%s,name=sstp

[chap-secrets]
gw-ip-address=%s
chap-secrets=%s/chap-secrets

[pppd-compat]
ip-up=%s/ip-up.sh
ip-down=%s/ip-down.sh

[cli]
tcp=127.0.0.1:%d
sessions-columns=username,calling-sid,ip,ifname,rx-bytes-raw,tx-bytes-raw
`, accelRoot, dir, firstString(inbound.Listen, "0.0.0.0"), inbound.Port, dir, dir, mtu, mtu, mtu, dns[0], dns[min(1, len(dns)-1)], gateway, addressRange, gateway, dir, dir, dir, cliPort), nil
}

func extraVPNPoolRange(pool string) (gateway, addressRange string, err error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(pool))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() > 29 {
		return "", "", fmt.Errorf("IPv4 pool must be a valid /29 or larger network")
	}
	network := ipv4ToUint32(prefix.Masked().Addr())
	size := uint64(1) << uint64(32-prefix.Bits())
	if size > 1<<20 {
		return "", "", fmt.Errorf("IPv4 pool must be /12 or narrower")
	}
	return uint32ToIPv4(network + 1).String(), uint32ToIPv4(network+2).String() + "-" + uint32ToIPv4(network+uint32(size)-2).String(), nil
}

func deterministicPort(value string, low, high int) int {
	sum := sha1.Sum([]byte(value))
	number := int(uint16(sum[0])<<8 | uint16(sum[1]))
	return low + number%(high-low+1)
}

func stringListSetting(settings map[string]any, key string) []string {
	values, _ := settings[key].([]any)
	result := []string{}
	for _, value := range values {
		if text := strings.TrimSpace(firstString(value)); text != "" {
			result = append(result, text)
		}
	}
	if valuesText, ok := settings[key].([]string); ok {
		result = append(result, valuesText...)
	}
	return result
}

func stopManagedProcess(process managedProcess) {
	if process.pid <= 0 {
		return
	}
	if target, err := os.FindProcess(process.pid); err == nil {
		_ = target.Signal(os.Interrupt)
		time.Sleep(100 * time.Millisecond)
		if processExists(process.pid) {
			_ = target.Kill()
		}
	}
}

func extraVPNUserActive(user extraRuntimeUser) bool {
	if user.UserID <= 0 || strings.TrimSpace(user.Username) == "" {
		return false
	}
	status := strings.ToLower(strings.TrimSpace(user.Status))
	if status != "" && status != "active" && status != "on_hold" {
		return false
	}
	if user.DataLimit != nil && *user.DataLimit > 0 && user.UsedTraffic >= *user.DataLimit {
		return false
	}
	return user.Expire == nil || *user.Expire <= 0 || time.Now().Unix() < *user.Expire
}

func sstpIPUpScript(dir, sessionsPath, inboundTag string, cliPort int) string {
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
SESSIONS=%q
now=$(date +%%s)
%s
peer=${PEERNAME:-}
ifname=${IFNAME:-$1}
assigned=${IPREMOTE:-$5}
client_ip=${CALLING_SID:-$6}
pid=$$
info=$(awk -F '\t' -v u="$peer" -v now="$now" '$2 == u && ($7 == "" || $7 == "active" || $7 == "on_hold") { if ($6 != "" && $5 >= $6) exit 2; if ($8 != "" && now >= $8) exit 3; print $1 "\t" $9; found=1; exit } END { exit found ? 0 : 1 }' "$USERS") || exit 1
uid=$(printf '%%s' "$info" | awk -F '\t' '{print $1}')
limit=$(printf '%%s' "$info" | awk -F '\t' '{print $2}')
session=$(vpn_safe "sstp:${pid}:${ifname}:${peer}")
if ! vpn_admit "$uid" sstp %q "$session" "$assigned" "$client_ip" "$limit"; then
  (%q -p %d terminate if "$ifname" hard >/dev/null 2>&1 || true) &
  exit 1
fi
printf '%%s\t%%s\t%%s\n' "$peer" "$ifname" "$pid" >> "$SESSIONS"
chmod 600 "$SESSIONS"
`, filepath.Join(dir, "users.tsv"), filepath.Join(dir, "sessions.tsv"), vpnSessionShell(vpnSessionCallbackPath(dir), sessionsPath), safeName(inboundTag), filepath.Join(accelRoot, "bin", "accel-cmd"), cliPort)
}

func sstpIPDownScript(dir, sessionsPath, inboundTag string) string {
	return fmt.Sprintf(`#!/bin/sh
USERS=%q
USAGE=%q
ACCOUNTING=%q
ACCOUNTING_LOCK="${ACCOUNTING}.lock"
SESSIONS=%q
%s
peer=${PEERNAME:-}
ifname=${IFNAME:-$1}
assigned=${IPREMOTE:-$5}
client_ip=${CALLING_SID:-$6}
uid=$(awk -F '\t' -v u="$peer" '$2 == u { print $1; exit }' "$USERS")
total=$((${BYTES_RCVD:-0} + ${BYTES_SENT:-0}))
pid=$(awk -F '\t' -v n="$ifname" '$2 == n { print $3; exit }' "$SESSIONS")
session=$(vpn_safe "sstp:${pid}:${ifname}:${peer}")
if [ -n "$uid" ] && [ "$total" -gt 0 ]; then
  touch "$ACCOUNTING"
  (
    flock -x 9 || exit 0
    previous=$(awk -F '\t' -v sid="$session" '$1 == sid { print $3; found=1; exit } END { if (!found) print 0 }' "$ACCOUNTING")
    case "$previous" in ''|*[!0-9]*) previous=0 ;; esac
    delta=$((total - previous))
    [ "$delta" -le 0 ] || printf 'sstp:%%s\t%%s\n' "$uid" "$delta" >> "$USAGE"
    tmp="${ACCOUNTING}.$$"; awk -F '\t' -v sid="$session" '$1 != sid { print }' "$ACCOUNTING" > "$tmp"; mv "$tmp" "$ACCOUNTING"; chmod 600 "$ACCOUNTING"
  ) 9>"$ACCOUNTING_LOCK"
fi
tmp="${SESSIONS}.$$"; awk -F '\t' -v n="$ifname" '$2 != n { print }' "$SESSIONS" > "$tmp" 2>/dev/null || : > "$tmp"; mv "$tmp" "$SESSIONS"
vpn_release "$uid" sstp %q "$session" "$assigned" "$client_ip"
`, filepath.Join(dir, "users.tsv"), filepath.Join(dir, "usage.tsv"), filepath.Join(dir, "accounting.tsv"), filepath.Join(dir, "sessions.tsv"), vpnSessionShell(vpnSessionCallbackPath(dir), sessionsPath), safeName(inboundTag))
}

func (m *extraVPNManager) collectSSTPUsageLocked() []xray.UserStat {
	if m.runtime == nil {
		return nil
	}
	totals := map[userUsageKey]int64{}
	for _, inbound := range filterExtraVPNInbounds(m.runtime.Inbounds, "sstp") {
		dir := filepath.Join(m.baseDir, "sstp", safeName(inbound.Tag))
		stats := map[string]int64{}
		path := filepath.Join(dir, "usage.tsv")
		if file, err := os.Open(path); err == nil {
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				parts := strings.Split(scanner.Text(), "\t")
				if len(parts) >= 2 {
					value, _ := strconv.ParseInt(parts[1], 10, 64)
					stats[parts[0]] += value
				}
			}
			_ = file.Close()
			_ = os.WriteFile(path, nil, 0o600)
		}
		collectPPPLiveUsage(dir, "sstp", stats)
		for uid, value := range stats {
			addUserUsage(totals, uid, inbound.Tag, value)
		}
	}
	return userUsageStats(totals)
}
