package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var managedTorUnitPattern = regexp.MustCompile(`^rebecca-tor-([0-9]+)\.service$`)
var managedPortPattern = regexp.MustCompile(`(?:LISTEN|SocksPort)[^0-9]*([0-9]{2,5})`)

type managedProxy struct {
	kind     string
	tag      string
	port     uint32
	country  string
	username string
	password string
}

// reconcileManagedProxyServices keeps OS-level proxy daemons aligned with the
// Xray config. It is intentionally tag/metadata based so ordinary SOCKS
// outbounds are never treated as services Rebecca owns.
func (s *Server) reconcileManagedProxyServices(ctx context.Context, raw string) error {
	if runtime.GOOS != "linux" || strings.TrimSpace(raw) == "" {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return fmt.Errorf("decode managed proxy config: %w", err)
	}
	managed := make([]managedProxy, 0)
	ports := map[uint32]bool{}
	locations := map[string]string{}
	windscribeCount := 0
	for _, outbound := range mapList(payload["outbounds"]) {
		kind := managedProxyKind(outbound)
		if kind == "" {
			continue
		}
		port, username, password, ok := localSocksDetails(outbound)
		if !ok {
			return fmt.Errorf("managed %s outbound %q must use a local SOCKS server", kind, managedString(outbound["tag"]))
		}
		if ports[port] {
			return fmt.Errorf("managed proxy port %d is used by more than one outbound", port)
		}
		ports[port] = true
		item := managedProxy{kind: kind, tag: strings.TrimSpace(managedString(outbound["tag"])), port: port, username: username, password: password}
		if kind == "windscribe" {
			windscribeCount++
			if windscribeCount > 1 {
				return fmt.Errorf("only one Windscribe outbound can run on a node")
			}
		}
		item.country = strings.ToLower(strings.TrimSpace(managedString(outbound["rebecca_proxy_location"])))
		if item.country == "" {
			item.country = managedCountry(item.tag, kind)
		}
		if item.country != "" {
			locationKey := kind + ":" + item.country
			if previous := locations[locationKey]; previous != "" && previous != item.tag {
				return fmt.Errorf("managed %s location %s is used by outbounds %q and %q", kind, strings.ToUpper(item.country), previous, item.tag)
			}
			locations[locationKey] = item.tag
		}
		managed = append(managed, item)
	}
	if err := cleanupManagedTor(ports); err != nil {
		return err
	}
	if err := cleanupManagedWindscribe(ctx, ports); err != nil {
		return err
	}
	for _, item := range managed {
		if !managedProxyOwnsPort(item) && !localPortAvailable(item.port) {
			return fmt.Errorf("managed %s outbound %q cannot use local port %d: the port is already occupied", item.kind, item.tag, item.port)
		}
		switch item.kind {
		case "tor":
			// Tor setup is an explicit action. Reconciliation only cleans stale
			// units; it must never restart a live Tor circuit on every SyncConfig.
			continue
		case "windscribe":
			if err := testAuthenticatedSocks5Connect(int(item.port), item.username, item.password, "example.com", 80); err != nil {
				if _, err := configureWindscribe(ctx, windscribeProxyConfig{Action: "apply", Location: item.country, SocksPort: item.port, ProxyUsername: item.username, ProxyPassword: item.password}); err != nil {
					return fmt.Errorf("configure Windscribe outbound %s: %w", item.tag, err)
				}
			}
		}
	}
	return nil
}

func managedProxyOwnsPort(item managedProxy) bool {
	switch item.kind {
	case "tor":
		if fileExists(filepath.Join("/etc/systemd/system", fmt.Sprintf("rebecca-tor-%d.service", item.port))) {
			return true
		}
		raw, err := os.ReadFile("/etc/tor/torrc")
		return err == nil && strings.Contains(string(raw), fmt.Sprintf("SocksPort 127.0.0.1:%d", item.port))
	case "windscribe":
		raw, err := os.ReadFile(filepath.Join("/etc/systemd/system", windscribeRelayUnitName))
		return err == nil && strings.Contains(string(raw), fmt.Sprintf("TCP4-LISTEN:%d", item.port))
	default:
		return false
	}
}

func localPortAvailable(port uint32) bool {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	_ = listener.Close()
	return true
}

func mapList(value any) []map[string]any {
	items, _ := value.([]any)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if mapped, ok := item.(map[string]any); ok {
			result = append(result, mapped)
		}
	}
	return result
}

func managedProxyKind(outbound map[string]any) string {
	kind := strings.ToLower(strings.TrimSpace(managedString(outbound["rebecca_proxy"])))
	if kind == "tor" || kind == "windscribe" {
		return kind
	}
	tag := strings.ToLower(strings.TrimSpace(managedString(outbound["tag"])))
	if tag == "tor" || strings.HasPrefix(tag, "tor-") {
		return "tor"
	}
	if tag == "windscribe" || strings.HasPrefix(tag, "windscribe-") {
		return "windscribe"
	}
	return ""
}

func localSocksDetails(outbound map[string]any) (uint32, string, string, bool) {
	if strings.ToLower(strings.TrimSpace(managedString(outbound["protocol"]))) != "socks" {
		return 0, "", "", false
	}
	settings, _ := outbound["settings"].(map[string]any)
	servers := mapList(settings["servers"])
	if len(servers) == 0 || !isLocalAddress(managedString(servers[0]["address"])) {
		return 0, "", "", false
	}
	port, err := uint32Value(servers[0]["port"])
	if err != nil || port < 1024 || port > 65535 {
		return 0, "", "", false
	}
	username, password := "", ""
	users := mapList(servers[0]["users"])
	if len(users) > 0 {
		username = managedString(users[0]["user"])
		password = managedString(users[0]["pass"])
	}
	return port, username, password, true
}

func managedString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func uint32Value(value any) (uint32, error) {
	switch v := value.(type) {
	case float64:
		if v != float64(uint32(v)) || v < 0 {
			return 0, fmt.Errorf("invalid port")
		}
		return uint32(v), nil
	case json.Number:
		parsed, err := strconv.ParseUint(string(v), 10, 32)
		return uint32(parsed), err
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		return uint32(parsed), err
	default:
		return 0, fmt.Errorf("invalid port")
	}
}

func isLocalAddress(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	return value == "127.0.0.1" || value == "::1" || strings.EqualFold(value, "localhost")
}

func managedCountry(tag, prefix string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(tag)), "-")
	if len(parts) > 1 && parts[len(parts)-1] != prefix {
		candidate := parts[len(parts)-1]
		if len(candidate) == 2 {
			return candidate
		}
	}
	return ""
}

func cleanupManagedTor(ports map[uint32]bool) error {
	entries, err := os.ReadDir("/etc/systemd/system")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	changed := false
	for _, entry := range entries {
		match := managedTorUnitPattern.FindStringSubmatch(entry.Name())
		if len(match) != 2 {
			continue
		}
		port, _ := strconv.ParseUint(match[1], 10, 32)
		if ports[uint32(port)] {
			continue
		}
		unit := entry.Name()
		if commandExists("systemctl") {
			_ = execCommand("systemctl", "disable", "--now", unit)
		}
		_ = os.Remove(filepath.Join("/etc/systemd/system", unit))
		_ = os.Remove(filepath.Join("/etc/tor/rebecca", fmt.Sprintf("rebecca-tor-%d.torrc", port)))
		_ = os.RemoveAll(filepath.Join("/var/lib/rebecca-tor", fmt.Sprintf("rebecca-tor-%d", port)))
		changed = true
	}
	if changed && commandExists("systemctl") {
		_ = execCommand("systemctl", "daemon-reload")
	}
	legacyPath := "/etc/tor/torrc"
	if raw, readErr := os.ReadFile(legacyPath); readErr == nil {
		block := string(raw)
		start := strings.Index(block, torRebeccaBlockStart)
		end := strings.Index(block, torRebeccaBlockEnd)
		if start >= 0 && end > start {
			section := block[start : end+len(torRebeccaBlockEnd)]
			match := managedPortPattern.FindStringSubmatch(section)
			if len(match) == 2 {
				port, _ := strconv.ParseUint(match[1], 10, 32)
				if !ports[uint32(port)] {
					next := strings.TrimSpace(block[:start] + block[end+len(torRebeccaBlockEnd):])
					if err := os.WriteFile(legacyPath, []byte(next+"\n"), 0o644); err != nil {
						return fmt.Errorf("remove stale Tor configuration: %w", err)
					}
					if err := restartTorService(); err != nil {
						return fmt.Errorf("restart Tor after removing stale configuration: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func cleanupManagedWindscribe(ctx context.Context, ports map[uint32]bool) error {
	path := "/etc/systemd/system/" + windscribeRelayUnitName
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	match := managedPortPattern.FindStringSubmatch(string(raw))
	if len(match) != 2 {
		return nil
	}
	port, _ := strconv.ParseUint(match[1], 10, 32)
	if ports[uint32(port)] {
		return nil
	}
	if commandExists("systemctl") {
		_ = execCommand("systemctl", "disable", "--now", windscribeRelayUnitName)
		_ = execCommand("systemctl", "daemon-reload")
	}
	_ = os.Remove(path)
	_ = runWindscribeCommand(ctx, "disconnect")
	return nil
}

func execCommand(name string, args ...string) error {
	return runCommandContext(context.Background(), nil, name, args...)
}
func runWindscribeCommand(ctx context.Context, args ...string) error {
	_, err := runWindscribeCLI(ctx, args...)
	return err
}
