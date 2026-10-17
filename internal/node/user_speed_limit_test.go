package node

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const userSpeedLimitTestDoc = `{
  "inbounds": [{"tag": "fastly1-1", "settings": {"clients": [
    {"email": "129939.rb1_ZmFzdGx5MS0x.a2beev"},
    {"email": "129940.rb1_ZmFzdGx5MS0x.other"}
  ]}}],
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "blocked", "protocol": "blackhole"},
    {"tag": "API", "protocol": "freedom"}
  ],
  "routing": {"rules": [
    {"type": "field", "inboundTag": ["API_INBOUND"], "outboundTag": "API"},
    {"type": "field", "network": ["udp"], "port": "443, 853", "outboundTag": "direct"},
    {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
    {"type": "field", "domain": ["geosite:spotify"], "outboundTag": "direct"}
  ]}
}`

func parseUserSpeedLimitTestDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("parse test doc: %v", err)
	}
	return doc
}

func findUserSpeedLimitRule(rules []any, match func(map[string]any) bool) int {
	for index, raw := range rules {
		rule, _ := raw.(map[string]any)
		if rule != nil && match(rule) {
			return index
		}
	}
	return -1
}

func TestBuildUserSpeedLimitPlanKeepsBaseRoutingAndLimitsSpecificRoutes(t *testing.T) {
	doc := parseUserSpeedLimitTestDoc(t, userSpeedLimitTestDoc)
	plan, err := buildUserSpeedLimitPlan(doc, []userSpeedLimit{{UserID: 129939, SpeedLimitKbps: 10000}}, nil)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Clones) != 1 {
		t.Fatalf("clones = %d, want 1 (direct only; API and blackhole must not be cloned)", len(plan.Clones))
	}
	clone := plan.Clones[0]
	if clone["tag"] != "rl-u129939-direct" || clone["protocol"] != "freedom" {
		t.Fatalf("unexpected clone: %v", clone)
	}
	stream, _ := clone["streamSettings"].(map[string]any)
	sockopt, _ := stream["sockopt"].(map[string]any)
	if got := sockopt["mark"]; got != int64(userSpeedLimitMark(129939)) {
		t.Fatalf("clone mark = %v, want %d", got, userSpeedLimitMark(129939))
	}
	if len(plan.Overlay) != 8 {
		t.Fatalf("overlay rules = %d, want 8 (5 base + udp copy + domain copy + default)", len(plan.Overlay))
	}

	udpCopy := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "rl-u129939-direct" && r["port"] == "443, 853"
	})
	udpBase := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "direct" && r["port"] == "443, 853"
	})
	if udpCopy < 0 || udpBase < 0 || udpCopy > udpBase {
		t.Fatalf("udp copy index %d must come before base udp rule index %d", udpCopy, udpBase)
	}
	domainCopy := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "rl-u129939-direct" && r["domain"] != nil
	})
	domainBase := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "direct" && r["domain"] != nil
	})
	bittorrent := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "blocked" && r["protocol"] != nil
	})
	if domainCopy < 0 || domainBase < 0 || domainCopy > domainBase {
		t.Fatalf("domain copy index %d must come before base domain rule index %d", domainCopy, domainBase)
	}
	if bittorrent < 0 || bittorrent > domainCopy {
		t.Fatalf("bittorrent block index %d must stay before the domain copy index %d", bittorrent, domainCopy)
	}

	api := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool { return r["outboundTag"] == "API" })
	if api != 0 {
		t.Fatalf("API rule must stay first, index = %d", api)
	}
	if blocked := findUserSpeedLimitRule(plan.Overlay, func(r map[string]any) bool {
		return r["outboundTag"] == "blocked" && r["user"] != nil
	}); blocked >= 0 {
		t.Fatalf("blocked rules must not be copied for the limited user")
	}

	last, _ := plan.Overlay[len(plan.Overlay)-1].(map[string]any)
	users, _ := last["user"].([]any)
	if last["outboundTag"] != "rl-u129939-direct" || len(users) != 1 || users[0] != "129939.rb1_ZmFzdGx5MS0x.a2beev" {
		t.Fatalf("default route for the limited user is wrong: %v", last)
	}

	for _, raw := range plan.Overlay {
		rule, _ := raw.(map[string]any)
		listed, _ := rule["user"].([]any)
		for _, email := range listed {
			if strings.HasPrefix(fmt.Sprint(email), "129940.") {
				t.Fatalf("unlimited user 129940 must not get any copied rule: %v", rule)
			}
		}
	}
}

func TestUserSpeedLimitNFTScriptLimitsOnlyMarkedUsers(t *testing.T) {
	doc := parseUserSpeedLimitTestDoc(t, userSpeedLimitTestDoc)
	plan, err := buildUserSpeedLimitPlan(doc, []userSpeedLimit{{UserID: 129939, SpeedLimitKbps: 10000}}, nil)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	script := plan.NFTScript
	for _, want := range []string{
		"add table inet rebecca_user_speed",
		"delete table inet rebecca_user_speed",
		"chain premark",
		"chain outmark",
		fmt.Sprintf("0x%08x : jump lim_in_129939", userSpeedLimitMark(129939)),
		fmt.Sprintf("0x%08x : jump lim_out_129939", userSpeedLimitMark(129939)),
		"limit rate over 1250000 bytes/second burst 312500 bytes drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script misses %q:\n%s", want, script)
		}
	}
	empty := userSpeedLimitNFTScript(nil, nil, nil)
	if empty != "add table inet rebecca_user_speed\ndelete table inet rebecca_user_speed\n" {
		t.Fatalf("empty script must only reset the table, got %q", empty)
	}
}

func TestUserSpeedLimitMarkStaysInDedicatedRange(t *testing.T) {
	for _, userID := range []int64{1, 129939, 0x7fffffff} {
		mark := userSpeedLimitMark(userID)
		if mark&userSpeedLimitMarkMask != userSpeedLimitMarkBase {
			t.Fatalf("mark %#x for user %d is outside the dedicated range", mark, userID)
		}
	}
}

func TestUserSpeedLimitBaseHashFollowsRoutingChanges(t *testing.T) {
	doc := parseUserSpeedLimitTestDoc(t, userSpeedLimitTestDoc)
	first, err := buildUserSpeedLimitPlan(doc, nil, nil)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	again, err := buildUserSpeedLimitPlan(parseUserSpeedLimitTestDoc(t, userSpeedLimitTestDoc), nil, nil)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if first.BaseHash != again.BaseHash {
		t.Fatalf("base hash must be stable for the same config")
	}
	changed := strings.Replace(userSpeedLimitTestDoc, `"outboundTag": "direct"}`, `"outboundTag": "blocked"}`, 1)
	changedPlan, err := buildUserSpeedLimitPlan(parseUserSpeedLimitTestDoc(t, changed), nil, nil)
	if err != nil {
		t.Fatalf("build changed plan: %v", err)
	}
	if first.BaseHash == changedPlan.BaseHash {
		t.Fatalf("base hash must change when routing changes")
	}
}

func TestUserSpeedLimitVPNBindingsMapsAssignedIPsOfLimitedUsers(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		"129939\topenvpn\tovpn-main\tsession-a\t10.66.0.2\t203.0.113.7\t1700000000\t1194",
		"129939\twireguard\twg0\tsession-b\t10.69.0.3\t\t1700000000",
		"129940\twireguard\twg0\tsession-c\t10.69.0.4\t\t1700000000",
		"129939\tl2tp\tl2tp-main\tsession-d\tnot-an-ip\t\t1700000000",
		"129939\tl2tp\tl2tp-main\tsession-e\t2001:db8::1\t\t1700000000",
		"129939\tanyconnect\tac\tsession-f\t10.71.0.9",
		"short\tline",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "vpn-sessions.tsv"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	bindings := userSpeedLimitVPNBindings(dir, []userSpeedLimit{{UserID: 129939, SpeedLimitKbps: 5000}, {UserID: 129940, SpeedLimitKbps: 0}})
	want := []userSpeedLimitBinding{{IP: "10.66.0.2", UserID: 129939}, {IP: "10.69.0.3", UserID: 129939}, {IP: "10.71.0.9", UserID: 129939}}
	if !reflect.DeepEqual(bindings, want) {
		t.Fatalf("bindings = %v, want %v", bindings, want)
	}
}

func TestUserSpeedLimitNFTScriptIncludesVPNOnlyUsers(t *testing.T) {
	limits := []userSpeedLimit{{UserID: 42, SpeedLimitKbps: 5000}}
	bindings := []userSpeedLimitBinding{{IP: "10.69.0.9", UserID: 42}}
	script := userSpeedLimitNFTScript(nil, limits, bindings)
	for _, want := range []string{
		"chain lim_in_42 { limit rate over 625000 bytes/second burst 156250 bytes drop; }",
		"chain lim_out_42 { limit rate over 625000 bytes/second burst 156250 bytes drop; }",
		"map vpn_up { type ipv4_addr : verdict; elements = { 10.69.0.9 : jump lim_out_42 }; }",
		"map vpn_down { type ipv4_addr : verdict; elements = { 10.69.0.9 : jump lim_in_42 }; }",
		"chain vpn_pre { type filter hook prerouting priority 0; policy accept; ip saddr vmap @vpn_up; }",
		"chain vpn_fwd { type filter hook forward priority 0; policy accept; ip daddr vmap @vpn_down; }",
		"chain vpn_out { type filter hook output priority 0; policy accept; ip daddr vmap @vpn_down; }",
		"map in_limits { type mark : verdict; }",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script misses %q:\n%s", want, script)
		}
	}
}
