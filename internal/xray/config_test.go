package xray

import (
	"encoding/json"
	"fmt"
	"testing"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
)

func TestNewConfigForcesStatsPolicy(t *testing.T) {
	raw := `{
		"inbounds": [],
		"outbounds": [{"tag": "direct", "protocol": "freedom"}],
		"routing": {"rules": []}
	}`

	cfg, err := NewConfig(raw, "127.0.0.1", appconfig.Settings{
		XrayAPIHost: "127.0.0.1",
		XrayAPIPort: 62051,
		SSLCertFile: "/tmp/cert.pem",
		SSLKeyFile:  "/tmp/key.pem",
	})
	if err != nil {
		t.Fatalf("NewConfig failed: %v", err)
	}

	payload := map[string]any{}
	if err := json.Unmarshal(mustJSON(t, cfg), &payload); err != nil {
		t.Fatalf("config JSON is invalid: %v", err)
	}

	policy := payload["policy"].(map[string]any)
	system := policy["system"].(map[string]any)
	if system["statsOutboundUplink"] != true || system["statsOutboundDownlink"] != true {
		t.Fatalf("outbound stats were not enabled: %#v", system)
	}
	if system["statsInboundUplink"] != true {
		t.Fatalf("missing inbound uplink toggle should enable inbound statistics: %#v", system)
	}
	if system["statsInboundDownlink"] != true {
		t.Fatalf("missing inbound downlink toggle should enable inbound statistics: %#v", system)
	}

	levels := policy["levels"].(map[string]any)
	level0 := levels["0"].(map[string]any)
	if level0["statsUserUplink"] != true || level0["statsUserDownlink"] != true || level0["statsUserOnline"] != true {
		t.Fatalf("user stats were not enabled: %#v", level0)
	}
}

func TestNewConfigPreservesIndependentInboundStatsToggles(t *testing.T) {
	for _, test := range []struct {
		name     string
		uplink   bool
		downlink bool
	}{
		{name: "both disabled"},
		{name: "uplink only", uplink: true},
		{name: "downlink only", downlink: true},
		{name: "both enabled", uplink: true, downlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
				"inbounds": [],
				"outbounds": [{"tag": "direct", "protocol": "freedom"}],
				"routing": {"rules": []},
				"policy": {"system": {"statsInboundUplink": %t, "statsInboundDownlink": %t}}
			}`, test.uplink, test.downlink)
			cfg, err := NewConfig(raw, "127.0.0.1", appconfig.Settings{XrayAPIHost: "127.0.0.1", XrayAPIPort: 62051})
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{}
			if err := json.Unmarshal(mustJSON(t, cfg), &payload); err != nil {
				t.Fatal(err)
			}
			system := payload["policy"].(map[string]any)["system"].(map[string]any)
			if system["statsInboundUplink"] != test.uplink || system["statsInboundDownlink"] != test.downlink {
				t.Fatalf("inbound stats toggles changed: %#v", system)
			}
		})
	}
}

func mustJSON(t *testing.T, cfg *Config) []byte {
	t.Helper()
	data, err := cfg.JSON()
	if err != nil {
		t.Fatalf("JSON failed: %v", err)
	}
	return data
}
