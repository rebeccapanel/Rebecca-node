package xray

import (
	"encoding/json"
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

	levels := policy["levels"].(map[string]any)
	level0 := levels["0"].(map[string]any)
	if level0["statsUserUplink"] != true || level0["statsUserDownlink"] != true {
		t.Fatalf("user stats were not enabled: %#v", level0)
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
