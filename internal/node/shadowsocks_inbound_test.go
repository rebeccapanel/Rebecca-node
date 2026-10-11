package node

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func TestPatchConfigCacheUserOmitsMethodForShadowsocks2022(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	raw := `{"inbounds":[{"tag":"ss","protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-256-gcm","clients":[]}}]}`
	user := xray.InboundUser{Protocol: "shadowsocks", Email: "u1", Password: key, Method: "2022-blake3-aes-256-gcm"}
	patched, changed, err := patchConfigCacheUserJSON(raw, "ss", user, "")
	if err != nil || !changed {
		t.Fatalf("patch changed=%v err=%v", changed, err)
	}
	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []map[string]any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(patched), &config); err != nil {
		t.Fatal(err)
	}
	clients := config.Inbounds[0].Settings.Clients
	if len(clients) != 1 {
		t.Fatalf("expected one client, got %d", len(clients))
	}
	if _, ok := clients[0]["method"]; ok {
		t.Fatalf("a 2022 client must not carry a method: %#v", clients[0])
	}
}

func TestShadowsocksInboundMethodFollowsTheInbound(t *testing.T) {
	methods := map[string]string{"ss": "2022-blake3-aes-256-gcm"}
	user := withShadowsocksInboundMethod(xray.InboundUser{Protocol: "shadowsocks", Method: "chacha20-ietf-poly1305"}, methods, "ss")
	if user.Method != "2022-blake3-aes-256-gcm" {
		t.Fatalf("method = %q, want the inbound method", user.Method)
	}
	other := withShadowsocksInboundMethod(xray.InboundUser{Protocol: "vless", Method: "x"}, methods, "ss")
	if other.Method != "x" {
		t.Fatalf("non-shadowsocks user method changed to %q", other.Method)
	}
}

func TestShadowsocksMethodsFromConfigReadsShadowsocksInbounds(t *testing.T) {
	raw := `{"inbounds":[{"tag":"ss","protocol":"shadowsocks","settings":{"method":"2022-blake3-aes-256-gcm"}},{"tag":"v","protocol":"vless","settings":{}}]}`
	methods := shadowsocksMethodsFromConfig(raw)
	if methods["ss"] != "2022-blake3-aes-256-gcm" || len(methods) != 1 {
		t.Fatalf("unexpected methods: %#v", methods)
	}
}
