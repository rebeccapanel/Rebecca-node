package node

import "testing"

func TestManagedProxyOutboundParsing(t *testing.T) {
	outbound := map[string]any{
		"tag": "custom", "rebecca_proxy": "windscribe", "rebecca_proxy_location": "de", "protocol": "socks",
		"settings": map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": float64(18080),
			"users": []any{map[string]any{"user": "proxy-user", "pass": "proxy-pass"}},
		}}},
	}
	if got := managedProxyKind(outbound); got != "windscribe" {
		t.Fatalf("managed kind = %q", got)
	}
	port, user, pass, ok := localSocksDetails(outbound)
	if !ok || port != 18080 || user != "proxy-user" || pass != "proxy-pass" {
		t.Fatalf("unexpected local SOCKS details: %d %q %q %v", port, user, pass, ok)
	}
	if got := managedCountry(outbound["tag"].(string), "windscribe"); got != "" {
		t.Fatalf("custom tag should not infer a location: %q", got)
	}
}
