package node

import (
	"reflect"
	"testing"
)

const runtimeTopologyCachedDoc = `{
  "inbounds": [
    {"tag": "API", "protocol": "dokodemo-door"},
    {"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": [{"email": "1.a"}]}}
  ],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
  "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}
}`

func TestRuntimeTopologyDeltaAddsRemovesInboundsAndRouting(t *testing.T) {
	incoming := parseUserSpeedLimitTestDoc(t, `{
	  "inbounds": [
	    {"tag": "API", "protocol": "dokodemo-door"},
	    {"tag": "tunnel-a", "protocol": "tunnel", "port": 41940, "settings": {"clients": []}}
	  ],
	  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
	  "routing": {"rules": [{"type": "field", "inboundTag": ["tunnel-a"], "outboundTag": "direct"}]}
	}`)
	delta, ok := runtimeTopologyDeltaFor(parseUserSpeedLimitTestDoc(t, runtimeTopologyCachedDoc), incoming)
	if !ok {
		t.Fatalf("inbound and routing changes must apply at runtime")
	}
	if len(delta.addInbounds) != 1 || delta.addInbounds[0]["tag"] != "tunnel-a" {
		t.Fatalf("expected tunnel-a to be added, got %v", delta.addInbounds)
	}
	if settings, _ := delta.addInbounds[0]["settings"].(map[string]any); settings["clients"] != nil {
		t.Fatalf("runtime add must not carry clients, got %v", settings)
	}
	if !reflect.DeepEqual(delta.removeInbounds, []string{"vless-a"}) {
		t.Fatalf("expected vless-a to be removed, got %v", delta.removeInbounds)
	}
	if delta.routing == nil {
		t.Fatalf("changed routing rules must be replaced")
	}
}

func TestRuntimeTopologyDeltaIgnoresClientOnlyChanges(t *testing.T) {
	incoming := parseUserSpeedLimitTestDoc(t, `{
	  "inbounds": [
	    {"tag": "API", "protocol": "dokodemo-door"},
	    {"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": [{"email": "1.a"}, {"email": "2.b"}]}}
	  ],
	  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
	  "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}
	}`)
	delta, ok := runtimeTopologyDeltaFor(parseUserSpeedLimitTestDoc(t, runtimeTopologyCachedDoc), incoming)
	if !ok || len(delta.addInbounds) != 0 || len(delta.removeInbounds) != 0 || delta.routing != nil {
		t.Fatalf("client-only changes belong to the user diff, got ok=%v delta=%+v", ok, delta)
	}
}

func TestRuntimeTopologyDeltaRejectsChangesThatNeedRestart(t *testing.T) {
	cases := map[string]string{
		"modified inbound": `{"inbounds": [{"tag": "API", "protocol": "dokodemo-door"}, {"tag": "vless-a", "protocol": "vless", "port": 8443, "settings": {"clients": []}}], "outbounds": [{"tag": "direct", "protocol": "freedom"}], "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}}`,
		"outbound change":  `{"inbounds": [{"tag": "API", "protocol": "dokodemo-door"}, {"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": []}}], "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}], "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}}`,
		"routing setting":  `{"inbounds": [{"tag": "API", "protocol": "dokodemo-door"}, {"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": []}}], "outbounds": [{"tag": "direct", "protocol": "freedom"}], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}}`,
		"dns change":       `{"inbounds": [{"tag": "API", "protocol": "dokodemo-door"}, {"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": []}}], "outbounds": [{"tag": "direct", "protocol": "freedom"}], "dns": {"servers": ["1.1.1.1"]}, "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}}`,
	}
	for name, raw := range cases {
		if _, ok := runtimeTopologyDeltaFor(parseUserSpeedLimitTestDoc(t, runtimeTopologyCachedDoc), parseUserSpeedLimitTestDoc(t, raw)); ok {
			t.Fatalf("%s must keep the restart path", name)
		}
	}
}
