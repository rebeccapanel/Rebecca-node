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
	if settings, _ := delta.addInbounds[0]["settings"].(map[string]any); settings["clients"] == nil {
		t.Fatalf("runtime add must carry the inbound's clients, got %v", settings)
	}
	if !reflect.DeepEqual(delta.freshInboundTags(), []string{"tunnel-a"}) {
		t.Fatalf("added inbounds must be skipped by the user diff, got %v", delta.freshInboundTags())
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

func TestRuntimeTopologyDeltaSwapsChangedInboundWithItsClients(t *testing.T) {
	incoming := parseUserSpeedLimitTestDoc(t, `{
	  "inbounds": [
	    {"tag": "API", "protocol": "dokodemo-door"},
	    {"tag": "vless-a", "protocol": "vless", "port": 8443, "settings": {"clients": [{"email": "1.a"}, {"email": "2.b"}]}}
	  ],
	  "outbounds": [{"tag": "direct", "protocol": "freedom"}],
	  "routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}
	}`)
	delta, ok := runtimeTopologyDeltaFor(parseUserSpeedLimitTestDoc(t, runtimeTopologyCachedDoc), incoming)
	if !ok {
		t.Fatalf("a changed inbound must be swapped without a restart")
	}
	if !reflect.DeepEqual(delta.removeInbounds, []string{"vless-a"}) || len(delta.addInbounds) != 1 {
		t.Fatalf("expected remove+add of vless-a, got %+v", delta)
	}
	settings, _ := delta.addInbounds[0]["settings"].(map[string]any)
	if clients, _ := settings["clients"].([]any); len(clients) != 2 {
		t.Fatalf("swapped inbound must carry all clients, got %v", settings)
	}
	if !reflect.DeepEqual(delta.freshInboundTags(), []string{"vless-a"}) {
		t.Fatalf("swapped inbound must be skipped by the user diff, got %v", delta.freshInboundTags())
	}
}

func TestRuntimeTopologyDeltaReloadsOutboundsByTag(t *testing.T) {
	cached := parseUserSpeedLimitTestDoc(t, `{
	  "inbounds": [{"tag": "API_INBOUND", "protocol": "dokodemo-door"}],
	  "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "socks", "settings": {"port": 1}}, {"tag": "old", "protocol": "freedom"}],
	  "routing": {"rules": []}
	}`)
	incoming := parseUserSpeedLimitTestDoc(t, `{
	  "inbounds": [{"tag": "API_INBOUND", "protocol": "dokodemo-door"}],
	  "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "warp", "protocol": "socks", "settings": {"port": 2}}, {"tag": "new", "protocol": "freedom"}],
	  "routing": {"rules": []}
	}`)
	delta, ok := runtimeTopologyDeltaFor(cached, incoming)
	if !ok {
		t.Fatalf("non-default outbound changes must apply at runtime")
	}
	if !reflect.DeepEqual(delta.removeOutbounds, []string{"warp", "old"}) {
		t.Fatalf("unexpected removed outbounds %v", delta.removeOutbounds)
	}
	if len(delta.addOutbounds) != 2 || delta.addOutbounds[0]["tag"] != "warp" || delta.addOutbounds[1]["tag"] != "new" {
		t.Fatalf("unexpected added outbounds %v", delta.addOutbounds)
	}
	if !delta.touchesRoutingBase() {
		t.Fatalf("outbound changes must invalidate the speed-limit plan")
	}
}

func TestRuntimeTopologyDeltaRejectsChangesThatNeedRestart(t *testing.T) {
	const apiInbound = `{"tag": "API", "protocol": "dokodemo-door"}`
	const vlessInbound = `{"tag": "vless-a", "protocol": "vless", "port": 443, "settings": {"clients": []}}`
	const direct = `{"tag": "direct", "protocol": "freedom"}`
	const rules = `"routing": {"rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}`
	cases := map[string]string{
		"default outbound change": `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `], "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}], ` + rules + `}`,
		"routing setting":         `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `], "outbounds": [` + direct + `], "routing": {"domainStrategy": "IPIfNonMatch", "rules": [{"type": "field", "inboundTag": ["vless-a"], "outboundTag": "direct"}]}}`,
		"routing removed":         `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `], "outbounds": [` + direct + `]}`,
		"dns change":              `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `], "outbounds": [` + direct + `], "dns": {"servers": ["1.1.1.1"]}, ` + rules + `}`,
		"policy change":           `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `], "outbounds": [` + direct + `], "policy": {"system": {"statsInboundUplink": true}}, ` + rules + `}`,
		"api inbound change":      `{"inbounds": [{"tag": "API_INBOUND", "protocol": "dokodemo-door", "port": 1}, ` + vlessInbound + `], "outbounds": [` + direct + `], ` + rules + `}`,
		"reality inbound":         `{"inbounds": [` + apiInbound + `, {"tag": "vless-a", "protocol": "vless", "port": 443, "streamSettings": {"security": "reality"}, "settings": {"clients": []}}], "outbounds": [` + direct + `], ` + rules + `}`,
		"tproxy inbound":          `{"inbounds": [` + apiInbound + `, {"tag": "tp", "protocol": "tunnel", "port": 1, "streamSettings": {"sockopt": {"tproxy": "tproxy"}}, "settings": {}}, ` + vlessInbound + `], "outbounds": [` + direct + `], ` + rules + `}`,
		"duplicate inbound tag":   `{"inbounds": [` + apiInbound + `, ` + vlessInbound + `, ` + vlessInbound + `], "outbounds": [` + direct + `], ` + rules + `}`,
	}
	for name, raw := range cases {
		if _, ok := runtimeTopologyDeltaFor(parseUserSpeedLimitTestDoc(t, runtimeTopologyCachedDoc), parseUserSpeedLimitTestDoc(t, raw)); ok {
			t.Fatalf("%s must keep the restart path", name)
		}
	}
}

func TestConfigUserDiffSkipsSwappedInbounds(t *testing.T) {
	diff := configUserDiffResult{
		add:    []configUserAdd{{inboundTag: "a"}, {inboundTag: "b"}},
		remove: []configUserRemove{{inboundTag: "a"}},
		update: []configUserUpdate{{inboundTag: "b"}},
	}
	kept := diff.withoutInboundTags([]string{"a"})
	if len(kept.add) != 1 || kept.add[0].inboundTag != "b" || len(kept.remove) != 0 || len(kept.update) != 1 {
		t.Fatalf("unexpected filtered diff %+v", kept)
	}
	if got := diff.withoutInboundTags(nil); len(got.add) != 2 {
		t.Fatalf("no tags must keep everything, got %+v", got)
	}
}
