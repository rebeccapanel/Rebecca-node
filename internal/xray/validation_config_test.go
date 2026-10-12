package xray

import (
	"encoding/json"
	"testing"
)

func TestForceWireGuardUserspaceOnlyChangesWireGuardOutbounds(t *testing.T) {
	raw := []byte(`{"inbounds":[{"tag":"vless","port":443,"protocol":"vless"}],"outbounds":[{"tag":"wg","protocol":"wireguard","settings":{"secretKey":"k","noKernelTun":false,"address":["10.0.0.2/32"]}},{"tag":"direct","protocol":"freedom","settings":{"noKernelTun":false}}]}`)
	out, err := forceWireGuardUserspace(raw)
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []struct {
			Protocol string         `json:"protocol"`
			Settings map[string]any `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &data); err != nil {
		t.Fatal(err)
	}
	if data.Outbounds[0].Settings["noKernelTun"] != true {
		t.Fatalf("wireguard outbound must use userspace validation: %#v", data.Outbounds[0].Settings)
	}
	if data.Outbounds[0].Settings["secretKey"] != "k" {
		t.Fatalf("wireguard settings must be preserved: %#v", data.Outbounds[0].Settings)
	}
	if data.Outbounds[1].Settings["noKernelTun"] != false {
		t.Fatalf("non-wireguard outbounds must not change: %#v", data.Outbounds[1].Settings)
	}
	if data.Inbounds[0]["port"] != float64(443) {
		t.Fatalf("inbounds must be preserved: %#v", data.Inbounds[0])
	}
}
