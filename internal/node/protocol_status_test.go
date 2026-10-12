package node

import (
	"strings"
	"testing"
)

func TestProtocolStateAndProcessStatParsing(t *testing.T) {
	if got := protocolState("openvpn", 2, 1, ""); got.GetState() != "error" || !strings.HasPrefix(got.GetDetail(), "1/2 running") || !strings.Contains(got.GetDetail(), "not running") {
		t.Fatalf("partial protocol state = %#v", got)
	}
	if got := protocolState("wireguard", 0, 0, ""); got.GetState() != "idle" {
		t.Fatalf("empty protocol state = %#v", got)
	}
	stat := "42 (xray core) S 1 2 3 4 5 6 7 8 9 10 25 17 0 0"
	if ticks, ok := parseProcessTicks(stat); !ok || ticks != 42 {
		t.Fatalf("process ticks = %d, %v", ticks, ok)
	}
}
