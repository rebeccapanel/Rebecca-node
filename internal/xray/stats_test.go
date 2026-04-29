package xray

import "testing"

func TestParseOutboundStatName(t *testing.T) {
	tag, link, ok := parseOutboundStatName("outbound>>>proxy>>>traffic>>>uplink")
	if !ok || tag != "proxy" || link != "uplink" {
		t.Fatalf("unexpected parse result: tag=%q link=%q ok=%v", tag, link, ok)
	}

	if _, _, ok := parseOutboundStatName("user>>>1.test>>>traffic>>>uplink"); ok {
		t.Fatal("non-outbound stats should be ignored")
	}
}

func TestParseUserStatName(t *testing.T) {
	uid, ok := parseUserStatName("user>>>42.alice>>>traffic>>>downlink")
	if !ok || uid != "42" {
		t.Fatalf("unexpected parse result: uid=%q ok=%v", uid, ok)
	}

	if _, ok := parseUserStatName("outbound>>>proxy>>>traffic>>>uplink"); ok {
		t.Fatal("non-user stats should be ignored")
	}
}
