package xray

import (
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type concurrentOnlineIPClient struct {
	active atomic.Int32
	peak   atomic.Int32
	fail   string
}

func (c *concurrentOnlineIPClient) GetStatsOnlineIpList(_ context.Context, request *statscommand.GetStatsRequest, _ ...grpc.CallOption) (*statscommand.GetStatsOnlineIpListResponse, error) {
	if c.fail != "" && strings.Contains(request.GetName(), c.fail) {
		return nil, status.Error(codes.Unavailable, "temporary failure")
	}
	active := c.active.Add(1)
	for peak := c.peak.Load(); active > peak && !c.peak.CompareAndSwap(peak, active); peak = c.peak.Load() {
	}
	time.Sleep(5 * time.Millisecond)
	c.active.Add(-1)
	return &statscommand.GetStatsOnlineIpListResponse{Name: request.GetName(), Ips: map[string]int64{"198.51.100.10": 100}}, nil
}

func TestQueryOnlineUserIPsPreservesPartialResults(t *testing.T) {
	client := &concurrentOnlineIPClient{fail: "2.user"}
	users, err := queryOnlineUserIPs(context.Background(), client, []string{
		"user>>>1.user>>>online", "user>>>2.user>>>online", "user>>>3.user>>>online",
	}, nil)
	if err == nil {
		t.Fatal("expected partial query error")
	}
	if len(users) != 2 {
		t.Fatalf("partial users=%d want=2", len(users))
	}
}

func TestOnlineUserUIDsReturnsUniqueSortedSnapshot(t *testing.T) {
	got := onlineUserUIDs([]string{
		"user>>>20.second>>>online",
		"user>>>10.first>>>online",
		"user>>>20.second>>>online",
		"",
	})
	if len(got) != 2 || got[0] != "10" || got[1] != "20" {
		t.Fatalf("online user snapshot=%v", got)
	}
}

func TestParseOutboundStatName(t *testing.T) {
	tag, link, ok := parseOutboundStatName("outbound>>>proxy>>>traffic>>>uplink")
	if !ok || tag != "proxy" || link != "uplink" {
		t.Fatalf("unexpected parse result: tag=%q link=%q ok=%v", tag, link, ok)
	}

	if _, _, ok := parseOutboundStatName("user>>>1.test>>>traffic>>>uplink"); ok {
		t.Fatal("non-outbound stats should be ignored")
	}
}

func TestParseInboundStatName(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		link string
		ok   bool
	}{
		{name: "inbound>>>vless-in>>>traffic>>>uplink", tag: "vless-in", link: "uplink", ok: true},
		{name: "inbound>>>vless-in>>>traffic>>>downlink", tag: "vless-in", link: "downlink", ok: true},
		{name: "outbound>>>proxy>>>traffic>>>uplink", ok: false},
		{name: "inbound>>>>>>traffic>>>uplink", ok: false},
		{name: "inbound>>>vless-in>>>traffic>>>other", ok: false},
	}
	for _, test := range tests {
		tag, link, ok := parseInboundStatName(test.name)
		if tag != test.tag || link != test.link || ok != test.ok {
			t.Fatalf("parseInboundStatName(%q) = (%q, %q, %v), want (%q, %q, %v)", test.name, tag, link, ok, test.tag, test.link, test.ok)
		}
	}
}

func TestInboundStatsFromCountersMapsDirectionsAndMissingCounters(t *testing.T) {
	stats := inboundStatsFromCounters([]*statscommand.Stat{
		{Name: "inbound>>>shared>>>traffic>>>uplink", Value: 10},
		{Name: "inbound>>>shared>>>traffic>>>downlink", Value: 20},
		{Name: "inbound>>>upload-only>>>traffic>>>uplink", Value: 5},
		{Name: "inbound>>>api>>>traffic>>>uplink", Value: 99},
		{Name: "inbound>>>API_INBOUND>>>traffic>>>downlink", Value: 99},
		{Name: "inbound>>>shared>>>traffic>>>uplink", Value: -1},
		nil,
	})
	if len(stats) != 2 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if stats[0] != (InboundStat{Tag: "shared", Up: 10, Down: 20}) {
		t.Fatalf("uplink/downlink mapping changed: %#v", stats[0])
	}
	if stats[1] != (InboundStat{Tag: "upload-only", Up: 5}) {
		t.Fatalf("missing downlink counter should remain zero: %#v", stats[1])
	}
	if missing := inboundStatsFromCounters(nil); len(missing) != 0 {
		t.Fatalf("disabled stats should return an empty result: %#v", missing)
	}
}

func TestInboundStatsFromCountersSaturatesDuplicateCounters(t *testing.T) {
	stats := inboundStatsFromCounters([]*statscommand.Stat{
		{Name: "inbound>>>shared>>>traffic>>>uplink", Value: math.MaxInt64 - 1},
		{Name: "inbound>>>shared>>>traffic>>>uplink", Value: 10},
	})
	if len(stats) != 1 || stats[0].Up != math.MaxInt64 {
		t.Fatalf("duplicate counters must saturate instead of wrapping: %#v", stats)
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

func TestUserStatsKeepInboundDimensionsSeparate(t *testing.T) {
	encode := func(tag string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(tag))
	}
	stats := userStatsFromCounters([]*statscommand.Stat{
		{Name: "user>>>42.rb1_" + encode("germany-vless") + ".alice>>>traffic>>>uplink", Value: 10},
		{Name: "user>>>42.rb1_" + encode("germany-vless") + ".alice>>>traffic>>>downlink", Value: 20},
		{Name: "user>>>42.rb1_" + encode("تهران") + ".alice>>>traffic>>>uplink", Value: 5},
		{Name: "user>>>42.alice>>>traffic>>>uplink", Value: 7},
	})
	if len(stats) != 3 {
		t.Fatalf("stats=%#v", stats)
	}
	want := map[string]int64{"": 7, "germany-vless": 30, "تهران": 5}
	for _, stat := range stats {
		if stat.UID != "42" || want[stat.InboundTag] != stat.Value {
			t.Fatalf("unexpected stat: %#v", stat)
		}
	}
	if stats[1].Up != 10 || stats[1].Down != 20 {
		t.Fatalf("directional counters were lost: %#v", stats[1])
	}
}

func TestParseOnlineUserName(t *testing.T) {
	tests := []struct {
		name  string
		email string
		uid   string
		ok    bool
	}{
		{name: "user>>>abc123.example>>>online", email: "abc123.example", uid: "abc123", ok: true},
		{name: "abc123.example", email: "abc123.example", uid: "abc123", ok: true},
		{name: "user>>>>>>online", ok: false},
		{name: "", ok: false},
	}

	for _, tt := range tests {
		email, uid, ok := parseOnlineUserName(tt.name)
		if ok != tt.ok || email != tt.email || uid != tt.uid {
			t.Fatalf("parseOnlineUserName(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.name, email, uid, ok, tt.email, tt.uid, tt.ok)
		}
	}
}

func TestParseUserEmailUID(t *testing.T) {
	uid, ok := parseUserEmailUID("42.alice")
	if !ok || uid != "42" {
		t.Fatalf("unexpected parse result: uid=%q ok=%v", uid, ok)
	}

	uid, ok = parseUserEmailUID("42")
	if !ok || uid != "42" {
		t.Fatalf("unexpected parse result without suffix: uid=%q ok=%v", uid, ok)
	}

	if _, ok := parseUserEmailUID(""); ok {
		t.Fatal("empty email should be ignored")
	}
}

func TestQueryOnlineUserIPsUsesBoundedWorkers(t *testing.T) {
	names := make([]string, 24)
	for index := range names {
		names[index] = fmt.Sprintf("user>>>%d.user>>>online", index+1)
	}
	client := &concurrentOnlineIPClient{}
	users, err := queryOnlineUserIPs(context.Background(), client, names, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != len(names) {
		t.Fatalf("users=%d want=%d", len(users), len(names))
	}
	if peak := client.peak.Load(); peak < 2 || peak > 8 {
		t.Fatalf("worker peak=%d want 2..8", peak)
	}
}

func TestQueryOnlineUserIPsCapsLargeSnapshots(t *testing.T) {
	names := make([]string, maxOnlineIPLookups+40)
	for index := range names {
		names[index] = fmt.Sprintf("user>>>%d.user>>>online", index+1)
	}
	client := &concurrentOnlineIPClient{}
	users, err := queryOnlineUserIPs(context.Background(), client, names, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != maxOnlineIPLookups {
		t.Fatalf("users=%d want=%d", len(users), maxOnlineIPLookups)
	}
}

func TestQueryOnlineUserIPsScopeLookupsOnlyScopedUsersWithoutCap(t *testing.T) {
	names := make([]string, maxOnlineIPLookups+40)
	scoped := make(map[string]struct{}, maxOnlineIPLookups+8)
	for index := range names {
		uid := fmt.Sprint(index + 1)
		names[index] = "user>>>" + uid + ".user>>>online"
		if index < maxOnlineIPLookups+8 {
			scoped[uid] = struct{}{}
		}
	}
	client := &concurrentOnlineIPClient{}
	users, err := queryOnlineUserIPs(context.Background(), client, names, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != len(scoped) {
		t.Fatalf("users=%d want=%d", len(users), len(scoped))
	}
}

func TestQueryOnlineUserIPsEmptyScopeSkipsAllLookups(t *testing.T) {
	names := []string{"user>>>1.user>>>online", "user>>>2.user>>>online"}
	client := &concurrentOnlineIPClient{}
	users, err := queryOnlineUserIPs(context.Background(), client, names, map[string]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Fatalf("users=%d want=0", len(users))
	}
	if peak := client.peak.Load(); peak != 0 {
		t.Fatalf("lookups ran with empty scope, peak=%d", peak)
	}
}
