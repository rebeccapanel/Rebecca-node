package node

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func TestCacheUserMutationDoesNotBlockControlState(t *testing.T) {
	s := &Server{settings: appconfig.Settings{RebeccaDataDir: t.TempDir()}, core: &xray.Core{}}
	s.saveConfigCache(`{"inbounds":[{"tag":"vless","protocol":"vless","settings":{"clients":[]}}],"outbounds":[]}`, "127.0.0.1", nil, nil, nil, nil)
	user := xray.InboundUser{Email: "1.test", Protocol: "vless", ID: "11111111-1111-4111-8111-111111111111"}
	for _, mutate := range []func() error{
		func() error { return s.addUserToConfigCache("vless", user) },
		func() error { return s.removeUserFromConfigCache("vless", user.Email) },
	} {
		done := make(chan error, 1)
		go func() {
			err := mutate()
			if err == nil {
				s.grpcRuntimeState("healthy")
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("user cache mutation deadlocked node control requests")
		}
	}
	payload, ok := s.loadConfigCache()
	if !ok || len(cacheTestClients(t, payload.Config)) != 0 {
		t.Fatal("user cache mutation was not persisted")
	}
}

func TestLiveAndReconciledUsersInheritVLESSInboundFlow(t *testing.T) {
	s := &Server{settings: appconfig.Settings{RebeccaDataDir: t.TempDir()}, core: &xray.Core{}}
	raw := `{"inbounds":[{"tag":"vision","protocol":"vless","settings":{"flow":"xtls-rprx-vision","clients":[{"email":"1.old","id":"11111111-1111-4111-8111-111111111111"}]}},{"tag":"plain","protocol":"vless","settings":{"clients":[]}}],"outbounds":[]}`
	s.saveConfigCache(raw, "127.0.0.1", nil, nil, nil, nil)
	for _, tag := range []string{"vision", "plain"} {
		user, err := s.inheritInboundUserFlow(tag, xray.InboundUser{Protocol: "vless", Email: "2.new", ID: "22222222-2222-4222-8222-222222222222"})
		if err != nil {
			t.Fatal(err)
		}
		want := ""
		if tag == "vision" {
			want = "xtls-rprx-vision"
		}
		if user.Flow != want {
			t.Fatalf("%s live user flow=%q, want %q", tag, user.Flow, want)
		}
	}
	states, err := configClientStates(raw)
	if err != nil {
		t.Fatal(err)
	}
	if states["vision"].clients["1.old"].Flow != "xtls-rprx-vision" {
		t.Fatal("reconciliation did not inherit effective account flow")
	}
	// Old live-added accounts can lack Flow even when the cached JSON has a
	// default. A full sync with explicit Flow must repair them, not skip them.
	explicit := strings.Replace(raw, `"email":"1.old"`, `"flow":"xtls-rprx-vision","email":"1.old"`, 1)
	diff, err := configUserDiff(raw, explicit)
	if err != nil || len(diff.update) != 1 || diff.update[0].current.Flow != "xtls-rprx-vision" {
		t.Fatalf("legacy account was not scheduled for repair: %+v, %v", diff, err)
	}
	user, err := s.inheritInboundUserFlow("vision", xray.InboundUser{Protocol: "vless", Flow: "explicit"})
	if err != nil || user.Flow != "explicit" {
		t.Fatal("explicit account override changed")
	}
}

func TestPatchConfigCacheUserJSONAddsAndReplacesUser(t *testing.T) {
	raw := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[{"email":"1.old","id":"old-id"}]}}]}`

	updated, changed, err := patchConfigCacheUserJSON(raw, "vless-ws", xray.InboundUser{
		Protocol: "vless",
		Email:    "2.alice",
		ID:       "11111111-1111-4111-8111-111111111111",
		Flow:     "xtls-rprx-vision",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected cache to change")
	}
	clients := cacheTestClients(t, updated)
	if len(clients) != 2 {
		t.Fatalf("expected two clients, got %#v", clients)
	}
	if clients[1]["email"] != "2.alice" || clients[1]["id"] != "11111111-1111-4111-8111-111111111111" || clients[1]["flow"] != "xtls-rprx-vision" {
		t.Fatalf("unexpected added client: %#v", clients[1])
	}

	replaced, changed, err := patchConfigCacheUserJSON(updated, "vless-ws", xray.InboundUser{
		Protocol: "vless",
		Email:    "2.alice",
		ID:       "22222222-2222-4222-8222-222222222222",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected replacement to change cache")
	}
	clients = cacheTestClients(t, replaced)
	if len(clients) != 2 {
		t.Fatalf("expected replacement without duplicate, got %#v", clients)
	}
	if clients[1]["id"] != "22222222-2222-4222-8222-222222222222" {
		t.Fatalf("expected replacement id, got %#v", clients[1])
	}
}

func TestPatchConfigCacheUserJSONRemovesUser(t *testing.T) {
	raw := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[{"email":"1.old","id":"old-id"},{"email":"2.alice","id":"alice-id"}]}}]}`

	updated, changed, err := patchConfigCacheUserJSON(raw, "vless-ws", xray.InboundUser{}, "2.alice")
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected cache to change")
	}
	clients := cacheTestClients(t, updated)
	if len(clients) != 1 {
		t.Fatalf("expected one remaining client, got %#v", clients)
	}
	if clients[0]["email"] != "1.old" {
		t.Fatalf("unexpected remaining client: %#v", clients[0])
	}
}

func TestConfigUserDiffAddsUpdatesAndRemovesUsers(t *testing.T) {
	cached := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[{"email":"1.old","id":"old-id"},{"email":"2.alice","id":"alice-id"}]}}]}`
	incoming := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[{"email":"2.alice","id":"alice-new-id","flow":"xtls-rprx-vision"},{"email":"3.bob","id":"bob-id"}]}}]}`

	diff, err := configUserDiff(cached, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.remove) != 1 {
		t.Fatalf("expected one deleted user removal, got %#v", diff.remove)
	}
	if diff.remove[0].inboundTag != "vless-ws" || diff.remove[0].email != "1.old" {
		t.Fatalf("unexpected deleted user removal: %#v", diff.remove[0])
	}
	if len(diff.update) != 1 || diff.update[0].inboundTag != "vless-ws" || diff.update[0].previous.ID != "alice-id" || diff.update[0].current.ID != "alice-new-id" {
		t.Fatalf("unexpected user update: %#v", diff.update)
	}
	if len(diff.add) != 1 {
		t.Fatalf("expected one new user addition, got %#v", diff.add)
	}
	if item := diff.add[0]; item.inboundTag != "vless-ws" || item.user.Email != "3.bob" || item.user.ID != "bob-id" {
		t.Fatalf("unexpected new user addition: %#v", item)
	}
}

func TestApplyConfigUserDiffRestoresPreviousUserWhenUpdateFails(t *testing.T) {
	previous := xray.InboundUser{Protocol: "vless", Email: "2.alice", ID: "old-id"}
	current := xray.InboundUser{Protocol: "vless", Email: "2.alice", ID: "new-id"}
	diff := configUserDiffResult{update: []configUserUpdate{{inboundTag: "vless-ws", previous: previous, current: current}}}
	calls := []string{}
	err := applyConfigUserDiff(diff,
		func(tag string, user xray.InboundUser) error {
			calls = append(calls, "add:"+user.ID)
			if user.ID == current.ID {
				return errors.New("temporary Xray API failure")
			}
			return nil
		},
		func(tag string, email string) error {
			calls = append(calls, "remove:"+email)
			return nil
		},
	)
	if err == nil || err.Error() != "temporary Xray API failure" {
		t.Fatalf("expected original update error, got %v", err)
	}
	want := []string{"remove:2.alice", "add:new-id", "add:old-id"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unexpected update/restore calls: got %#v want %#v", calls, want)
	}
}

func TestConfigUserDiffKeepsVLESSReverseTag(t *testing.T) {
	cached := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[]}}]}`
	incoming := `{"inbounds":[{"tag":"vless-ws","protocol":"vless","settings":{"clients":[{"email":"reverse.tunnel","id":"11111111-1111-4111-8111-111111111111","reverse":{"tag":"reverse-out"}}]}}]}`

	diff, err := configUserDiff(cached, incoming)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.add) != 1 || diff.add[0].user.ReverseTag != "reverse-out" {
		t.Fatalf("reverse tag was not added to the runtime diff: %#v", diff.add)
	}
}

func cacheTestClients(t *testing.T, raw string) []map[string]any {
	t.Helper()
	var config struct {
		Inbounds []struct {
			Settings struct {
				Clients []map[string]any `json:"clients"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Inbounds) != 1 {
		t.Fatalf("expected one inbound, got %#v", config.Inbounds)
	}
	return config.Inbounds[0].Settings.Clients
}
