package node

import (
	"fmt"
	"os"
	"strings"
	"testing"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func TestConfigCacheBatchWritesOnceAtTheEnd(t *testing.T) {
	s := &Server{settings: appconfig.Settings{RebeccaDataDir: t.TempDir()}, core: &xray.Core{}}
	initial := `{"config":"{\"inbounds\":[{\"tag\":\"vless-ws\",\"protocol\":\"vless\",\"settings\":{\"clients\":[]}}]}","peer_ip":"127.0.0.1","applied_revision":7}`
	if err := os.WriteFile(s.configCachePath(), []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	s.beginConfigCacheBatch()
	for index := 0; index < 50; index++ {
		user := xray.InboundUser{Protocol: "vless", Email: fmt.Sprintf("%d.user", index), ID: "11111111-1111-4111-8111-111111111111"}
		if err := s.addUserToConfigCache("vless-ws", user); err != nil {
			t.Fatal(err)
		}
	}
	onDisk, err := os.ReadFile(s.configCachePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != initial {
		t.Fatal("cache file must not be rewritten for each user inside a batch")
	}
	payload, ok := s.loadConfigCache()
	if !ok || !strings.Contains(payload.Config, "49.user") || payload.AppliedRevision != 7 {
		t.Fatalf("batch reads must see the patched cache, got ok=%v revision=%d", ok, payload.AppliedRevision)
	}

	if err := s.endConfigCacheBatch(); err != nil {
		t.Fatal(err)
	}
	saved, ok := s.readConfigCacheFile()
	if !ok || strings.Count(saved.Config, ".user") != 50 || saved.AppliedRevision != 7 {
		t.Fatalf("flushed cache must hold all users and keep the revision, got ok=%v users=%d revision=%d", ok, strings.Count(saved.Config, ".user"), saved.AppliedRevision)
	}
}
