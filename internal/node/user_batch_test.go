package node

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func startedBatchTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	executable := filepath.Join(dir, "xray")
	script := `#!/bin/sh
if [ "$1" = version ]; then echo 'Xray 26.5.9'; exit 0; fi
if [ "$2" = -test ]; then cat >/dev/null; exit 0; fi
cat >/dev/null
while :; do sleep 1; done
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	settings := appconfig.Settings{RebeccaDataDir: dir, XrayAssetsPath: dir, XrayLogDir: dir, XrayAPIHost: "127.0.0.1", XrayAPIPort: closedPort}
	core, err := xray.NewCore(executable, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.Stop)
	config, err := xray.NewConfig(`{"inbounds":[],"outbounds":[]}`, "127.0.0.1", settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(config); err != nil {
		t.Fatal(err)
	}
	return &Server{settings: settings, core: core, sessions: make(map[string]time.Time)}
}

func TestApplyUserBatchRejectsWhenXrayIsNotStarted(t *testing.T) {
	api := &grpcAPI{server: &Server{core: &xray.Core{}}}
	_, err := api.ApplyUserBatch(context.Background(), &nodev1.UserBatchRequest{
		BatchId:    "b1",
		Operations: []*nodev1.UserBatchOperation{{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_REMOVE, InboundTag: "in", Email: "u"}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition when Xray is not started, got %v", err)
	}
}

func TestApplyUserBatchStopsAtUnreachableXrayAPI(t *testing.T) {
	api := &grpcAPI{server: startedBatchTestServer(t)}
	response, err := api.ApplyUserBatch(context.Background(), &nodev1.UserBatchRequest{
		BatchId: "b2",
		Operations: []*nodev1.UserBatchOperation{
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_UPSERT, User: &nodev1.InboundUser{Email: "u1", Protocol: "vless", Fields: map[string]string{"id": "11111111-1111-1111-1111-111111111111"}}},
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_UPSERT, InboundTag: "vless-in", User: &nodev1.InboundUser{Email: "u2", Protocol: "vless", Fields: map[string]string{"id": "22222222-2222-2222-2222-222222222222"}}},
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_REMOVE, InboundTag: "vless-in", Email: "u3"},
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_UNSPECIFIED, InboundTag: "vless-in"},
		},
	})
	if err != nil {
		t.Fatalf("batch call failed as a whole instead of per operation: %v", err)
	}
	if response.GetBatchId() != "b2" || len(response.GetResults()) != 4 {
		t.Fatalf("unexpected response shape: %#v", response)
	}
	results := response.GetResults()
	if results[0].GetError() != "inbound_tag is required" {
		t.Fatalf("missing tag error = %q", results[0].GetError())
	}
	if msg := results[1].GetError(); !strings.Contains(msg, "Xray API is unavailable") {
		t.Fatalf("unreachable API error = %q", msg)
	}
	for _, result := range results[2:] {
		if result.GetError() != "not attempted: Xray API is unavailable" {
			t.Fatalf("operations after an unreachable API must not be attempted: %#v", result)
		}
	}
}

func TestApplyUserBatchValidationFailuresDoNotSkipLaterOperations(t *testing.T) {
	api := &grpcAPI{server: startedBatchTestServer(t)}
	response, err := api.ApplyUserBatch(context.Background(), &nodev1.UserBatchRequest{
		BatchId: "b3",
		Operations: []*nodev1.UserBatchOperation{
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_REMOVE, InboundTag: "in"},
			{Action: nodev1.UserBatchAction_USER_BATCH_ACTION_REMOVE, InboundTag: "in"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range response.GetResults() {
		if result.GetError() != "email is required" {
			t.Fatalf("validation failure should be reported per operation: %#v", result)
		}
	}
}
