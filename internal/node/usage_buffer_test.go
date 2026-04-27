package node

import (
	"testing"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func TestUsageBufferKeepsPendingUntilAck(t *testing.T) {
	buffer := newUsageBuffer()

	batchID, stats := buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "proxy", Up: 10, Down: 20}})
	if batchID == "" {
		t.Fatal("expected a batch id")
	}
	if len(stats) != 1 || stats[0].Up != 10 || stats[0].Down != 20 {
		t.Fatalf("unexpected snapshot: %#v", stats)
	}

	_, stats = buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "proxy", Up: 5, Down: 1}})
	if len(stats) != 1 || stats[0].Up != 15 || stats[0].Down != 21 {
		t.Fatalf("unacked usage should be returned with new samples: %#v", stats)
	}

	if !buffer.ack(batchID) {
		t.Fatal("expected first batch ack to succeed")
	}
	_, stats = buffer.addAndSnapshot(nil)
	if len(stats) != 1 || stats[0].Up != 5 || stats[0].Down != 1 {
		t.Fatalf("ack should only subtract the acknowledged snapshot: %#v", stats)
	}
}

func TestUsageBufferDoesNotCreateEmptyBatch(t *testing.T) {
	buffer := newUsageBuffer()
	batchID, stats := buffer.addAndSnapshot(nil)
	if batchID != "" {
		t.Fatalf("empty snapshot should not create batch, got %q", batchID)
	}
	if len(stats) != 0 {
		t.Fatalf("expected no stats, got %#v", stats)
	}
}

func TestUsageBufferKeepsUserPendingUntilAck(t *testing.T) {
	buffer := newUsageBuffer()

	batchID, stats := buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "1", Value: 100}})
	if batchID == "" {
		t.Fatal("expected a user batch id")
	}
	if len(stats) != 1 || stats[0].Value != 100 {
		t.Fatalf("unexpected user snapshot: %#v", stats)
	}

	_, stats = buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "1", Value: 50}})
	if len(stats) != 1 || stats[0].Value != 150 {
		t.Fatalf("unacked user usage should be returned with new samples: %#v", stats)
	}

	if !buffer.ackUsers(batchID) {
		t.Fatal("expected first user batch ack to succeed")
	}
	_, stats = buffer.addUsersAndSnapshot(nil)
	if len(stats) != 1 || stats[0].Value != 50 {
		t.Fatalf("user ack should only subtract acknowledged snapshot: %#v", stats)
	}
}
