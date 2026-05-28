package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

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

	secondBatchID, stats := buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "proxy", Up: 5, Down: 1}})
	if secondBatchID != batchID {
		t.Fatalf("unacked usage should return the in-flight batch id: got %q want %q", secondBatchID, batchID)
	}
	if len(stats) != 1 || stats[0].Up != 10 || stats[0].Down != 20 {
		t.Fatalf("unacked usage should return the in-flight snapshot: %#v", stats)
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

	secondBatchID, stats := buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "1", Value: 50}})
	if secondBatchID != batchID {
		t.Fatalf("unacked user usage should return the in-flight batch id: got %q want %q", secondBatchID, batchID)
	}
	if len(stats) != 1 || stats[0].Value != 100 {
		t.Fatalf("unacked user usage should return the in-flight snapshot: %#v", stats)
	}

	if !buffer.ackUsers(batchID) {
		t.Fatal("expected first user batch ack to succeed")
	}
	_, stats = buffer.addUsersAndSnapshot(nil)
	if len(stats) != 1 || stats[0].Value != 50 {
		t.Fatalf("user ack should only subtract acknowledged snapshot: %#v", stats)
	}
}

func TestPersistentUsageBufferRestoresUnackedBatches(t *testing.T) {
	spoolPath := filepath.Join(t.TempDir(), "usage-spool.json")
	buffer, err := newPersistentUsageBuffer(spoolPath)
	if err != nil {
		t.Fatalf("failed to create persistent usage buffer: %v", err)
	}

	outboundBatchID, outboundStats := buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "proxy", Up: 10, Down: 20}})
	if outboundBatchID == "" || len(outboundStats) != 1 {
		t.Fatalf("expected outbound batch, got batch=%q stats=%#v", outboundBatchID, outboundStats)
	}
	userBatchID, userStats := buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "42", Value: 100}})
	if userBatchID == "" || len(userStats) != 1 {
		t.Fatalf("expected user batch, got batch=%q stats=%#v", userBatchID, userStats)
	}

	buffer.add([]xray.OutboundStat{{Tag: "proxy", Up: 3, Down: 4}})
	buffer.addUsers([]xray.UserStat{{UID: "42", Value: 7}})

	recovered, err := newPersistentUsageBuffer(spoolPath)
	if err != nil {
		t.Fatalf("failed to recover persistent usage buffer: %v", err)
	}

	recoveredOutboundBatchID, outboundStats := recovered.addAndSnapshot(nil)
	if recoveredOutboundBatchID != outboundBatchID {
		t.Fatalf("expected restored outbound in-flight batch %q, got %q", outboundBatchID, recoveredOutboundBatchID)
	}
	if len(outboundStats) != 1 || outboundStats[0].Up != 10 || outboundStats[0].Down != 20 {
		t.Fatalf("unexpected restored outbound in-flight snapshot: %#v", outboundStats)
	}

	recoveredUserBatchID, userStats := recovered.addUsersAndSnapshot(nil)
	if recoveredUserBatchID != userBatchID {
		t.Fatalf("expected restored user in-flight batch %q, got %q", userBatchID, recoveredUserBatchID)
	}
	if len(userStats) != 1 || userStats[0].UID != "42" || userStats[0].Value != 100 {
		t.Fatalf("unexpected restored user in-flight snapshot: %#v", userStats)
	}

	if !recovered.ack(outboundBatchID) {
		t.Fatal("expected restored outbound batch ack to succeed")
	}
	nextOutboundBatchID, outboundStats := recovered.addAndSnapshot(nil)
	if nextOutboundBatchID == "" || nextOutboundBatchID == outboundBatchID {
		t.Fatalf("expected queued outbound batch after ack, got %q", nextOutboundBatchID)
	}
	if len(outboundStats) != 1 || outboundStats[0].Up != 3 || outboundStats[0].Down != 4 {
		t.Fatalf("unexpected queued outbound stats after recovery ack: %#v", outboundStats)
	}

	if !recovered.ackUsers(userBatchID) {
		t.Fatal("expected restored user batch ack to succeed")
	}
	nextUserBatchID, userStats := recovered.addUsersAndSnapshot(nil)
	if nextUserBatchID == "" || nextUserBatchID == userBatchID {
		t.Fatalf("expected queued user batch after ack, got %q", nextUserBatchID)
	}
	if len(userStats) != 1 || userStats[0].UID != "42" || userStats[0].Value != 7 {
		t.Fatalf("unexpected queued user stats after recovery ack: %#v", userStats)
	}
}

func TestPersistentUsageBufferRestoresEmptyAfterAck(t *testing.T) {
	spoolPath := filepath.Join(t.TempDir(), "usage-spool.json")
	buffer, err := newPersistentUsageBuffer(spoolPath)
	if err != nil {
		t.Fatalf("failed to create persistent usage buffer: %v", err)
	}

	outboundBatchID, _ := buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "proxy", Up: 1, Down: 2}})
	userBatchID, _ := buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "42", Value: 5}})
	if !buffer.ack(outboundBatchID) {
		t.Fatal("expected outbound ack to succeed")
	}
	if !buffer.ackUsers(userBatchID) {
		t.Fatal("expected user ack to succeed")
	}

	recovered, err := newPersistentUsageBuffer(spoolPath)
	if err != nil {
		t.Fatalf("failed to recover persistent usage buffer: %v", err)
	}
	outboundBatchID, outboundStats := recovered.addAndSnapshot(nil)
	if outboundBatchID != "" || len(outboundStats) != 0 {
		t.Fatalf("expected no restored outbound usage after ack, got batch=%q stats=%#v", outboundBatchID, outboundStats)
	}
	userBatchID, userStats := recovered.addUsersAndSnapshot(nil)
	if userBatchID != "" || len(userStats) != 0 {
		t.Fatalf("expected no restored user usage after ack, got batch=%q stats=%#v", userBatchID, userStats)
	}
}

func TestUsageEndpointsReturnPendingWhenCoreStopped(t *testing.T) {
	buffer := newUsageBuffer()
	buffer.add([]xray.OutboundStat{{Tag: "proxy", Up: 10, Down: 20}})
	buffer.addUsers([]xray.UserStat{{UID: "42", Value: 123}})

	server := &Server{
		core:     &xray.Core{},
		usage:    buffer,
		sessions: map[string]time.Time{"session": time.Now()},
	}

	outboundPayload := postUsage(t, http.HandlerFunc(server.handleOutboundUsage))
	outboundStats := outboundPayload["stats"].([]any)
	if outboundPayload["batch_id"] == "" || len(outboundStats) != 1 {
		t.Fatalf("expected pending outbound batch, got %#v", outboundPayload)
	}
	outbound := outboundStats[0].(map[string]any)
	if outbound["tag"] != "proxy" || outbound["up"].(float64) != 10 || outbound["down"].(float64) != 20 {
		t.Fatalf("unexpected outbound stats: %#v", outbound)
	}

	userPayload := postUsage(t, http.HandlerFunc(server.handleUserUsage))
	userStats := userPayload["stats"].([]any)
	if userPayload["batch_id"] == "" || len(userStats) != 1 {
		t.Fatalf("expected pending user batch, got %#v", userPayload)
	}
	user := userStats[0].(map[string]any)
	if user["uid"] != "42" || user["value"].(float64) != 123 {
		t.Fatalf("unexpected user stats: %#v", user)
	}
}

func TestServerAllowsConcurrentSessions(t *testing.T) {
	server := &Server{sessions: make(map[string]time.Time)}

	server.addSession("first", "127.0.0.1")
	server.addSession("second", "127.0.0.1")

	if !server.sessionMatches("first") {
		t.Fatal("expected first session to remain valid")
	}
	if !server.sessionMatches("second") {
		t.Fatal("expected second session to remain valid")
	}
	if server.sessionMatches("missing") {
		t.Fatal("unexpected match for missing session")
	}
}

func TestUsageBufferHighVolumeUserSnapshotsAndAck(t *testing.T) {
	buffer := newUsageBuffer()

	const users = 30000
	firstSamples := make([]xray.UserStat, 0, users)
	for i := 1; i <= users; i++ {
		firstSamples = append(firstSamples, xray.UserStat{
			UID:   strconv.Itoa(i),
			Value: int64(i%997 + 1),
		})
	}

	firstBatchID, stats := buffer.addUsersAndSnapshot(firstSamples)
	if firstBatchID == "" {
		t.Fatal("expected first user batch id")
	}
	if len(stats) != users {
		t.Fatalf("expected %d user stats, got %d", users, len(stats))
	}

	const changedUsers = 10000
	secondSamples := make([]xray.UserStat, 0, changedUsers)
	expectedAfterAck := make(map[string]int64, changedUsers)
	for i := 1; i <= changedUsers; i++ {
		uid := strconv.Itoa(i * 3)
		value := int64(500 + i%31)
		secondSamples = append(secondSamples, xray.UserStat{UID: uid, Value: value})
		expectedAfterAck[uid] += value
	}

	repeatedBatchID, stats := buffer.addUsersAndSnapshot(secondSamples)
	if repeatedBatchID != firstBatchID {
		t.Fatalf("unacked user batch should be reused: got %q want %q", repeatedBatchID, firstBatchID)
	}
	if len(stats) != users {
		t.Fatalf("unacked batch should still include all %d users, got %d", users, len(stats))
	}

	if !buffer.ackUsers(firstBatchID) {
		t.Fatal("expected first user batch ack to succeed")
	}

	secondBatchID, stats := buffer.addUsersAndSnapshot(nil)
	if secondBatchID == "" {
		t.Fatal("expected second user batch id")
	}
	if len(stats) != changedUsers {
		t.Fatalf("expected %d post-ack user deltas, got %d", changedUsers, len(stats))
	}

	actualAfterAck := make(map[string]int64, len(stats))
	for _, stat := range stats {
		actualAfterAck[stat.UID] = stat.Value
	}
	for uid, expectedValue := range expectedAfterAck {
		if actualAfterAck[uid] != expectedValue {
			t.Fatalf("unexpected post-ack value for user %s: got %d want %d", uid, actualAfterAck[uid], expectedValue)
		}
	}

	if !buffer.ackUsers(secondBatchID) {
		t.Fatal("expected second user batch ack to succeed")
	}
	batchID, stats := buffer.addUsersAndSnapshot(nil)
	if batchID != "" || len(stats) != 0 {
		t.Fatalf("expected empty user buffer after ack, got batch=%q stats=%d", batchID, len(stats))
	}
}

func TestUsageBufferHighVolumeOutboundSnapshotsAndAck(t *testing.T) {
	buffer := newUsageBuffer()

	const outbounds = 5000
	firstSamples := make([]xray.OutboundStat, 0, outbounds)
	for i := 1; i <= outbounds; i++ {
		firstSamples = append(firstSamples, xray.OutboundStat{
			Tag:  fmt.Sprintf("outbound-%05d", i),
			Up:   int64(i%4096 + 1),
			Down: int64(i%8192 + 2),
		})
	}

	firstBatchID, stats := buffer.addAndSnapshot(firstSamples)
	if firstBatchID == "" {
		t.Fatal("expected first outbound batch id")
	}
	if len(stats) != outbounds {
		t.Fatalf("expected %d outbound stats, got %d", outbounds, len(stats))
	}

	const changedOutbounds = 1500
	secondSamples := make([]xray.OutboundStat, 0, changedOutbounds)
	expectedAfterAck := make(map[string]xray.OutboundStat, changedOutbounds)
	for i := 1; i <= changedOutbounds; i++ {
		tag := fmt.Sprintf("outbound-%05d", i*2)
		sample := xray.OutboundStat{
			Tag:  tag,
			Up:   int64(100 + i%17),
			Down: int64(200 + i%23),
		}
		secondSamples = append(secondSamples, sample)
		expectedAfterAck[tag] = sample
	}

	repeatedBatchID, stats := buffer.addAndSnapshot(secondSamples)
	if repeatedBatchID != firstBatchID {
		t.Fatalf("unacked outbound batch should be reused: got %q want %q", repeatedBatchID, firstBatchID)
	}
	if len(stats) != outbounds {
		t.Fatalf("unacked batch should still include all %d outbounds, got %d", outbounds, len(stats))
	}

	if !buffer.ack(firstBatchID) {
		t.Fatal("expected first outbound batch ack to succeed")
	}

	secondBatchID, stats := buffer.addAndSnapshot(nil)
	if secondBatchID == "" {
		t.Fatal("expected second outbound batch id")
	}
	if len(stats) != changedOutbounds {
		t.Fatalf("expected %d post-ack outbound deltas, got %d", changedOutbounds, len(stats))
	}

	actualAfterAck := make(map[string]xray.OutboundStat, len(stats))
	for _, stat := range stats {
		actualAfterAck[stat.Tag] = stat
	}
	for tag, expectedStat := range expectedAfterAck {
		actualStat := actualAfterAck[tag]
		if actualStat.Up != expectedStat.Up || actualStat.Down != expectedStat.Down {
			t.Fatalf("unexpected post-ack value for outbound %s: got up=%d down=%d want up=%d down=%d", tag, actualStat.Up, actualStat.Down, expectedStat.Up, expectedStat.Down)
		}
	}

	if !buffer.ack(secondBatchID) {
		t.Fatal("expected second outbound batch ack to succeed")
	}
	batchID, stats := buffer.addAndSnapshot(nil)
	if batchID != "" || len(stats) != 0 {
		t.Fatalf("expected empty outbound buffer after ack, got batch=%q stats=%d", batchID, len(stats))
	}
}

func TestUsageBufferConcurrentHighVolumeWriters(t *testing.T) {
	buffer := newUsageBuffer()

	const workers = 16
	const samplesPerWorker = 2000
	const outboundBuckets = 256

	var wg sync.WaitGroup
	wg.Add(workers)
	for worker := 0; worker < workers; worker++ {
		worker := worker
		go func() {
			defer wg.Done()
			for i := 0; i < samplesPerWorker; i++ {
				buffer.addUsers([]xray.UserStat{{
					UID:   fmt.Sprintf("user-%02d-%04d", worker, i),
					Value: 1,
				}})
				buffer.add([]xray.OutboundStat{{
					Tag:  fmt.Sprintf("outbound-%03d", i%outboundBuckets),
					Up:   1,
					Down: 2,
				}})
			}
		}()
	}
	wg.Wait()

	userBatchID, userStats := buffer.addUsersAndSnapshot(nil)
	if userBatchID == "" {
		t.Fatal("expected user batch after concurrent writes")
	}
	if len(userStats) != workers*samplesPerWorker {
		t.Fatalf("expected %d unique user stats, got %d", workers*samplesPerWorker, len(userStats))
	}
	for _, stat := range userStats {
		if stat.Value != 1 {
			t.Fatalf("expected each unique user stat to be 1, got %#v", stat)
		}
	}

	outboundBatchID, outboundStats := buffer.addAndSnapshot(nil)
	if outboundBatchID == "" {
		t.Fatal("expected outbound batch after concurrent writes")
	}
	if len(outboundStats) != outboundBuckets {
		t.Fatalf("expected %d outbound buckets, got %d", outboundBuckets, len(outboundStats))
	}
	var totalUp, totalDown int64
	for _, stat := range outboundStats {
		totalUp += stat.Up
		totalDown += stat.Down
	}
	expectedSamples := int64(workers * samplesPerWorker)
	if totalUp != expectedSamples || totalDown != expectedSamples*2 {
		t.Fatalf("unexpected outbound totals: got up=%d down=%d want up=%d down=%d", totalUp, totalDown, expectedSamples, expectedSamples*2)
	}

	if !buffer.ackUsers(userBatchID) || !buffer.ack(outboundBatchID) {
		t.Fatal("expected concurrent write batches to ack")
	}
}

func TestUsageBufferConcurrentSnapshotRequestsShareInFlightBatch(t *testing.T) {
	buffer := newUsageBuffer()
	buffer.addUsers([]xray.UserStat{{UID: "1", Value: 100}})
	buffer.add([]xray.OutboundStat{{Tag: "direct", Up: 7, Down: 9}})

	userBatchID, userStats := buffer.addUsersAndSnapshot(nil)
	if userBatchID == "" || len(userStats) != 1 || userStats[0].Value != 100 {
		t.Fatalf("expected initial user batch, got batch=%q stats=%#v", userBatchID, userStats)
	}
	outboundBatchID, outboundStats := buffer.addAndSnapshot(nil)
	if outboundBatchID == "" || len(outboundStats) != 1 || outboundStats[0].Up != 7 || outboundStats[0].Down != 9 {
		t.Fatalf("expected initial outbound batch, got batch=%q stats=%#v", outboundBatchID, outboundStats)
	}

	const workers = 32
	var wg sync.WaitGroup
	userBatches := make(chan string, workers)
	outboundBatches := make(chan string, workers)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			userBatchID, userStats := buffer.addUsersAndSnapshot([]xray.UserStat{{UID: "1", Value: 1}})
			outboundBatchID, outboundStats := buffer.addAndSnapshot([]xray.OutboundStat{{Tag: "direct", Up: 1, Down: 1}})
			if len(userStats) != 1 || userStats[0].Value != 100 {
				t.Errorf("unexpected user in-flight snapshot: %#v", userStats)
			}
			if len(outboundStats) != 1 || outboundStats[0].Up != 7 || outboundStats[0].Down != 9 {
				t.Errorf("unexpected outbound in-flight snapshot: %#v", outboundStats)
			}
			userBatches <- userBatchID
			outboundBatches <- outboundBatchID
		}()
	}
	wg.Wait()
	close(userBatches)
	close(outboundBatches)

	for batchID := range userBatches {
		if batchID == "" {
			t.Fatal("expected user batch id")
		}
		if batchID != userBatchID {
			t.Fatalf("expected one shared user batch id, got %q and %q", userBatchID, batchID)
		}
	}

	for batchID := range outboundBatches {
		if batchID == "" {
			t.Fatal("expected outbound batch id")
		}
		if batchID != outboundBatchID {
			t.Fatalf("expected one shared outbound batch id, got %q and %q", outboundBatchID, batchID)
		}
	}

	if !buffer.ackUsers(userBatchID) {
		t.Fatal("expected user batch ack")
	}
	nextUserBatchID, userStats := buffer.addUsersAndSnapshot(nil)
	if nextUserBatchID == "" || nextUserBatchID == userBatchID {
		t.Fatalf("expected a new user batch for queued deltas, got %q", nextUserBatchID)
	}
	if len(userStats) != 1 || userStats[0].Value != workers {
		t.Fatalf("expected queued user deltas after ack, got %#v", userStats)
	}

	if !buffer.ack(outboundBatchID) {
		t.Fatal("expected outbound batch ack")
	}
	nextOutboundBatchID, outboundStats := buffer.addAndSnapshot(nil)
	if nextOutboundBatchID == "" || nextOutboundBatchID == outboundBatchID {
		t.Fatalf("expected a new outbound batch for queued deltas, got %q", nextOutboundBatchID)
	}
	if len(outboundStats) != 1 || outboundStats[0].Up != workers || outboundStats[0].Down != workers {
		t.Fatalf("expected queued outbound deltas after ack, got %#v", outboundStats)
	}
}

func postUsage(t *testing.T, handler http.Handler) map[string]any {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/usage", bytes.NewBufferString(`{"session_id":"session"}`))
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	return payload
}
