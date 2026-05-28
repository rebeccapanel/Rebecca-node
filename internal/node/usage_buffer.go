package node

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type usageBuffer struct {
	mu                     sync.Mutex
	spoolPath              string
	nextBatch              uint64
	pending                map[string]xray.OutboundStat
	users                  map[string]int64
	activeOutboundBatch    string
	activeOutboundSnapshot map[string]xray.OutboundStat
	activeUserBatch        string
	activeUserSnapshot     map[string]int64
}

type usageBufferSpool struct {
	NextBatch              uint64                       `json:"next_batch"`
	Pending                map[string]xray.OutboundStat `json:"pending,omitempty"`
	Users                  map[string]int64             `json:"users,omitempty"`
	ActiveOutboundBatch    string                       `json:"active_outbound_batch,omitempty"`
	ActiveOutboundSnapshot map[string]xray.OutboundStat `json:"active_outbound_snapshot,omitempty"`
	ActiveUserBatch        string                       `json:"active_user_batch,omitempty"`
	ActiveUserSnapshot     map[string]int64             `json:"active_user_snapshot,omitempty"`
}

func newUsageBuffer() *usageBuffer {
	return &usageBuffer{
		pending: map[string]xray.OutboundStat{},
		users:   map[string]int64{},
	}
}

func newPersistentUsageBuffer(spoolPath string) (*usageBuffer, error) {
	buffer := newUsageBuffer()
	buffer.spoolPath = spoolPath
	if spoolPath == "" {
		return buffer, nil
	}

	data, err := os.ReadFile(spoolPath)
	if errors.Is(err, os.ErrNotExist) {
		return buffer, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return buffer, nil
	}

	var state usageBufferSpool
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	buffer.nextBatch = state.NextBatch
	buffer.pending = state.Pending
	if buffer.pending == nil {
		buffer.pending = map[string]xray.OutboundStat{}
	}
	buffer.users = state.Users
	if buffer.users == nil {
		buffer.users = map[string]int64{}
	}
	buffer.activeOutboundBatch = state.ActiveOutboundBatch
	buffer.activeOutboundSnapshot = state.ActiveOutboundSnapshot
	buffer.activeUserBatch = state.ActiveUserBatch
	buffer.activeUserSnapshot = state.ActiveUserSnapshot
	return buffer, nil
}

func (b *usageBuffer) persistLocked() error {
	if b.spoolPath == "" {
		return nil
	}
	state := usageBufferSpool{
		NextBatch:              b.nextBatch,
		Pending:                b.pending,
		Users:                  b.users,
		ActiveOutboundBatch:    b.activeOutboundBatch,
		ActiveOutboundSnapshot: b.activeOutboundSnapshot,
		ActiveUserBatch:        b.activeUserBatch,
		ActiveUserSnapshot:     b.activeUserSnapshot,
	}
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.spoolPath), 0o700); err != nil {
		return err
	}
	tempPath := b.spoolPath + ".tmp"
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return err
	}
	return replaceFile(tempPath, b.spoolPath)
}

func (b *usageBuffer) persistBestEffortLocked() {
	if err := b.persistLocked(); err != nil {
		log.Printf("failed to persist usage spool: %v", err)
	}
}

func replaceFile(sourcePath, targetPath string) error {
	if runtime.GOOS == "windows" {
		_ = os.Remove(targetPath)
	}
	return os.Rename(sourcePath, targetPath)
}

func (b *usageBuffer) addOutboundLocked(samples []xray.OutboundStat) {
	for _, sample := range samples {
		if sample.Tag == "" || (sample.Up == 0 && sample.Down == 0) {
			continue
		}
		current := b.pending[sample.Tag]
		current.Tag = sample.Tag
		current.Up += sample.Up
		current.Down += sample.Down
		b.pending[sample.Tag] = current
	}
}

func (b *usageBuffer) add(samples []xray.OutboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addOutboundLocked(samples)
	b.persistBestEffortLocked()
}

func (b *usageBuffer) addAndSnapshot(samples []xray.OutboundStat) (string, []xray.OutboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addOutboundLocked(samples)
	if b.activeOutboundBatch != "" {
		b.persistBestEffortLocked()
		return b.activeOutboundBatch, outboundSnapshotResult(b.activeOutboundSnapshot)
	}

	snapshot := make(map[string]xray.OutboundStat, len(b.pending))
	for tag, item := range b.pending {
		if item.Up == 0 && item.Down == 0 {
			continue
		}
		snapshot[tag] = item
	}
	if len(snapshot) == 0 {
		return "", nil
	}
	b.nextBatch++
	batchID := strconv.FormatUint(b.nextBatch, 10)
	b.activeOutboundBatch = batchID
	b.activeOutboundSnapshot = snapshot
	b.persistBestEffortLocked()
	return batchID, outboundSnapshotResult(snapshot)
}

func (b *usageBuffer) addUsersLocked(samples []xray.UserStat) {
	for _, sample := range samples {
		if sample.UID == "" || sample.Value == 0 {
			continue
		}
		b.users[sample.UID] += sample.Value
	}
}

func (b *usageBuffer) addUsers(samples []xray.UserStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addUsersLocked(samples)
	b.persistBestEffortLocked()
}

func (b *usageBuffer) addUsersAndSnapshot(samples []xray.UserStat) (string, []xray.UserStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addUsersLocked(samples)
	if b.activeUserBatch != "" {
		b.persistBestEffortLocked()
		return b.activeUserBatch, userSnapshotResult(b.activeUserSnapshot)
	}

	snapshot := make(map[string]int64, len(b.users))
	for uid, value := range b.users {
		if value == 0 {
			continue
		}
		snapshot[uid] = value
	}
	if len(snapshot) == 0 {
		return "", nil
	}
	b.nextBatch++
	batchID := strconv.FormatUint(b.nextBatch, 10)
	b.activeUserBatch = batchID
	b.activeUserSnapshot = snapshot
	b.persistBestEffortLocked()
	return batchID, userSnapshotResult(snapshot)
}

func (b *usageBuffer) ackUsers(batchID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if batchID == "" || batchID != b.activeUserBatch || b.activeUserSnapshot == nil {
		return false
	}
	for uid, value := range b.activeUserSnapshot {
		current, exists := b.users[uid]
		if !exists {
			continue
		}
		current -= value
		if current <= 0 {
			delete(b.users, uid)
			continue
		}
		b.users[uid] = current
	}
	b.activeUserBatch = ""
	b.activeUserSnapshot = nil
	b.persistBestEffortLocked()
	return true
}

func (b *usageBuffer) ack(batchID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if batchID == "" || batchID != b.activeOutboundBatch || b.activeOutboundSnapshot == nil {
		return false
	}
	for tag, item := range b.activeOutboundSnapshot {
		current, exists := b.pending[tag]
		if !exists {
			continue
		}
		current.Up -= item.Up
		current.Down -= item.Down
		if current.Up <= 0 && current.Down <= 0 {
			delete(b.pending, tag)
			continue
		}
		current.Tag = tag
		b.pending[tag] = current
	}
	b.activeOutboundBatch = ""
	b.activeOutboundSnapshot = nil
	b.persistBestEffortLocked()
	return true
}

func outboundSnapshotResult(snapshot map[string]xray.OutboundStat) []xray.OutboundStat {
	result := make([]xray.OutboundStat, 0, len(snapshot))
	for _, item := range snapshot {
		if item.Up != 0 || item.Down != 0 {
			result = append(result, item)
		}
	}
	return result
}

func userSnapshotResult(snapshot map[string]int64) []xray.UserStat {
	result := make([]xray.UserStat, 0, len(snapshot))
	for uid, value := range snapshot {
		if value != 0 {
			result = append(result, xray.UserStat{UID: uid, Value: value})
		}
	}
	return result
}
