package node

import (
	"encoding/base64"
	"errors"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type usageBuffer struct {
	mu                     sync.Mutex
	spoolPath              string
	spoolBuf               []byte
	nextBatch              uint64
	pending                map[string]xray.OutboundStat
	inbounds               map[string]xray.InboundStat
	users                  map[string]int64
	activeOutboundBatch    string
	activeOutboundSnapshot map[string]xray.OutboundStat
	activeInboundSnapshot  map[string]xray.InboundStat
	activeUserBatch        string
	activeUserSnapshot     map[string]int64
}

type usageBufferSpool struct {
	NextBatch              uint64                       `json:"next_batch"`
	Pending                map[string]xray.OutboundStat `json:"pending,omitempty"`
	Inbounds               map[string]xray.InboundStat  `json:"inbounds,omitempty"`
	Users                  map[string]int64             `json:"users,omitempty"`
	ActiveOutboundBatch    string                       `json:"active_outbound_batch,omitempty"`
	ActiveOutboundSnapshot map[string]xray.OutboundStat `json:"active_outbound_snapshot,omitempty"`
	ActiveInboundSnapshot  map[string]xray.InboundStat  `json:"active_inbound_snapshot,omitempty"`
	ActiveUserBatch        string                       `json:"active_user_batch,omitempty"`
	ActiveUserSnapshot     map[string]int64             `json:"active_user_snapshot,omitempty"`
}

func newUsageBuffer() *usageBuffer {
	return &usageBuffer{
		pending:  map[string]xray.OutboundStat{},
		inbounds: map[string]xray.InboundStat{},
		users:    map[string]int64{},
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

	state, err := decodeUsageSpool(data)
	if err != nil {
		return nil, err
	}
	buffer.nextBatch = state.NextBatch
	buffer.pending = state.Pending
	if buffer.pending == nil {
		buffer.pending = map[string]xray.OutboundStat{}
	}
	buffer.inbounds = state.Inbounds
	if buffer.inbounds == nil {
		buffer.inbounds = map[string]xray.InboundStat{}
	}
	buffer.users = state.Users
	if buffer.users == nil {
		buffer.users = map[string]int64{}
	}
	buffer.activeOutboundBatch = state.ActiveOutboundBatch
	buffer.activeOutboundSnapshot = state.ActiveOutboundSnapshot
	buffer.activeInboundSnapshot = state.ActiveInboundSnapshot
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
		Inbounds:               b.inbounds,
		Users:                  b.users,
		ActiveOutboundBatch:    b.activeOutboundBatch,
		ActiveOutboundSnapshot: b.activeOutboundSnapshot,
		ActiveInboundSnapshot:  b.activeInboundSnapshot,
		ActiveUserBatch:        b.activeUserBatch,
		ActiveUserSnapshot:     b.activeUserSnapshot,
	}
	b.spoolBuf = encodeUsageSpool(state, b.spoolBuf)
	if err := os.MkdirAll(filepath.Dir(b.spoolPath), 0o700); err != nil {
		return err
	}
	tempPath := b.spoolPath + ".tmp"
	if err := writeFileSync(tempPath, b.spoolBuf, 0o600); err != nil {
		return err
	}
	if err := replaceFile(tempPath, b.spoolPath); err != nil {
		return err
	}
	// fsync the directory so the rename itself is durable: without it a crash
	// right after the rename can leave the directory entry unwritten and the
	// spool reverting to its previous contents on the next boot.
	syncDir(filepath.Dir(b.spoolPath))
	return nil
}

// writeFileSync writes data to path and fsyncs the file before closing, so the
// bytes are on stable storage before the spool is renamed into place. A plain
// os.WriteFile only guarantees the write reached the OS cache, which a power
// loss can still drop.
func writeFileSync(path string, data []byte, perm os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

// syncDir fsyncs a directory so a rename inside it is durable. Best-effort:
// some platforms (notably Windows) do not support syncing a directory handle,
// where the rename is durable enough on its own.
func syncDir(dir string) {
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = handle.Sync()
	_ = handle.Close()
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
		if sample.Tag == "" || (sample.Up <= 0 && sample.Down <= 0) {
			continue
		}
		current := b.pending[sample.Tag]
		current.Tag = sample.Tag
		current.Up = addUsageCounter(current.Up, sample.Up)
		current.Down = addUsageCounter(current.Down, sample.Down)
		b.pending[sample.Tag] = current
	}
}

func (b *usageBuffer) addInboundLocked(samples []xray.InboundStat) {
	for _, sample := range samples {
		if sample.Tag == "" || (sample.Up <= 0 && sample.Down <= 0) {
			continue
		}
		current := b.inbounds[sample.Tag]
		current.Tag = sample.Tag
		current.Up = addUsageCounter(current.Up, sample.Up)
		current.Down = addUsageCounter(current.Down, sample.Down)
		b.inbounds[sample.Tag] = current
	}
}

func addUsageCounter(current, delta int64) int64 {
	if delta <= 0 {
		return current
	}
	if current < 0 {
		current = 0
	}
	if current > math.MaxInt64-delta {
		return math.MaxInt64
	}
	return current + delta
}

func (b *usageBuffer) add(samples []xray.OutboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addOutboundLocked(samples)
	b.persistBestEffortLocked()
}

func (b *usageBuffer) addInbound(samples []xray.InboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addInboundLocked(samples)
	b.persistBestEffortLocked()
}

func (b *usageBuffer) addAndSnapshot(samples []xray.OutboundStat) (string, []xray.OutboundStat) {
	batchID, outbounds, _ := b.addUsageAndSnapshot(samples, nil)
	return batchID, outbounds
}

func (b *usageBuffer) addUsageAndSnapshot(outbounds []xray.OutboundStat, inbounds []xray.InboundStat) (string, []xray.OutboundStat, []xray.InboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addOutboundLocked(outbounds)
	b.addInboundLocked(inbounds)
	if b.activeOutboundBatch != "" {
		b.persistBestEffortLocked()
		return b.activeOutboundBatch, outboundSnapshotResult(b.activeOutboundSnapshot), inboundSnapshotResult(b.activeInboundSnapshot)
	}

	snapshot := make(map[string]xray.OutboundStat, len(b.pending))
	for tag, item := range b.pending {
		if item.Up == 0 && item.Down == 0 {
			continue
		}
		snapshot[tag] = item
	}
	inboundSnapshot := make(map[string]xray.InboundStat, len(b.inbounds))
	for tag, item := range b.inbounds {
		if item.Up == 0 && item.Down == 0 {
			continue
		}
		inboundSnapshot[tag] = item
	}
	if len(snapshot) == 0 && len(inboundSnapshot) == 0 {
		return "", nil, nil
	}
	b.nextBatch++
	batchID := strconv.FormatUint(b.nextBatch, 10)
	b.activeOutboundBatch = batchID
	b.activeOutboundSnapshot = snapshot
	b.activeInboundSnapshot = inboundSnapshot
	b.persistBestEffortLocked()
	return batchID, outboundSnapshotResult(snapshot), inboundSnapshotResult(inboundSnapshot)
}

func (b *usageBuffer) addUsersLocked(samples []xray.UserStat) {
	for _, sample := range samples {
		if sample.UID == "" || sample.Value == 0 {
			continue
		}
		key := userUsageBufferKey(sample.UID, sample.InboundTag)
		b.users[key] = addUsageCounter(b.users[key], sample.Value)
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

	if batchID == "" || batchID != b.activeOutboundBatch || (b.activeOutboundSnapshot == nil && b.activeInboundSnapshot == nil) {
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
	for tag, item := range b.activeInboundSnapshot {
		current, exists := b.inbounds[tag]
		if !exists {
			continue
		}
		current.Up -= item.Up
		current.Down -= item.Down
		if current.Up <= 0 && current.Down <= 0 {
			delete(b.inbounds, tag)
			continue
		}
		current.Tag = tag
		b.inbounds[tag] = current
	}
	b.activeOutboundBatch = ""
	b.activeOutboundSnapshot = nil
	b.activeInboundSnapshot = nil
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

func inboundSnapshotResult(snapshot map[string]xray.InboundStat) []xray.InboundStat {
	result := make([]xray.InboundStat, 0, len(snapshot))
	for _, item := range snapshot {
		if item.Up != 0 || item.Down != 0 {
			result = append(result, item)
		}
	}
	return result
}

func userSnapshotResult(snapshot map[string]int64) []xray.UserStat {
	result := make([]xray.UserStat, 0, len(snapshot))
	for key, value := range snapshot {
		if value != 0 {
			uid, inboundTag := parseUserUsageBufferKey(key)
			result = append(result, xray.UserStat{UID: uid, Value: value, InboundTag: inboundTag})
		}
	}
	return result
}

func userUsageBufferKey(uid, inboundTag string) string {
	if inboundTag == "" {
		return uid
	}
	return uid + "\x00" + base64.RawURLEncoding.EncodeToString([]byte(inboundTag))
}

func parseUserUsageBufferKey(key string) (string, string) {
	uid, encodedTag, found := strings.Cut(key, "\x00")
	if !found {
		return key, ""
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encodedTag)
	if err != nil {
		return uid, ""
	}
	return uid, string(decoded)
}
