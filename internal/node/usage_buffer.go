package node

import (
	"strconv"
	"sync"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type usageBuffer struct {
	mu        sync.Mutex
	nextBatch uint64
	pending   map[string]xray.OutboundStat
	users     map[string]int64
	snapshots map[string]map[string]xray.OutboundStat
	userSnaps map[string]map[string]int64
}

func newUsageBuffer() *usageBuffer {
	return &usageBuffer{
		pending:   map[string]xray.OutboundStat{},
		users:     map[string]int64{},
		snapshots: map[string]map[string]xray.OutboundStat{},
		userSnaps: map[string]map[string]int64{},
	}
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
}

func (b *usageBuffer) addAndSnapshot(samples []xray.OutboundStat) (string, []xray.OutboundStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addOutboundLocked(samples)

	snapshot := make(map[string]xray.OutboundStat, len(b.pending))
	result := make([]xray.OutboundStat, 0, len(b.pending))
	for tag, item := range b.pending {
		if item.Up == 0 && item.Down == 0 {
			continue
		}
		snapshot[tag] = item
		result = append(result, item)
	}
	if len(snapshot) == 0 {
		return "", result
	}
	b.nextBatch++
	batchID := strconv.FormatUint(b.nextBatch, 10)
	b.snapshots[batchID] = snapshot
	return batchID, result
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
}

func (b *usageBuffer) addUsersAndSnapshot(samples []xray.UserStat) (string, []xray.UserStat) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.addUsersLocked(samples)

	snapshot := make(map[string]int64, len(b.users))
	result := make([]xray.UserStat, 0, len(b.users))
	for uid, value := range b.users {
		if value == 0 {
			continue
		}
		snapshot[uid] = value
		result = append(result, xray.UserStat{UID: uid, Value: value})
	}
	if len(snapshot) == 0 {
		return "", result
	}
	b.nextBatch++
	batchID := strconv.FormatUint(b.nextBatch, 10)
	b.userSnaps[batchID] = snapshot
	return batchID, result
}

func (b *usageBuffer) ackUsers(batchID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snapshot, ok := b.userSnaps[batchID]
	if !ok {
		return false
	}
	for uid, value := range snapshot {
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
	delete(b.userSnaps, batchID)
	return true
}

func (b *usageBuffer) ack(batchID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	snapshot, ok := b.snapshots[batchID]
	if !ok {
		return false
	}
	for tag, item := range snapshot {
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
	delete(b.snapshots, batchID)
	return true
}
