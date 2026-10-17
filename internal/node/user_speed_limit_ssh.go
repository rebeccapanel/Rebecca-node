package node

import (
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var userSpeedLimitIndex atomic.Pointer[map[int64]int64]

var userSpeedBuckets sync.Map

type userSpeedBucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

type userSpeedWriter struct {
	io.Writer
	uid    int64
	upload bool
}

func setUserSpeedLimitIndex(limits []userSpeedLimit) {
	index := make(map[int64]int64, len(limits))
	for _, limit := range limits {
		if limit.UserID > 0 && limit.SpeedLimitKbps > 0 {
			index[limit.UserID] = limit.SpeedLimitKbps
		}
	}
	userSpeedLimitIndex.Store(&index)
}

func userSpeedLimitKbpsFor(userID int64) int64 {
	index := userSpeedLimitIndex.Load()
	if index == nil {
		return 0
	}
	return (*index)[userID]
}

func sshSpeedUserID(uid string) int64 {
	id, err := strconv.ParseInt(strings.TrimPrefix(uid, "ssh:"), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func userSpeedBucketFor(userID int64, upload bool) *userSpeedBucket {
	key := strconv.FormatInt(userID, 10) + ":down"
	if upload {
		key = strconv.FormatInt(userID, 10) + ":up"
	}
	bucket, _ := userSpeedBuckets.LoadOrStore(key, &userSpeedBucket{})
	return bucket.(*userSpeedBucket)
}

func (b *userSpeedBucket) reserve(size int, kbps int64) time.Duration {
	rate := float64(kbps * 125)
	burst := rate / 4
	if burst < float64(userSpeedLimitMinBurst) {
		burst = float64(userSpeedLimitMinBurst)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.last.IsZero() {
		b.last = now
		b.tokens = burst
	}
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	b.tokens -= float64(size)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / rate * float64(time.Second))
}

func (w userSpeedWriter) Write(p []byte) (int, error) {
	if kbps := userSpeedLimitKbpsFor(w.uid); kbps > 0 && len(p) > 0 && w.uid > 0 {
		if delay := userSpeedBucketFor(w.uid, w.upload).reserve(len(p), kbps); delay > 0 {
			time.Sleep(delay)
		}
	}
	return w.Writer.Write(p)
}
