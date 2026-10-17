package node

import (
	"bytes"
	"testing"
	"time"
)

func TestUserSpeedBucketDelaysBeyondRate(t *testing.T) {
	bucket := &userSpeedBucket{last: time.Now()}
	if delay := bucket.reserve(16000, 640); delay < 150*time.Millisecond || delay > 250*time.Millisecond {
		t.Fatalf("delay = %v, want about 200ms", delay)
	}
}

func TestUserSpeedWriterThrottlesOnlyLimitedUsers(t *testing.T) {
	setUserSpeedLimitIndex([]userSpeedLimit{{UserID: 77, SpeedLimitKbps: 640}})
	defer setUserSpeedLimitIndex(nil)
	var sink bytes.Buffer
	limited := userSpeedWriter{Writer: &sink, uid: 77, upload: true}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if _, err := limited.Write(make([]byte, 32768)); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Fatalf("limited user wrote 96KiB in %v, want throttling", elapsed)
	}
	free := userSpeedWriter{Writer: &sink, uid: 78, upload: true}
	start = time.Now()
	if _, err := free.Write(make([]byte, 96*1024)); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("unlimited user waited %v", elapsed)
	}
}
