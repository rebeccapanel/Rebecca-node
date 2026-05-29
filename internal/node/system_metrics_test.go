package node

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, name string, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write fixture: %v", err)
	}
	return path
}

func TestReadCPUTimes(t *testing.T) {
	path := writeFixture(t, "stat", "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n")
	times, ok := readCPUTimes(path)
	if !ok {
		t.Fatal("expected CPU times")
	}
	if times.total != 1000 {
		t.Fatalf("total = %d, want 1000", times.total)
	}
	if times.idle != 850 {
		t.Fatalf("idle = %d, want 850", times.idle)
	}
}

func TestReadCPUFrequencyHz(t *testing.T) {
	path := writeFixture(t, "cpuinfo", "processor : 0\ncpu MHz : 2494.140\n")
	got := readCPUFrequencyHz(path)
	if got != 2_494_140_000 {
		t.Fatalf("frequency = %f, want 2494140000", got)
	}
}

func TestReadMemorySnapshot(t *testing.T) {
	path := writeFixture(t, "meminfo", "MemTotal:       4096000 kB\nMemAvailable:   1024000 kB\n")
	got := readMemorySnapshot(path)
	if got.TotalBytes != 4_194_304_000 {
		t.Fatalf("total bytes = %d", got.TotalBytes)
	}
	if got.UsedBytes != 3_145_728_000 {
		t.Fatalf("used bytes = %d", got.UsedBytes)
	}
	if got.UsagePct != 75 {
		t.Fatalf("usage percent = %f, want 75", got.UsagePct)
	}
}

func TestReadNetworkTotals(t *testing.T) {
	path := writeFixture(
		t,
		"netdev",
		`Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 99 0 0 0 0 0 0 0 99 0 0 0 0 0 0 0
  eth0: 1000 1 0 0 0 0 0 0 2000 1 0 0 0 0 0 0
  ens3: 3000 1 0 0 0 0 0 0 5000 1 0 0 0 0 0 0
`,
	)
	got, ok := readNetworkTotals(path)
	if !ok {
		t.Fatal("expected network totals")
	}
	if got.rx != 4000 {
		t.Fatalf("rx = %d, want 4000", got.rx)
	}
	if got.tx != 7000 {
		t.Fatalf("tx = %d, want 7000", got.tx)
	}
}
