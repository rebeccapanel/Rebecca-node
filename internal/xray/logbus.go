package xray

import "sync"

type LogBus struct {
	mu          sync.Mutex
	ring        []string
	max         int
	subscribers map[chan string]struct{}
}

func NewLogBus(max int) *LogBus {
	return &LogBus{
		max:         max,
		subscribers: make(map[chan string]struct{}),
	}
}

func (b *LogBus) Append(line string) {
	b.mu.Lock()
	if len(b.ring) == b.max {
		copy(b.ring, b.ring[1:])
		b.ring[len(b.ring)-1] = line
	} else {
		b.ring = append(b.ring, line)
	}
	for ch := range b.subscribers {
		select {
		case ch <- line:
		default:
		}
	}
	b.mu.Unlock()
}

func (b *LogBus) Snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.ring))
	copy(out, b.ring)
	return out
}

func (b *LogBus) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 128)
	b.mu.Lock()
	for _, line := range b.ring {
		ch <- line
	}
	b.subscribers[ch] = struct{}{}
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		if _, ok := b.subscribers[ch]; ok {
			delete(b.subscribers, ch)
			close(ch)
		}
		b.mu.Unlock()
	}
	return ch, cancel
}
