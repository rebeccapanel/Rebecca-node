package node

import (
	"log"
	"time"
)

var xrayRecoveryDelays = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 60 * time.Second}

const xrayStableAfter = 2 * time.Minute

func (s *Server) startXrayWatchdog() {
	exits := make(chan struct{}, 1)
	s.core.SetUnexpectedExitHandler(func() {
		select {
		case exits <- struct{}{}:
		default:
		}
	})
	go s.watchXray(exits, xrayRecoveryDelays)
}

func (s *Server) watchXray(exits <-chan struct{}, delays []time.Duration) {
	failures := 0
	var recoveredAt time.Time
	for range exits {
		log.Print("xray exited unexpectedly; scheduling recovery")
		if !recoveredAt.IsZero() && time.Since(recoveredAt) > xrayStableAfter {
			failures = 0
		}
		recovered := false
		for failures < len(delays) {
			time.Sleep(delays[failures])
			failures++
			if s.recoverXray() {
				recovered, recoveredAt = true, time.Now()
				break
			}
		}
		if !recovered {
			log.Print("xray recovery gave up; it stays down until the next config sync")
		}
	}
}

func (s *Server) recoverXray() bool {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	if s.core.Started() {
		return true
	}
	s.mu.Lock()
	stopped := s.runtimeStopped
	s.mu.Unlock()
	if stopped {
		return true
	}
	if err := s.startCachedConfig(false); err != nil {
		log.Printf("xray recovery failed: %v", err)
		return false
	}
	if !s.core.Started() {
		return false
	}
	log.Print("xray recovered from the cached config")
	return true
}
