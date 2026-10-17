package node

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const userSpeedLimitVPNInterval = 5 * time.Second

var userSpeedLimitVPNKey string

type userSpeedLimitBinding struct {
	IP     string
	UserID int64
}

func userSpeedLimitVPNBindings(dataDir string, limits []userSpeedLimit) []userSpeedLimitBinding {
	limited := make(map[int64]bool, len(limits))
	for _, limit := range limits {
		if limit.UserID > 0 && limit.SpeedLimitKbps > 0 {
			limited[limit.UserID] = true
		}
	}
	if len(limited) == 0 {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "vpn-sessions.tsv"))
	if err != nil {
		return nil
	}
	owners := map[string]int64{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(strings.TrimSpace(line), "\t")
		if len(fields) < 5 {
			continue
		}
		uid, err := strconv.ParseInt(strings.TrimSpace(fields[0]), 10, 64)
		if err != nil || !limited[uid] {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(fields[4]))
		if ip == nil || ip.To4() == nil {
			continue
		}
		owners[ip.To4().String()] = uid
	}
	bindings := make([]userSpeedLimitBinding, 0, len(owners))
	for ip, uid := range owners {
		bindings = append(bindings, userSpeedLimitBinding{IP: ip, UserID: uid})
	}
	sort.Slice(bindings, func(i, j int) bool {
		if bindings[i].UserID != bindings[j].UserID {
			return bindings[i].UserID < bindings[j].UserID
		}
		return bindings[i].IP < bindings[j].IP
	})
	return bindings
}

func userSpeedLimitVPNElements(bindings []userSpeedLimitBinding) ([]string, []string) {
	var up, down []string
	for _, binding := range bindings {
		up = append(up, fmt.Sprintf("%s : jump lim_out_%d", binding.IP, binding.UserID))
		down = append(down, fmt.Sprintf("%s : jump lim_in_%d", binding.IP, binding.UserID))
	}
	return up, down
}

func userSpeedLimitBindingsKey(bindings []userSpeedLimitBinding) string {
	parts := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		parts = append(parts, fmt.Sprintf("%s=%d", binding.IP, binding.UserID))
	}
	return strings.Join(parts, ",")
}

func applyUserSpeedLimitVPNElements(ctx context.Context, bindings []userSpeedLimitBinding) error {
	var script strings.Builder
	fmt.Fprintf(&script, "flush map inet %s vpn_up\n", userSpeedLimitTable)
	fmt.Fprintf(&script, "flush map inet %s vpn_down\n", userSpeedLimitTable)
	if len(bindings) > 0 {
		up, down := userSpeedLimitVPNElements(bindings)
		fmt.Fprintf(&script, "add element inet %s vpn_up { %s }\n", userSpeedLimitTable, strings.Join(up, ", "))
		fmt.Fprintf(&script, "add element inet %s vpn_down { %s }\n", userSpeedLimitTable, strings.Join(down, ", "))
	}
	return applyUserSpeedLimitNFT(ctx, script.String())
}

func (s *Server) refreshUserSpeedLimitVPN() error {
	userSpeedLimitMu.Lock()
	defer userSpeedLimitMu.Unlock()
	dataDir := s.settings.RebeccaDataDir
	limits := loadUserSpeedLimitState(dataDir).Limits
	if len(limits) == 0 {
		return nil
	}
	bindings := userSpeedLimitVPNBindings(dataDir, limits)
	key := userSpeedLimitBindingsKey(bindings)
	if key == userSpeedLimitVPNKey {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), userSpeedLimitApplyTimeout)
	defer cancel()
	if err := applyUserSpeedLimitVPNElements(ctx, bindings); err != nil {
		return err
	}
	userSpeedLimitVPNKey = key
	return nil
}

func (s *Server) runUserSpeedLimitVPNLoop() {
	ticker := time.NewTicker(userSpeedLimitVPNInterval)
	defer ticker.Stop()
	for range ticker.C {
		if err := s.refreshUserSpeedLimitVPN(); err != nil {
			log.Printf("user speed limit VPN refresh failed: %v", err)
		}
	}
}
