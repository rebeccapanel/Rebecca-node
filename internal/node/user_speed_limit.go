package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/rebeccapanel/rebecca-node/internal/proto/node/v1"
	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

const (
	userSpeedLimitMarkBase   uint32 = 0x10000000
	userSpeedLimitMarkMask   uint32 = 0xf0000000
	userSpeedLimitTable             = "rebecca_user_speed"
	userSpeedLimitTagPrefix         = "rl-u"
	userSpeedLimitStateFile         = "user-speed-limits.json"
	userSpeedLimitMinBurst   int64  = 32768
	userSpeedLimitAPITimeout        = "30"
)

const userSpeedLimitApplyTimeout = 60 * time.Second

var userSpeedLimitMu sync.Mutex

var userSpeedLimitCloneTagPattern = regexp.MustCompile("^" + userSpeedLimitTagPrefix + `[0-9]+-`)

type userSpeedLimit struct {
	UserID         int64 `json:"user_id"`
	SpeedLimitKbps int64 `json:"speed_limit_kbps"`
}

type userSpeedLimitState struct {
	BaseHash string           `json:"base_hash"`
	Limits   []userSpeedLimit `json:"limits"`
}

type userSpeedLimitPlan struct {
	BaseHash  string
	BaseRules []any
	Balancers []any
	Clones    []map[string]any
	CloneTags map[string]bool
	Overlay   []any
	NFTScript string
}

type userSpeedLimitActive struct {
	userSpeedLimit
	emails []string
}

func userSpeedLimitsFromProto(items []*nodev1.UserSpeedLimit) []userSpeedLimit {
	result := make([]userSpeedLimit, 0, len(items))
	for _, item := range items {
		result = append(result, userSpeedLimit{UserID: item.GetUserId(), SpeedLimitKbps: item.GetSpeedLimitKbps()})
	}
	return result
}

func userSpeedLimitMark(userID int64) uint32 {
	return userSpeedLimitMarkBase | (uint32(userID) &^ userSpeedLimitMarkMask)
}

func userSpeedLimitRateBytes(kbps int64) int64 {
	return kbps * 125
}

func userSpeedLimitBurstBytes(rate int64) int64 {
	burst := rate / 4
	if burst < userSpeedLimitMinBurst {
		burst = userSpeedLimitMinBurst
	}
	return burst
}

func userSpeedLimitCloneTag(userID int64, outboundTag string) string {
	return fmt.Sprintf("%s%d-%s", userSpeedLimitTagPrefix, userID, outboundTag)
}

func userSpeedLimitEmailsByID(doc map[string]any) map[int64][]string {
	result := map[int64][]string{}
	seen := map[string]bool{}
	inbounds, _ := doc["inbounds"].([]any)
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]any)
		settings, _ := inbound["settings"].(map[string]any)
		clients, _ := settings["clients"].([]any)
		for _, item := range clients {
			client, _ := item.(map[string]any)
			email, _ := client["email"].(string)
			prefix, _, found := strings.Cut(email, ".")
			if email == "" || !found || seen[email] {
				continue
			}
			userID, err := strconv.ParseInt(prefix, 10, 64)
			if err != nil || userID <= 0 {
				continue
			}
			seen[email] = true
			result[userID] = append(result[userID], email)
		}
	}
	for userID := range result {
		sort.Strings(result[userID])
	}
	return result
}

func userSpeedLimitActiveUsers(limits []userSpeedLimit, emails map[int64][]string) []userSpeedLimitActive {
	byID := map[int64]int64{}
	for _, limit := range limits {
		if limit.UserID > 0 && limit.SpeedLimitKbps > 0 {
			byID[limit.UserID] = limit.SpeedLimitKbps
		}
	}
	ids := make([]int64, 0, len(byID))
	for id := range byID {
		if len(emails[id]) > 0 {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	active := make([]userSpeedLimitActive, 0, len(ids))
	for _, id := range ids {
		active = append(active, userSpeedLimitActive{
			userSpeedLimit: userSpeedLimit{UserID: id, SpeedLimitKbps: byID[id]},
			emails:         emails[id],
		})
	}
	return active
}

func userSpeedLimitDeepCopy(value any) (any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func userSpeedLimitProtocol(outbound map[string]any) string {
	protocol, _ := outbound["protocol"].(string)
	return strings.ToLower(protocol)
}

func userSpeedLimitCloneable(rule map[string]any, byTag map[string]map[string]any) (string, bool) {
	if _, ok := rule["balancerTag"]; ok {
		return "", false
	}
	tag, _ := rule["outboundTag"].(string)
	if tag == "" || tag == "API" {
		return "", false
	}
	outbound, ok := byTag[tag]
	if !ok || userSpeedLimitProtocol(outbound) == "blackhole" {
		return "", false
	}
	return tag, true
}

func userSpeedLimitClone(userID int64, outbound map[string]any, mark uint32) (map[string]any, error) {
	copied, err := userSpeedLimitDeepCopy(outbound)
	if err != nil {
		return nil, err
	}
	clone, _ := copied.(map[string]any)
	origTag, _ := outbound["tag"].(string)
	clone["tag"] = userSpeedLimitCloneTag(userID, origTag)
	stream, _ := clone["streamSettings"].(map[string]any)
	if stream == nil {
		stream = map[string]any{}
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if sockopt == nil {
		sockopt = map[string]any{}
	}
	sockopt["mark"] = int64(mark)
	stream["sockopt"] = sockopt
	clone["streamSettings"] = stream
	return clone, nil
}

func userSpeedLimitRuleCopy(rule map[string]any, emails []string, outboundTag string) (map[string]any, bool, error) {
	copied, err := userSpeedLimitDeepCopy(rule)
	if err != nil {
		return nil, false, err
	}
	copyRule, _ := copied.(map[string]any)
	delete(copyRule, "ruleTag")
	copyRule["outboundTag"] = outboundTag
	allowed := map[string]bool{}
	for _, email := range emails {
		allowed[email] = true
	}
	if base, ok := rule["user"].([]any); ok {
		var users []any
		for _, item := range base {
			if email, _ := item.(string); allowed[email] {
				users = append(users, email)
			}
		}
		if len(users) == 0 {
			return nil, false, nil
		}
		copyRule["user"] = users
	} else {
		copyRule["user"] = userSpeedLimitAnySlice(emails)
	}
	return copyRule, true, nil
}

func userSpeedLimitAnySlice(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func userSpeedLimitBaseHash(routing map[string]any, outbounds []any) (string, error) {
	data, err := json.Marshal(map[string]any{"routing": routing, "outbounds": outbounds})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func buildUserSpeedLimitPlan(doc map[string]any, limits []userSpeedLimit, bindings []userSpeedLimitBinding) (*userSpeedLimitPlan, error) {
	routing, _ := doc["routing"].(map[string]any)
	baseRules, _ := routing["rules"].([]any)
	balancers, _ := routing["balancers"].([]any)
	outbounds, _ := doc["outbounds"].([]any)
	byTag := map[string]map[string]any{}
	for _, raw := range outbounds {
		outbound, _ := raw.(map[string]any)
		if tag, _ := outbound["tag"].(string); tag != "" {
			byTag[tag] = outbound
		}
	}
	hash, err := userSpeedLimitBaseHash(routing, outbounds)
	if err != nil {
		return nil, err
	}
	plan := &userSpeedLimitPlan{BaseHash: hash, BaseRules: baseRules, Balancers: balancers, CloneTags: map[string]bool{}}
	active := userSpeedLimitActiveUsers(limits, userSpeedLimitEmailsByID(doc))
	defaultTag := ""
	if len(outbounds) > 0 {
		first, _ := outbounds[0].(map[string]any)
		defaultTag, _ = first["tag"].(string)
	}
	defaultCloneable := defaultTag != "" && defaultTag != "API" && byTag[defaultTag] != nil && userSpeedLimitProtocol(byTag[defaultTag]) != "blackhole"
	if len(active) == 0 {
		plan.Overlay = baseRules
		plan.NFTScript = userSpeedLimitNFTScript(nil, limits, bindings)
		return plan, nil
	}
	for _, user := range active {
		mark := userSpeedLimitMark(user.UserID)
		needed := map[string]bool{}
		for _, raw := range baseRules {
			rule, _ := raw.(map[string]any)
			if tag, ok := userSpeedLimitCloneable(rule, byTag); ok {
				needed[tag] = true
			}
		}
		if defaultCloneable {
			needed[defaultTag] = true
		}
		tags := make([]string, 0, len(needed))
		for tag := range needed {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			clone, err := userSpeedLimitClone(user.UserID, byTag[tag], mark)
			if err != nil {
				return nil, err
			}
			plan.Clones = append(plan.Clones, clone)
			plan.CloneTags[userSpeedLimitCloneTag(user.UserID, tag)] = true
		}
	}
	overlay := make([]any, 0, len(baseRules)+len(active)*(len(baseRules)+1))
	for _, raw := range baseRules {
		rule, _ := raw.(map[string]any)
		if rule != nil {
			if tag, ok := userSpeedLimitCloneable(rule, byTag); ok {
				for _, user := range active {
					copyRule, keep, err := userSpeedLimitRuleCopy(rule, user.emails, userSpeedLimitCloneTag(user.UserID, tag))
					if err != nil {
						return nil, err
					}
					if keep {
						overlay = append(overlay, copyRule)
					}
				}
			}
		}
		overlay = append(overlay, raw)
	}
	if defaultCloneable {
		for _, user := range active {
			overlay = append(overlay, map[string]any{
				"type":        "field",
				"user":        userSpeedLimitAnySlice(user.emails),
				"outboundTag": userSpeedLimitCloneTag(user.UserID, defaultTag),
			})
		}
	}
	plan.Overlay = overlay
	plan.NFTScript = userSpeedLimitNFTScript(active, limits, bindings)
	return plan, nil
}

func userSpeedLimitNFTScript(active []userSpeedLimitActive, limited []userSpeedLimit, bindings []userSpeedLimitBinding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", userSpeedLimitTable)
	fmt.Fprintf(&b, "delete table inet %s\n", userSpeedLimitTable)
	if len(limited) == 0 {
		return b.String()
	}
	fmt.Fprintf(&b, "table inet %s {\n", userSpeedLimitTable)
	fmt.Fprintf(&b, "  chain premark { type filter hook prerouting priority -150; policy accept; ct mark and 0x%08x == 0x%08x meta mark set ct mark; }\n", userSpeedLimitMarkMask, userSpeedLimitMarkBase)
	fmt.Fprintf(&b, "  chain outmark { type route hook output priority -150; policy accept; meta mark and 0x%08x == 0x%08x ct mark set meta mark; }\n", userSpeedLimitMarkMask, userSpeedLimitMarkBase)
	for _, user := range limited {
		rate := userSpeedLimitRateBytes(user.SpeedLimitKbps)
		burst := userSpeedLimitBurstBytes(rate)
		fmt.Fprintf(&b, "  chain lim_in_%d { limit rate over %d bytes/second burst %d bytes drop; }\n", user.UserID, rate, burst)
		fmt.Fprintf(&b, "  chain lim_out_%d { limit rate over %d bytes/second burst %d bytes drop; }\n", user.UserID, rate, burst)
	}
	inElements := make([]string, 0, len(active))
	outElements := make([]string, 0, len(active))
	for _, user := range active {
		mark := userSpeedLimitMark(user.UserID)
		inElements = append(inElements, fmt.Sprintf("0x%08x : jump lim_in_%d", mark, user.UserID))
		outElements = append(outElements, fmt.Sprintf("0x%08x : jump lim_out_%d", mark, user.UserID))
	}
	writeUserSpeedLimitMap(&b, "in_limits", "mark", inElements)
	writeUserSpeedLimitMap(&b, "out_limits", "mark", outElements)
	fmt.Fprintf(&b, "  chain in_limit { type filter hook input priority 0; policy accept; meta mark vmap @in_limits; }\n")
	fmt.Fprintf(&b, "  chain out_limit { type filter hook output priority 0; policy accept; meta mark vmap @out_limits; }\n")
	upElements, downElements := userSpeedLimitVPNElements(bindings)
	writeUserSpeedLimitMap(&b, "vpn_up", "ipv4_addr", upElements)
	writeUserSpeedLimitMap(&b, "vpn_down", "ipv4_addr", downElements)
	fmt.Fprintf(&b, "  chain vpn_pre { type filter hook prerouting priority 0; policy accept; ip saddr vmap @vpn_up; }\n")
	fmt.Fprintf(&b, "  chain vpn_fwd { type filter hook forward priority 0; policy accept; ip daddr vmap @vpn_down; }\n")
	fmt.Fprintf(&b, "  chain vpn_out { type filter hook output priority 0; policy accept; ip daddr vmap @vpn_down; }\n")
	b.WriteString("}\n")
	return b.String()
}

func writeUserSpeedLimitMap(b *strings.Builder, name string, keyType string, elements []string) {
	if len(elements) == 0 {
		fmt.Fprintf(b, "  map %s { type %s : verdict; }\n", name, keyType)
		return
	}
	fmt.Fprintf(b, "  map %s { type %s : verdict; elements = { %s }; }\n", name, keyType, strings.Join(elements, ", "))
}

func userSpeedLimitRunXray(ctx context.Context, exe string, args []string, stdin []byte) error {
	cmd := exec.CommandContext(ctx, exe, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray %s: %w: %s", strings.Join(args[:2], " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func userSpeedLimitOutboundTags(ctx context.Context, exe, addr string) ([]string, error) {
	cmd := exec.CommandContext(ctx, exe, "api", "lso", "-s", addr)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("xray api lso: %w", err)
	}
	var listing struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &listing); err != nil {
		return nil, err
	}
	var tags []string
	for _, item := range listing.Outbounds {
		if userSpeedLimitCloneTagPattern.MatchString(item.Tag) {
			tags = append(tags, item.Tag)
		}
	}
	return tags, nil
}

func userSpeedLimitReplaceRouting(ctx context.Context, exe, addr string, rules []any, balancers []any) error {
	routing := map[string]any{"rules": rules}
	if len(balancers) > 0 {
		routing["balancers"] = balancers
	}
	data, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		return err
	}
	return userSpeedLimitRunXray(ctx, exe, []string{"api", "adrules", "-s", addr, "-t", userSpeedLimitAPITimeout, "/dev/stdin"}, data)
}

func userSpeedLimitAddOutbounds(ctx context.Context, exe, addr string, outbounds []map[string]any) error {
	data, err := json.Marshal(map[string]any{"outbounds": outbounds})
	if err != nil {
		return err
	}
	return userSpeedLimitRunXray(ctx, exe, []string{"api", "ado", "-s", addr, "-t", userSpeedLimitAPITimeout, "/dev/stdin"}, data)
}

func userSpeedLimitRemoveOutbounds(ctx context.Context, exe, addr string, tags []string) error {
	if len(tags) == 0 {
		return nil
	}
	args := append([]string{"api", "rmo", "-s", addr}, tags...)
	return userSpeedLimitRunXray(ctx, exe, args, nil)
}

func applyUserSpeedLimitRuntime(ctx context.Context, exe, addr string, plan *userSpeedLimitPlan, baseChanged bool) error {
	existing, err := userSpeedLimitOutboundTags(ctx, exe, addr)
	if err != nil {
		return err
	}
	if baseChanged {
		if err := userSpeedLimitReplaceRouting(ctx, exe, addr, plan.BaseRules, plan.Balancers); err != nil {
			return err
		}
		if err := userSpeedLimitRemoveOutbounds(ctx, exe, addr, existing); err != nil {
			return err
		}
		existing = nil
	}
	present := map[string]bool{}
	for _, tag := range existing {
		present[tag] = true
	}
	var missing []map[string]any
	for _, clone := range plan.Clones {
		if tag, _ := clone["tag"].(string); !present[tag] {
			missing = append(missing, clone)
		}
	}
	if len(missing) > 0 {
		if err := userSpeedLimitAddOutbounds(ctx, exe, addr, missing); err != nil {
			return err
		}
	}
	if err := userSpeedLimitReplaceRouting(ctx, exe, addr, plan.Overlay, plan.Balancers); err != nil {
		return err
	}
	var stale []string
	for _, tag := range existing {
		if !plan.CloneTags[tag] {
			stale = append(stale, tag)
		}
	}
	return userSpeedLimitRemoveOutbounds(ctx, exe, addr, stale)
}

func applyUserSpeedLimitNFT(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply user speed limits nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func userSpeedLimitStatePath(dataDir string) string {
	return filepath.Join(dataDir, userSpeedLimitStateFile)
}

func loadUserSpeedLimitState(dataDir string) userSpeedLimitState {
	var state userSpeedLimitState
	data, err := os.ReadFile(userSpeedLimitStatePath(dataDir))
	if err != nil {
		return state
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return userSpeedLimitState{}
	}
	return state
}

func saveUserSpeedLimitState(dataDir string, state userSpeedLimitState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	path := userSpeedLimitStatePath(dataDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Server) reconcileUserSpeedLimits(ctx context.Context, cfg *xray.Config, limits []userSpeedLimit) error {
	userSpeedLimitMu.Lock()
	defer userSpeedLimitMu.Unlock()
	setUserSpeedLimitIndex(limits)
	dataDir := s.settings.RebeccaDataDir
	state := loadUserSpeedLimitState(dataDir)
	if len(limits) == 0 && len(state.Limits) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, userSpeedLimitApplyTimeout)
	defer cancel()
	bindings := userSpeedLimitVPNBindings(dataDir, limits)
	state.Limits = limits
	if err := saveUserSpeedLimitState(dataDir, state); err != nil {
		return err
	}
	if cfg == nil || !s.core.Started() {
		if err := applyUserSpeedLimitNFT(ctx, userSpeedLimitNFTScript(nil, limits, bindings)); err != nil {
			return err
		}
		userSpeedLimitVPNKey = userSpeedLimitBindingsKey(bindings)
		return nil
	}
	raw, err := cfg.JSON()
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	plan, err := buildUserSpeedLimitPlan(doc, limits, bindings)
	if err != nil {
		return err
	}
	exe := s.core.ExecutablePath()
	addr := fmt.Sprintf("127.0.0.1:%d", s.settings.XrayAPIPort)
	if err := applyUserSpeedLimitRuntime(ctx, exe, addr, plan, state.BaseHash != plan.BaseHash); err != nil {
		return err
	}
	if err := applyUserSpeedLimitNFT(ctx, plan.NFTScript); err != nil {
		return err
	}
	userSpeedLimitVPNKey = userSpeedLimitBindingsKey(bindings)
	state.BaseHash = plan.BaseHash
	return saveUserSpeedLimitState(dataDir, state)
}

func (s *Server) syncUserSpeedLimits(ctx context.Context, req *nodev1.RuntimeConfigRequest) error {
	cfg, err := s.grpcConfig(ctx, req)
	if err != nil {
		return err
	}
	return s.reconcileUserSpeedLimits(ctx, cfg, userSpeedLimitsFromProto(req.GetUserSpeedLimits()))
}
