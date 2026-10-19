package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sort"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type runtimeTopologyDelta struct {
	addInbounds    []map[string]any
	removeInbounds []string
	routing        map[string]any
}

func runtimeTopologyDeltaFor(cached, incoming map[string]any) (runtimeTopologyDelta, bool) {
	var delta runtimeTopologyDelta
	for _, key := range mergedKeys(cached, incoming) {
		if key != "inbounds" && key != "routing" && !reflect.DeepEqual(cached[key], incoming[key]) {
			return delta, false
		}
	}
	cachedRouting, _ := cached["routing"].(map[string]any)
	incomingRouting, _ := incoming["routing"].(map[string]any)
	for _, key := range mergedKeys(cachedRouting, incomingRouting) {
		if key != "rules" && key != "balancers" && !reflect.DeepEqual(cachedRouting[key], incomingRouting[key]) {
			return delta, false
		}
	}
	if !reflect.DeepEqual(cachedRouting["rules"], incomingRouting["rules"]) || !reflect.DeepEqual(cachedRouting["balancers"], incomingRouting["balancers"]) {
		delta.routing = incomingRouting
	}
	cachedInbounds, ok := inboundsByTag(cached)
	if !ok {
		return delta, false
	}
	incomingInbounds, ok := inboundsByTag(incoming)
	if !ok {
		return delta, false
	}
	for _, tag := range sortedTags(incomingInbounds) {
		current, exists := cachedInbounds[tag]
		if !exists {
			delta.addInbounds = append(delta.addInbounds, inboundWithoutClients(incomingInbounds[tag]))
			continue
		}
		if !reflect.DeepEqual(inboundWithoutClients(current), inboundWithoutClients(incomingInbounds[tag])) {
			return delta, false
		}
	}
	for _, tag := range sortedTags(cachedInbounds) {
		if _, exists := incomingInbounds[tag]; !exists {
			delta.removeInbounds = append(delta.removeInbounds, tag)
		}
	}
	return delta, true
}

func (s *Server) applyRuntimeTopologyDelta(ctx context.Context, configJSON string) bool {
	s.mu.Lock()
	payload, ok := s.loadConfigCache()
	s.mu.Unlock()
	if !ok {
		return false
	}
	cachedCfg, err := xray.NewConfig(payload.Config, payload.PeerIP, s.settings)
	if err != nil {
		return false
	}
	incomingCfg, err := xray.NewConfig(configJSON, grpcPeerIP(ctx), s.settings)
	if err != nil {
		return false
	}
	delta, ok := runtimeTopologyDeltaFor(cachedCfg.Document(), incomingCfg.Document())
	if !ok {
		return false
	}
	prepareTProxyConfig(incomingCfg)
	exe := s.core.ExecutablePath()
	addr := fmt.Sprintf("127.0.0.1:%d", s.settings.XrayAPIPort)
	applyCtx, cancel := context.WithTimeout(ctx, userSpeedLimitApplyTimeout)
	defer cancel()
	if err := applyRuntimeTopologyAPI(applyCtx, exe, addr, delta); err != nil {
		log.Printf("runtime topology apply failed, restarting Xray: %v", err)
		return false
	}
	return true
}

func applyRuntimeTopologyAPI(ctx context.Context, exe, addr string, delta runtimeTopologyDelta) error {
	if len(delta.removeInbounds) > 0 {
		args := append([]string{"api", "rmi", "-s", addr, "-t", userSpeedLimitAPITimeout}, delta.removeInbounds...)
		if err := userSpeedLimitRunXray(ctx, exe, args, nil); err != nil {
			return err
		}
	}
	if len(delta.addInbounds) > 0 {
		data, err := json.Marshal(map[string]any{"inbounds": delta.addInbounds})
		if err != nil {
			return err
		}
		if err := userSpeedLimitRunXray(ctx, exe, []string{"api", "adi", "-s", addr, "-t", userSpeedLimitAPITimeout, "/dev/stdin"}, data); err != nil {
			return err
		}
	}
	if delta.routing != nil {
		rules, _ := delta.routing["rules"].([]any)
		if rules == nil {
			rules = []any{}
		}
		balancers, _ := delta.routing["balancers"].([]any)
		return userSpeedLimitReplaceRouting(ctx, exe, addr, rules, balancers)
	}
	return nil
}

func mergedKeys(a, b map[string]any) []string {
	seen := make(map[string]bool, len(a)+len(b))
	keys := make([]string, 0, len(a)+len(b))
	for _, values := range []map[string]any{a, b} {
		for key := range values {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

func inboundsByTag(doc map[string]any) (map[string]map[string]any, bool) {
	items, _ := doc["inbounds"].([]any)
	byTag := make(map[string]map[string]any, len(items))
	for _, item := range items {
		inbound, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		tag, _ := inbound["tag"].(string)
		if tag == "" {
			return nil, false
		}
		if _, dup := byTag[tag]; dup {
			return nil, false
		}
		byTag[tag] = inbound
	}
	return byTag, true
}

func sortedTags(items map[string]map[string]any) []string {
	tags := make([]string, 0, len(items))
	for tag := range items {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func inboundWithoutClients(inbound map[string]any) map[string]any {
	out := make(map[string]any, len(inbound))
	for key, value := range inbound {
		out[key] = value
	}
	if settings, ok := inbound["settings"].(map[string]any); ok {
		trimmed := make(map[string]any, len(settings))
		for key, value := range settings {
			if key != "clients" {
				trimmed[key] = value
			}
		}
		out["settings"] = trimmed
	}
	return out
}
