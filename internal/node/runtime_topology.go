package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"sort"
	"strings"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

const runtimeTopologyAPIInboundTag = "API_INBOUND"

type runtimeTopologyDelta struct {
	addInbounds     []map[string]any
	removeInbounds  []string
	addOutbounds    []map[string]any
	removeOutbounds []string
	routing         map[string]any
}

func (d runtimeTopologyDelta) touchesRoutingBase() bool {
	return d.routing != nil || len(d.addOutbounds) > 0 || len(d.removeOutbounds) > 0
}

func (d runtimeTopologyDelta) freshInboundTags() []string {
	tags := make([]string, 0, len(d.addInbounds))
	for _, inbound := range d.addInbounds {
		tags = append(tags, asString(inbound["tag"]))
	}
	return tags
}

func runtimeTopologyDeltaFor(cached, incoming map[string]any) (runtimeTopologyDelta, bool) {
	var delta runtimeTopologyDelta
	for _, key := range mergedKeys(cached, incoming) {
		switch key {
		case "inbounds", "outbounds", "routing":
		default:
			if !reflect.DeepEqual(cached[key], incoming[key]) {
				return delta, false
			}
		}
	}
	return delta, runtimeRoutingDelta(cached, incoming, &delta) &&
		runtimeInboundDelta(cached, incoming, &delta) &&
		runtimeOutboundDelta(cached, incoming, &delta)
}

func runtimeRoutingDelta(cached, incoming map[string]any, delta *runtimeTopologyDelta) bool {
	if reflect.DeepEqual(cached["routing"], incoming["routing"]) {
		return true
	}
	cachedRouting, cachedOK := cached["routing"].(map[string]any)
	incomingRouting, incomingOK := incoming["routing"].(map[string]any)
	if !cachedOK || !incomingOK {
		return false
	}
	for _, key := range mergedKeys(cachedRouting, incomingRouting) {
		if key != "rules" && key != "balancers" && !reflect.DeepEqual(cachedRouting[key], incomingRouting[key]) {
			return false
		}
	}
	delta.routing = incomingRouting
	return true
}

func runtimeInboundDelta(cached, incoming map[string]any, delta *runtimeTopologyDelta) bool {
	cachedInbounds, ok := inboundsByTag(cached)
	if !ok {
		return false
	}
	incomingInbounds, ok := inboundsByTag(incoming)
	if !ok {
		return false
	}
	for _, tag := range sortedTags(incomingInbounds) {
		next := incomingInbounds[tag]
		current, exists := cachedInbounds[tag]
		if exists && reflect.DeepEqual(inboundWithoutClients(current), inboundWithoutClients(next)) {
			continue
		}
		if tag == runtimeTopologyAPIInboundTag || !runtimeInboundSwappable(next) || (exists && !runtimeInboundSwappable(current)) {
			return false
		}
		if exists {
			delta.removeInbounds = append(delta.removeInbounds, tag)
		}
		delta.addInbounds = append(delta.addInbounds, next)
	}
	for _, tag := range sortedTags(cachedInbounds) {
		if _, exists := incomingInbounds[tag]; exists {
			continue
		}
		if tag == runtimeTopologyAPIInboundTag {
			return false
		}
		delta.removeInbounds = append(delta.removeInbounds, tag)
	}
	return true
}

func runtimeInboundSwappable(inbound map[string]any) bool {
	stream, _ := inbound["streamSettings"].(map[string]any)
	if asString(stream["security"]) == "reality" {
		return false
	}
	sockopt, _ := stream["sockopt"].(map[string]any)
	if tproxy := asString(sockopt["tproxy"]); tproxy != "" && tproxy != "off" {
		return false
	}
	settings, _ := inbound["settings"].(map[string]any)
	if asString(inbound["protocol"]) == "socks" && asString(settings["auth"]) == "password" {
		return false
	}
	clients, _ := settings["clients"].([]any)
	for _, item := range clients {
		client, _ := item.(map[string]any)
		if client["reverse"] != nil {
			return false
		}
	}
	return true
}

func runtimeOutboundDelta(cached, incoming map[string]any, delta *runtimeTopologyDelta) bool {
	if reflect.DeepEqual(cached["outbounds"], incoming["outbounds"]) {
		return true
	}
	cachedList, ok := outboundsInOrder(cached)
	if !ok {
		return false
	}
	incomingList, ok := outboundsInOrder(incoming)
	if !ok {
		return false
	}
	if (len(cachedList) == 0) != (len(incomingList) == 0) {
		return false
	}
	if len(cachedList) > 0 && !reflect.DeepEqual(cachedList[0], incomingList[0]) {
		return false
	}
	cachedByTag := outboundsKeyed(cachedList)
	incomingByTag := outboundsKeyed(incomingList)
	for _, outbound := range cachedList {
		tag := asString(outbound["tag"])
		next, exists := incomingByTag[tag]
		if exists && reflect.DeepEqual(outbound, next) {
			continue
		}
		delta.removeOutbounds = append(delta.removeOutbounds, tag)
		if exists {
			delta.addOutbounds = append(delta.addOutbounds, next)
		}
	}
	for _, outbound := range incomingList {
		if _, exists := cachedByTag[asString(outbound["tag"])]; !exists {
			delta.addOutbounds = append(delta.addOutbounds, outbound)
		}
	}
	return true
}

func outboundsInOrder(doc map[string]any) ([]map[string]any, bool) {
	items, _ := doc["outbounds"].([]any)
	list := make([]map[string]any, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		outbound, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		tag := asString(outbound["tag"])
		if tag == "" || seen[tag] {
			return nil, false
		}
		seen[tag] = true
		list = append(list, outbound)
	}
	return list, true
}

func outboundsKeyed(list []map[string]any) map[string]map[string]any {
	byTag := make(map[string]map[string]any, len(list))
	for _, outbound := range list {
		byTag[asString(outbound["tag"])] = outbound
	}
	return byTag
}

func (s *Server) applyRuntimeTopologyDelta(ctx context.Context, configJSON string) ([]string, bool) {
	s.mu.Lock()
	payload, ok := s.loadConfigCache()
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	cachedCfg, err := xray.NewConfig(payload.Config, payload.PeerIP, s.settings)
	if err != nil {
		return nil, false
	}
	incomingCfg, err := xray.NewConfig(configJSON, grpcPeerIP(ctx), s.settings)
	if err != nil {
		return nil, false
	}
	delta, ok := runtimeTopologyDeltaFor(cachedCfg.Document(), incomingCfg.Document())
	if !ok {
		return nil, false
	}
	prepareTProxyConfig(incomingCfg)
	exe := s.core.ExecutablePath()
	addr := fmt.Sprintf("127.0.0.1:%d", s.settings.XrayAPIPort)
	applyCtx, cancel := context.WithTimeout(ctx, userSpeedLimitApplyTimeout)
	defer cancel()
	if err := applyRuntimeTopologyAPI(applyCtx, exe, addr, delta); err != nil {
		log.Printf("runtime topology apply failed, restarting Xray: %v", err)
		return nil, false
	}
	if delta.touchesRoutingBase() {
		invalidateUserSpeedLimitPlan()
	}
	s.setLastConfig(incomingCfg)
	return delta.freshInboundTags(), true
}

func topologyMissingHandler(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "not enough information")
}

func applyRuntimeTopologyAPI(ctx context.Context, exe, addr string, delta runtimeTopologyDelta) error {
	for _, tag := range delta.removeInbounds {
		args := []string{"api", "rmi", "-s", addr, "-t", userSpeedLimitAPITimeout, tag}
		if err := userSpeedLimitRunXray(ctx, exe, args, nil); err != nil && !topologyMissingHandler(err) {
			return err
		}
	}
	for _, tag := range delta.removeOutbounds {
		if err := userSpeedLimitRemoveOutbounds(ctx, exe, addr, []string{tag}); err != nil && !topologyMissingHandler(err) {
			return err
		}
	}
	if len(delta.addOutbounds) > 0 {
		if err := userSpeedLimitAddOutbounds(ctx, exe, addr, delta.addOutbounds); err != nil {
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
