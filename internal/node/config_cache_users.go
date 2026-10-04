package node

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

func (s *Server) addUserToConfigCache(inboundTag string, user xray.InboundUser) error {
	return s.patchConfigCacheUser(inboundTag, user, "")
}

func (s *Server) inheritInboundUserFlow(inboundTag string, user xray.InboundUser) (xray.InboundUser, error) {
	if user.Protocol != "vless" || user.Flow != "" {
		return user, nil
	}
	s.mu.Lock()
	payload, ok := s.loadConfigCache()
	s.mu.Unlock()
	if !ok {
		return user, nil
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(payload.Config), &config); err != nil {
		return user, err
	}
	for _, value := range anySlice(config["inbounds"]) {
		inbound, _ := value.(map[string]any)
		if asString(inbound["tag"]) == inboundTag && asString(inbound["protocol"]) == "vless" {
			settings, _ := inbound["settings"].(map[string]any)
			user.Flow = strings.TrimSpace(asString(settings["flow"]))
			break
		}
	}
	return user, nil
}

func (s *Server) removeUserFromConfigCache(inboundTag string, email string) error {
	return s.patchConfigCacheUser(inboundTag, xray.InboundUser{}, email)
}

func (s *Server) applyConfigCacheUserDiff(incomingConfig string) error {
	s.mu.Lock()
	payload, ok := s.loadConfigCache()
	s.mu.Unlock()
	if !ok {
		return nil
	}
	diff, err := configUserDiff(payload.Config, incomingConfig)
	if err != nil {
		return err
	}
	return s.applyConfigUserDiffResult(diff)
}

func (s *Server) applyConfigUserDiffResult(diff configUserDiffResult) error {
	return applyConfigUserDiff(diff,
		func(inboundTag string, user xray.InboundUser) error {
			return xray.AddInboundUser(
				s.settings.XrayAPIHost,
				s.settings.XrayAPIPort,
				grpcOperationTimeout,
				inboundTag,
				user,
			)
		},
		func(inboundTag string, email string) error {
			return xray.RemoveInboundUser(
				s.settings.XrayAPIHost,
				s.settings.XrayAPIPort,
				grpcOperationTimeout,
				inboundTag,
				email,
			)
		},
	)
}

func (s *Server) cachedConfigUser(inboundTag string, email string) (xray.InboundUser, bool, bool, error) {
	s.mu.Lock()
	payload, ok := s.loadConfigCache()
	s.mu.Unlock()
	if !ok {
		return xray.InboundUser{}, false, false, nil
	}
	states, err := configClientStates(payload.Config)
	if err != nil {
		return xray.InboundUser{}, false, true, err
	}
	user, ok := states[strings.TrimSpace(inboundTag)].clients[strings.TrimSpace(email)]
	return user, ok, true, nil
}

func applyConfigUserDiff(
	diff configUserDiffResult,
	add func(string, xray.InboundUser) error,
	remove func(string, string) error,
) error {
	for _, item := range diff.remove {
		if err := remove(item.inboundTag, item.email); err != nil && !isIgnorableXrayRemoveError(err) {
			return err
		}
	}
	for _, item := range diff.update {
		if err := remove(item.inboundTag, item.previous.Email); err != nil && !isIgnorableXrayRemoveError(err) {
			return err
		}
		if err := add(item.inboundTag, item.current); err != nil && !isIgnorableXrayAddError(err) {
			if restoreErr := add(item.inboundTag, item.previous); restoreErr != nil && !isIgnorableXrayAddError(restoreErr) {
				return fmt.Errorf("update inbound user: %v; restore previous user: %w", err, restoreErr)
			}
			return err
		}
	}
	for _, item := range diff.add {
		if err := add(item.inboundTag, item.user); err != nil && !isIgnorableXrayAddError(err) {
			return err
		}
	}
	return nil
}

func (s *Server) patchConfigCacheUser(inboundTag string, user xray.InboundUser, removeEmail string) error {
	inboundTag = strings.TrimSpace(inboundTag)
	if inboundTag == "" {
		return fmt.Errorf("inbound_tag is required")
	}

	// Public user/runtime operations already hold runtimeMu. Do not hold the
	// session mutex while saving: diagnostic config updates acquire it too.
	payload, ok := s.loadConfigCache()
	if !ok {
		return nil
	}
	configJSON, changed, err := patchConfigCacheUserJSON(payload.Config, inboundTag, user, removeEmail)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	s.saveConfigCache(configJSON, payload.PeerIP, payload.OVRuntime, payload.L2TPRuntime, payload.PPTPRuntime, payload.WGRuntime, payload.IKEv2Runtime, payload.AnyConnectRuntime)
	return nil
}

func patchConfigCacheUserJSON(rawConfig string, inboundTag string, user xray.InboundUser, removeEmail string) (string, bool, error) {
	var config map[string]any
	if err := json.Unmarshal([]byte(rawConfig), &config); err != nil {
		return "", false, err
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok {
		return "", false, nil
	}

	email := strings.TrimSpace(removeEmail)
	adding := email == ""
	if adding {
		email = strings.TrimSpace(user.Email)
	}
	if email == "" {
		return "", false, fmt.Errorf("email is required")
	}

	changed := false
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok || strings.TrimSpace(asString(inbound["tag"])) != inboundTag {
			continue
		}
		settings, ok := inbound["settings"].(map[string]any)
		if !ok {
			settings = map[string]any{}
			inbound["settings"] = settings
		}
		clients := anySlice(settings["clients"])
		next := make([]any, 0, len(clients)+1)
		for _, client := range clients {
			if strings.TrimSpace(clientEmail(client)) == email {
				changed = true
				continue
			}
			next = append(next, client)
		}
		if adding {
			next = append(next, inboundUserClientMap(user))
			changed = true
		}
		settings["clients"] = next
		break
	}
	if !changed {
		return "", false, nil
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return "", false, err
	}
	return string(encoded), true, nil
}

func inboundUserClientMap(user xray.InboundUser) map[string]any {
	client := map[string]any{
		"email": strings.TrimSpace(user.Email),
	}
	if user.Level != 0 {
		client["level"] = user.Level
	}
	if value := strings.TrimSpace(user.ID); value != "" {
		client["id"] = value
	}
	if value := strings.TrimSpace(user.Password); value != "" {
		client["password"] = value
	}
	if value := strings.TrimSpace(user.Auth); value != "" {
		client["auth"] = value
	}
	if value := strings.TrimSpace(user.Flow); value != "" {
		client["flow"] = value
	}
	if value := strings.TrimSpace(user.ReverseTag); value != "" {
		client["reverse"] = map[string]any{"tag": value}
	}
	if value := strings.TrimSpace(user.Method); value != "" {
		client["method"] = value
	}
	if user.CipherType != 0 {
		client["cipher_type"] = user.CipherType
	}
	if user.IVCheck {
		client["iv_check"] = true
	}
	return client
}

func clientEmail(value any) string {
	client, ok := value.(map[string]any)
	if !ok {
		return ""
	}
	return asString(client["email"])
}

func anySlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []map[string]any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, item)
		}
		return result
	default:
		return nil
	}
}

func asString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case nil:
		return ""
	default:
		return fmt.Sprint(value)
	}
}

type configUserDiffResult struct {
	add    []configUserAdd
	remove []configUserRemove
	update []configUserUpdate
}

type configUserAdd struct {
	inboundTag string
	user       xray.InboundUser
}

type configUserRemove struct {
	inboundTag string
	email      string
}

type configUserUpdate struct {
	inboundTag string
	previous   xray.InboundUser
	current    xray.InboundUser
}

type configClientState struct {
	protocol string
	clients  map[string]xray.InboundUser
	raw      map[string]string
}

func configUserDiff(cachedConfig string, incomingConfig string) (configUserDiffResult, error) {
	cached, err := configClientStates(cachedConfig)
	if err != nil {
		return configUserDiffResult{}, err
	}
	incoming, err := configClientStates(incomingConfig)
	if err != nil {
		return configUserDiffResult{}, err
	}
	diff := configUserDiffResult{}
	for tag, incomingState := range incoming {
		cachedState := cached[tag]
		for email := range cachedState.clients {
			if _, ok := incomingState.clients[email]; !ok {
				diff.remove = append(diff.remove, configUserRemove{inboundTag: tag, email: email})
			}
		}
		for email, user := range incomingState.clients {
			if cachedState.raw[email] == incomingState.raw[email] {
				continue
			}
			if previous, ok := cachedState.clients[email]; ok {
				diff.update = append(diff.update, configUserUpdate{inboundTag: tag, previous: previous, current: user})
				continue
			}
			diff.add = append(diff.add, configUserAdd{inboundTag: tag, user: user})
		}
	}
	return diff, nil
}

func configClientStates(rawConfig string) (map[string]configClientState, error) {
	var config map[string]any
	if err := json.Unmarshal([]byte(rawConfig), &config); err != nil {
		return nil, err
	}
	result := map[string]configClientState{}
	for _, item := range anySlice(config["inbounds"]) {
		inbound, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := strings.TrimSpace(asString(inbound["tag"]))
		protocol := strings.ToLower(strings.TrimSpace(asString(inbound["protocol"])))
		if tag == "" || protocol == "" {
			continue
		}
		settings, _ := inbound["settings"].(map[string]any)
		state := configClientState{
			protocol: protocol,
			clients:  map[string]xray.InboundUser{},
			raw:      map[string]string{},
		}
		for _, item := range anySlice(settings["clients"]) {
			client, ok := item.(map[string]any)
			if !ok {
				continue
			}
			user, err := inboundUserFromClient(protocol, client)
			if err != nil {
				return nil, fmt.Errorf("inbound %s client: %w", tag, err)
			}
			if user.Email == "" {
				continue
			}
			if protocol == "vless" && user.Flow == "" {
				user.Flow = strings.TrimSpace(asString(settings["flow"]))
			}
			state.clients[user.Email] = user
			encoded, _ := json.Marshal(client)
			state.raw[user.Email] = string(encoded)
		}
		result[tag] = state
	}
	return result, nil
}

func inboundUserFromClient(protocol string, client map[string]any) (xray.InboundUser, error) {
	level, err := uint32ClientValue(client["level"])
	if err != nil {
		return xray.InboundUser{}, err
	}
	cipherType, err := int32ClientValue(firstPresent(client, "cipher_type", "cipherType"))
	if err != nil {
		return xray.InboundUser{}, err
	}
	ivCheck, _ := boolClientValue(firstPresent(client, "iv_check", "ivCheck"))
	auth := strings.TrimSpace(asString(client["auth"]))
	if auth == "" {
		auth = strings.TrimSpace(asString(client["password"]))
	}
	reverseTag := ""
	if reverse, ok := client["reverse"].(map[string]any); ok {
		reverseTag = strings.TrimSpace(asString(reverse["tag"]))
	}
	return xray.InboundUser{
		Protocol:   protocol,
		Email:      strings.TrimSpace(asString(client["email"])),
		Level:      level,
		ID:         strings.TrimSpace(asString(firstPresent(client, "id", "uuid"))),
		Password:   strings.TrimSpace(asString(client["password"])),
		Auth:       auth,
		Flow:       strings.TrimSpace(asString(client["flow"])),
		ReverseTag: reverseTag,
		Method:     strings.TrimSpace(asString(client["method"])),
		CipherType: cipherType,
		IVCheck:    ivCheck,
	}, nil
}

func firstPresent(values map[string]any, keys ...string) any {
	for _, key := range keys {
		if value, ok := values[key]; ok {
			return value
		}
	}
	return nil
}

func uint32ClientValue(value any) (uint32, error) {
	switch typed := value.(type) {
	case nil:
		return 0, nil
	case float64:
		return uint32(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		return uint32(parsed), err
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(typed), 10, 32)
		return uint32(parsed), err
	default:
		return 0, fmt.Errorf("level must be numeric")
	}
}

func int32ClientValue(value any) (int32, error) {
	switch typed := value.(type) {
	case nil:
		return 0, nil
	case float64:
		return int32(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		return int32(parsed), err
	case string:
		if strings.TrimSpace(typed) == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 32)
		return int32(parsed), err
	default:
		return 0, fmt.Errorf("cipher_type must be numeric")
	}
}

func boolClientValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}
