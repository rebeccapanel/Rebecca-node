package xray

import (
	"encoding/json"
	"path/filepath"
	"strings"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
)

type Config struct {
	data     map[string]any
	settings appconfig.Settings
	peerIP   string
}

func NewConfig(raw string, peerIP string, settings appconfig.Settings) (*Config, error) {
	data := make(map[string]any)
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, err
	}

	cfg := &Config{data: data, settings: settings, peerIP: peerIP}
	cfg.applyAPI()
	return cfg, nil
}

func (c *Config) JSON() ([]byte, error) {
	return json.Marshal(c.data)
}

func (c *Config) AccessLogPath() string {
	logConfig, ok := c.data["log"].(map[string]any)
	if !ok {
		return ""
	}
	value, _ := logConfig["access"].(string)
	return value
}

func (c *Config) NormalizeLogPaths() error {
	logConfig, ok := c.data["log"].(map[string]any)
	if !ok {
		logConfig = map[string]any{}
	}
	if level, _ := logConfig["logLevel"].(string); level == "none" || level == "error" {
		logConfig["logLevel"] = "warning"
	}
	if _, ok := logConfig["access"]; !ok {
		logConfig["access"] = ""
	}
	if _, ok := logConfig["error"]; !ok {
		logConfig["error"] = ""
	}

	baseDir := c.settings.XrayLogDir
	if strings.TrimSpace(baseDir) == "" {
		baseDir = c.settings.XrayAssetsPath
	}
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "/var/log"
	}

	logConfig["access"] = resolveLogPath(logConfig["access"], "access.log", baseDir)
	logConfig["error"] = resolveLogPath(logConfig["error"], "error.log", baseDir)
	c.data["log"] = logConfig
	return nil
}

func (c *Config) applyAPI() {
	c.filterInbounds()
	c.filterAPIRoutes()

	c.data["api"] = map[string]any{
		"services": []any{"HandlerService", "StatsService", "LoggerService"},
		"tag":      "API",
	}
	c.data["stats"] = map[string]any{}
	c.applyStatsPolicy()

	inbound := map[string]any{
		"listen":   c.settings.XrayAPIHost,
		"port":     c.settings.XrayAPIPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
		"streamSettings": map[string]any{
			"security": "tls",
			"tlsSettings": map[string]any{
				"certificates": []any{
					map[string]any{
						"certificateFile": c.settings.SSLCertFile,
						"keyFile":         c.settings.SSLKeyFile,
					},
				},
			},
		},
		"tag": "API_INBOUND",
	}
	inbounds, _ := c.data["inbounds"].([]any)
	c.data["inbounds"] = append([]any{inbound}, inbounds...)

	rule := map[string]any{
		"inboundTag":  []any{"API_INBOUND"},
		"source":      []any{"127.0.0.1", c.peerIP},
		"outboundTag": "API",
		"type":        "field",
	}
	routing, _ := c.data["routing"].(map[string]any)
	if routing == nil {
		routing = map[string]any{}
	}
	rules, _ := routing["rules"].([]any)
	routing["rules"] = append([]any{rule}, rules...)
	c.data["routing"] = routing
}

func (c *Config) applyStatsPolicy() {
	policy, _ := c.data["policy"].(map[string]any)
	if policy == nil {
		policy = map[string]any{}
	}

	levels := ensureConfigMap(policy, "levels")
	level0 := ensureConfigMap(levels, "0")
	level0["statsUserUplink"] = true
	level0["statsUserDownlink"] = true

	system := ensureConfigMap(policy, "system")
	system["statsInboundDownlink"] = false
	system["statsInboundUplink"] = false
	system["statsOutboundDownlink"] = true
	system["statsOutboundUplink"] = true

	c.data["policy"] = policy
}

func ensureConfigMap(parent map[string]any, key string) map[string]any {
	if child, ok := parent[key].(map[string]any); ok {
		return child
	}
	child := map[string]any{}
	parent[key] = child
	return child
}

func (c *Config) filterInbounds() {
	allowed := map[string]struct{}{}
	for _, tag := range c.settings.Inbounds {
		allowed[tag] = struct{}{}
	}

	inbounds, _ := c.data["inbounds"].([]any)
	filtered := make([]any, 0, len(inbounds))
	for _, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok {
			filtered = append(filtered, item)
			continue
		}
		if inbound["protocol"] == "dokodemo-door" && inbound["tag"] == "API_INBOUND" {
			continue
		}
		if len(allowed) > 0 {
			tag, _ := inbound["tag"].(string)
			if _, ok := allowed[tag]; !ok {
				continue
			}
		}
		filtered = append(filtered, item)
	}
	c.data["inbounds"] = filtered
}

func (c *Config) filterAPIRoutes() {
	api, _ := c.data["api"].(map[string]any)
	apiTag, _ := api["tag"].(string)
	if apiTag == "" {
		return
	}

	routing, _ := c.data["routing"].(map[string]any)
	if routing == nil {
		return
	}
	rules, _ := routing["rules"].([]any)
	filtered := make([]any, 0, len(rules))
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok || rule["outboundTag"] != apiTag {
			filtered = append(filtered, item)
		}
	}
	routing["rules"] = filtered
	c.data["routing"] = routing
}

func resolveLogPath(value any, filename string, baseDir string) string {
	if value == nil {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return filepath.Join(baseDir, filename)
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if strings.EqualFold(text, "none") {
		return "none"
	}
	if !filepath.IsAbs(text) || filepath.Dir(text) == string(filepath.Separator) {
		return filepath.Join(baseDir, filepath.Base(text))
	}
	return text
}
