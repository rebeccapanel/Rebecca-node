package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
	"golang.org/x/net/proxy"
)

const DefaultOutboundTestURL = "https://www.google.com/generate_204"

type OutboundTestResult struct {
	Success    bool   `json:"success"`
	Delay      int64  `json:"delay,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	Error      string `json:"error,omitempty"`
	TestType   string `json:"test_type,omitempty"`
	Address    string `json:"address,omitempty"`
	Port       int    `json:"port,omitempty"`
	Output     string `json:"output,omitempty"`
}

type RouteTestRun struct {
	OutboundTestResult
	Matched         bool
	OutboundTag     string
	GroupTags       []string
	OutboundTraffic []OutboundStat
}

func (c *Core) TestRoute(ctx context.Context, rawConfig string, inboundTag string, testURL string, request RouteTestRequest) RouteTestRun {
	testURL = strings.TrimSpace(testURL)
	if testURL == "" {
		testURL = DefaultOutboundTestURL
	}
	release, ok := c.acquireTestRuntime(ctx)
	if !ok {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Route test queue timed out", TestType: "latency"}}
	}
	defer release()

	socksPort, listener, err := findAvailablePort()
	if err != nil {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Failed to find available test port", TestType: "latency"}}
	}
	_ = listener.Close()
	apiPort, listener, err := findAvailablePort()
	if err != nil {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Failed to find available test API port", TestType: "latency"}}
	}
	_ = listener.Close()

	configJSON, err := buildRouteTestConfig(rawConfig, inboundTag, socksPort, apiPort)
	if err != nil {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: err.Error(), TestType: "latency"}}
	}

	c.mu.Lock()
	executable := c.executablePath
	assets := c.assetsPath
	c.mu.Unlock()

	cmd := exec.Command(executable, "run", "-config", "stdin:")
	configureManagedProcess(cmd)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Failed to create stdin pipe for test Xray process", TestType: "latency"}}
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Failed to start test Xray instance", TestType: "latency"}}
	}
	if _, err := stdin.Write(configJSON); err != nil {
		stopTestProcess(cmd, nil)
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: "Route test failed", TestType: "latency"}}
	}
	_ = stdin.Close()

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	defer func() {
		stopTestProcess(cmd, done)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	if ready, errText := waitForPort(done, socksPort, 3*time.Second); !ready {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: errText, TestType: "latency"}}
	}
	if ready, errText := waitForPort(done, apiPort, 3*time.Second); !ready {
		return RouteTestRun{OutboundTestResult: OutboundTestResult{Error: errText, TestType: "latency"}}
	}

	selected, _ := TestRoute("127.0.0.1", apiPort, 3*time.Second, request)
	run := RouteTestRun{Matched: selected.Matched, OutboundTag: selected.OutboundTag, GroupTags: selected.GroupTags}
	delay, statusCode, err := measureSocksDelay(socksPort, testURL)
	if err != nil {
		run.OutboundTestResult = OutboundTestResult{Error: "Request failed", TestType: "latency"}
		return run
	}
	run.OutboundTestResult = OutboundTestResult{Success: true, Delay: delay, StatusCode: statusCode, TestType: "latency"}
	run.OutboundTraffic, _ = QueryOutboundStats("127.0.0.1", apiPort, 3*time.Second, true)
	return run
}

func buildRouteTestConfig(rawConfig string, inboundTag string, socksPort int, apiPort int) ([]byte, error) {
	data := map[string]any{}
	if err := json.Unmarshal([]byte(rawConfig), &data); err != nil {
		return nil, errors.New("invalid Xray config")
	}
	if outbounds, _ := data["outbounds"].([]any); len(outbounds) == 0 {
		return nil, errors.New("Xray config has no outbounds")
	} else {
		for _, item := range outbounds {
			outbound, _ := item.(map[string]any)
			if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(outbound["protocol"])), "wireguard") {
				continue
			}
			settings, _ := outbound["settings"].(map[string]any)
			if settings == nil {
				settings = map[string]any{}
				outbound["settings"] = settings
			}
			settings["noKernelTun"] = true
		}
	}
	inboundTag = strings.TrimSpace(inboundTag)
	if inboundTag == "" {
		inboundTag = "route-test"
	}
	data["log"] = map[string]any{"loglevel": "warning", "access": "none", "error": "none", "dnsLog": false}
	data["inbounds"] = []any{map[string]any{
		"tag":      inboundTag,
		"listen":   "127.0.0.1",
		"port":     socksPort,
		"protocol": "socks",
		"settings": map[string]any{"auth": "noauth", "udp": false},
		"sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}},
	}}
	prepared, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	config, err := NewConfig(string(prepared), "127.0.0.1", appconfig.Settings{XrayAPIHost: "127.0.0.1", XrayAPIPort: apiPort})
	if err != nil {
		return nil, err
	}
	return config.JSON()
}

func (c *Core) TestOutbound(ctx context.Context, outboundTag string, outboundProtocol string, allOutbounds []map[string]any, testURL string, testType string) OutboundTestResult {
	outboundTag = strings.TrimSpace(outboundTag)
	outboundProtocol = strings.ToLower(strings.TrimSpace(outboundProtocol))
	testType = normalizeOutboundTestType(testType)
	testURL = strings.TrimSpace(testURL)
	if testURL == "" {
		testURL = DefaultOutboundTestURL
	}
	if outboundTag == "" {
		return OutboundTestResult{Success: false, Error: "Outbound has no tag", TestType: testType}
	}
	if outboundProtocol == "blackhole" || strings.EqualFold(outboundTag, "blocked") {
		return OutboundTestResult{Success: false, Error: "Blocked/blackhole outbound cannot be tested", TestType: testType}
	}
	if testType == "tcp" || testType == "icmp" {
		target, ok := outboundTestTarget(outboundTag, allOutbounds)
		if !ok {
			return OutboundTestResult{Success: false, Error: "Outbound server address was not found", TestType: testType}
		}
		if testType == "tcp" {
			return measureOutboundTCP(target)
		}
		return measureOutboundICMP(target)
	}
	if outboundProtocol == "freedom" || strings.EqualFold(outboundTag, "direct") {
		delay, statusCode, err := measureDirectDelay(testURL)
		if err != nil {
			return OutboundTestResult{Success: false, Error: "Direct request failed", TestType: testType}
		}
		return OutboundTestResult{Success: true, Delay: delay, StatusCode: statusCode, TestType: testType}
	}
	release, ok := c.acquireTestRuntime(ctx)
	if !ok {
		return OutboundTestResult{Success: false, Error: "Outbound test queue timed out", TestType: testType}
	}
	defer release()

	port, listener, err := findAvailablePort()
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to find available test port", TestType: testType}
	}
	_ = listener.Close()

	config, err := buildOutboundTestConfig(outboundTag, allOutbounds, port)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed", TestType: testType}
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed", TestType: testType}
	}

	c.mu.Lock()
	executable := c.executablePath
	assets := c.assetsPath
	c.mu.Unlock()

	cmd := exec.Command(executable, "run", "-config", "stdin:")
	configureManagedProcess(cmd)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to create stdin pipe for test Xray process", TestType: testType}
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to start test xray instance", TestType: testType}
	}

	if _, err := stdin.Write(configJSON); err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed", TestType: testType}
	}
	_ = stdin.Close()

	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	defer func() {
		stopTestProcess(cmd, done)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}()
	if ready, errText := waitForPort(done, port, 3*time.Second); !ready {
		return OutboundTestResult{Success: false, Error: errText, TestType: testType}
	}

	delay, statusCode, err := measureSocksDelay(port, testURL)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Request failed", TestType: testType}
	}
	return OutboundTestResult{Success: true, Delay: delay, StatusCode: statusCode, TestType: testType}
}

func normalizeOutboundTestType(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "latency":
		return "latency"
	case "tcp":
		return "tcp"
	case "icmp", "ping":
		return "icmp"
	default:
		return "latency"
	}
}

type outboundTarget struct {
	Address string
	Port    int
}

func outboundTestTarget(tag string, outbounds []map[string]any) (outboundTarget, bool) {
	tag = strings.TrimSpace(tag)
	for _, outbound := range outbounds {
		if strings.TrimSpace(fmt.Sprint(outbound["tag"])) != tag {
			continue
		}
		return outboundTargetFromConfig(outbound)
	}
	return outboundTarget{}, false
}

func outboundTargetFromConfig(outbound map[string]any) (outboundTarget, bool) {
	settings, _ := outbound["settings"].(map[string]any)
	protocol := strings.ToLower(strings.TrimSpace(fmt.Sprint(outbound["protocol"])))
	switch protocol {
	case "vmess", "vless":
		return targetFromArray(settings["vnext"], "address", "port")
	case "trojan", "shadowsocks", "socks", "http":
		return targetFromArray(settings["servers"], "address", "port")
	case "hysteria":
		address := stringFromMap(settings, "address")
		port := intFromAny(settings["port"])
		if strings.TrimSpace(address) == "" || port <= 0 {
			return targetFromEndpoint(address)
		}
		return outboundTarget{Address: strings.Trim(strings.TrimSpace(address), "[]"), Port: port}, true
	case "wireguard":
		if target, ok := targetFromArray(settings["peers"], "endpoint", ""); ok {
			return target, true
		}
		return targetFromEndpoint(stringFromMap(settings, "endpoint"))
	default:
		return targetFromEndpoint(firstNonEmptyString(
			stringFromMap(settings, "address"),
			stringFromMap(settings, "domain"),
			stringFromMap(outbound, "address"),
		))
	}
}

func targetFromArray(value any, addressKey string, portKey string) (outboundTarget, bool) {
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return outboundTarget{}, false
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		return outboundTarget{}, false
	}
	address := stringFromMap(first, addressKey)
	if portKey == "" {
		return targetFromEndpoint(address)
	}
	port := intFromAny(first[portKey])
	if strings.TrimSpace(address) == "" || port <= 0 {
		return targetFromEndpoint(address)
	}
	return outboundTarget{Address: strings.Trim(strings.TrimSpace(address), "[]"), Port: port}, true
}

func targetFromEndpoint(endpoint string) (outboundTarget, bool) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return outboundTarget{}, false
	}
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil {
		if strings.Count(endpoint, ":") == 1 {
			parts := strings.SplitN(endpoint, ":", 2)
			host, portText = parts[0], parts[1]
		} else {
			return outboundTarget{Address: strings.Trim(endpoint, "[]")}, true
		}
	}
	port, _ := strconv.Atoi(strings.TrimSpace(portText))
	return outboundTarget{Address: strings.Trim(strings.TrimSpace(host), "[]"), Port: port}, strings.TrimSpace(host) != ""
}

func measureOutboundTCP(target outboundTarget) OutboundTestResult {
	if strings.TrimSpace(target.Address) == "" || target.Port <= 0 {
		return OutboundTestResult{Success: false, Error: "TCP test requires outbound address and port", TestType: "tcp", Address: target.Address, Port: target.Port}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target.Address, strconv.Itoa(target.Port)), 6*time.Second)
	delay := time.Since(start).Milliseconds()
	if err != nil {
		return OutboundTestResult{Success: false, Error: err.Error(), TestType: "tcp", Address: target.Address, Port: target.Port}
	}
	_ = conn.Close()
	return OutboundTestResult{Success: true, Delay: delay, TestType: "tcp", Address: target.Address, Port: target.Port}
}

func measureOutboundICMP(target outboundTarget) OutboundTestResult {
	if strings.TrimSpace(target.Address) == "" {
		return OutboundTestResult{Success: false, Error: "ICMP test requires outbound address", TestType: "icmp", Address: target.Address, Port: target.Port}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	args := []string{"-c", "1", "-W", "5", target.Address}
	if runtime.GOOS == "windows" {
		args = []string{"-n", "1", "-w", "5000", target.Address}
	}
	output, err := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	cleanOutput := strings.TrimSpace(string(output))
	delay := parsePingDelay(cleanOutput)
	if err != nil {
		return OutboundTestResult{Success: false, Delay: delay, Error: firstNonEmptyString(cleanOutput, err.Error()), TestType: "icmp", Address: target.Address, Port: target.Port, Output: cleanOutput}
	}
	return OutboundTestResult{Success: true, Delay: delay, TestType: "icmp", Address: target.Address, Port: target.Port, Output: cleanOutput}
}

var pingDelayPattern = regexp.MustCompile(`(?i)time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms`)

func parsePingDelay(output string) int64 {
	match := pingDelayPattern.FindStringSubmatch(output)
	if len(match) < 2 {
		return 0
	}
	value, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0
	}
	return int64(value + 0.5)
}

func stringFromMap(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	value := values[key]
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		n, _ := typed.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(typed))
		return n
	default:
		return 0
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func buildOutboundTestConfig(outboundTag string, allOutbounds []map[string]any, testPort int) (map[string]any, error) {
	testOutbounds, err := selectOutboundTestOutbounds(outboundTag, allOutbounds)
	if err != nil {
		return nil, err
	}
	outbounds := make([]map[string]any, 0, len(testOutbounds))
	for _, outbound := range testOutbounds {
		cloned := map[string]any{}
		raw, err := json.Marshal(outbound)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &cloned); err != nil {
			return nil, err
		}
		if strings.EqualFold(strings.TrimSpace(fmt.Sprint(cloned["protocol"])), "wireguard") {
			settings, _ := cloned["settings"].(map[string]any)
			if settings == nil {
				settings = map[string]any{}
				cloned["settings"] = settings
			}
			settings["noKernelTun"] = true
		}
		outbounds = append(outbounds, cloned)
	}
	return map[string]any{
		"log": map[string]any{
			"loglevel": "warning",
			"access":   "none",
			"error":    "none",
			"dnsLog":   false,
		},
		"inbounds": []map[string]any{
			{
				"tag":      "test-inbound",
				"listen":   "127.0.0.1",
				"port":     testPort,
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true},
			},
		},
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []map[string]any{
				{
					"type":        "field",
					"outboundTag": outboundTag,
					"network":     "tcp,udp",
				},
			},
		},
		"policy": map[string]any{},
		"stats":  map[string]any{},
	}, nil
}

func selectOutboundTestOutbounds(outboundTag string, allOutbounds []map[string]any) ([]map[string]any, error) {
	byTag := make(map[string]map[string]any, len(allOutbounds))
	for _, outbound := range allOutbounds {
		tag := strings.TrimSpace(fmt.Sprint(outbound["tag"]))
		if tag != "" {
			byTag[tag] = outbound
		}
	}

	selected := make([]map[string]any, 0, 2)
	seen := make(map[string]struct{}, 2)
	for tag := strings.TrimSpace(outboundTag); tag != ""; {
		if _, ok := seen[tag]; ok {
			break
		}
		outbound, ok := byTag[tag]
		if !ok {
			return nil, fmt.Errorf("outbound %q was not found", tag)
		}
		seen[tag] = struct{}{}
		selected = append(selected, outbound)
		proxySettings, _ := outbound["proxySettings"].(map[string]any)
		tag = strings.TrimSpace(stringFromMap(proxySettings, "tag"))
	}
	return selected, nil
}

func findAvailablePort() (int, net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, err
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		_ = listener.Close()
		return 0, nil, errors.New("failed to detect test port")
	}
	return addr.Port, listener, nil
}

func waitForPort(done <-chan struct{}, port int, timeout time.Duration) (bool, string) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			return false, "Xray test instance exited before it was ready"
		default:
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), 150*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true, ""
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false, "Xray test instance did not become ready"
}

func measureDirectDelay(testURL string) (int64, int, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	return measureHTTPDelay(client, testURL)
}

func measureSocksDelay(port int, testURL string) (int64, int, error) {
	dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), nil, proxy.Direct)
	if err != nil {
		return 0, 0, err
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return 0, 0, errors.New("SOCKS5 dialer does not support contexts")
	}
	transport := &http.Transport{
		DialContext: contextDialer.DialContext,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	return measureHTTPDelay(client, testURL)
}

func measureHTTPDelay(client *http.Client, testURL string) (int64, int, error) {
	warmup, err := client.Get(testURL)
	if err != nil {
		return 0, 0, err
	}
	_, _ = io.Copy(io.Discard, warmup.Body)
	_ = warmup.Body.Close()

	start := time.Now()
	response, err := client.Get(testURL)
	if err != nil {
		return 0, 0, err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return time.Since(start).Milliseconds(), response.StatusCode, nil
}

func stopTestProcess(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if done == nil {
		killManagedProcess(cmd)
		return
	}
	_ = terminateManagedProcess(cmd, done)
}
