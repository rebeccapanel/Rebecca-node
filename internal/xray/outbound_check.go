package xray

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const DefaultOutboundTestURL = "https://www.google.com/generate_204"

type OutboundTestResult struct {
	Success    bool   `json:"success"`
	Delay      int64  `json:"delay,omitempty"`
	StatusCode int    `json:"statusCode,omitempty"`
	Error      string `json:"error,omitempty"`
}

func (c *Core) TestOutbound(outboundTag string, outboundProtocol string, allOutbounds []map[string]any, testURL string) OutboundTestResult {
	outboundTag = strings.TrimSpace(outboundTag)
	outboundProtocol = strings.ToLower(strings.TrimSpace(outboundProtocol))
	testURL = strings.TrimSpace(testURL)
	if testURL == "" {
		testURL = DefaultOutboundTestURL
	}
	if outboundTag == "" {
		return OutboundTestResult{Success: false, Error: "Outbound has no tag"}
	}
	if outboundProtocol == "blackhole" || strings.EqualFold(outboundTag, "blocked") {
		return OutboundTestResult{Success: false, Error: "Blocked/blackhole outbound cannot be tested"}
	}
	if outboundProtocol == "freedom" || strings.EqualFold(outboundTag, "direct") {
		delay, statusCode, err := measureDirectDelay(testURL)
		if err != nil {
			return OutboundTestResult{Success: false, Error: "Direct request failed"}
		}
		return OutboundTestResult{Success: true, Delay: delay, StatusCode: statusCode}
	}

	port, listener, err := findAvailablePort()
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to find available test port"}
	}
	_ = listener.Close()

	config, err := buildOutboundTestConfig(outboundTag, allOutbounds, port)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed"}
	}
	configJSON, err := json.Marshal(config)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed"}
	}

	c.mu.Lock()
	executable := c.executablePath
	assets := c.assetsPath
	c.mu.Unlock()

	cmd := exec.Command(executable, "run", "-config", "stdin:")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to create stdin pipe for test Xray process"}
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return OutboundTestResult{Success: false, Error: "Failed to start test xray instance"}
	}
	defer stopTestProcess(cmd)

	if _, err := stdin.Write(configJSON); err != nil {
		return OutboundTestResult{Success: false, Error: "Outbound test failed"}
	}
	_ = stdin.Close()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if ready, errText := waitForPort(done, port, 3*time.Second); !ready {
		if strings.TrimSpace(output.String()) != "" && errText == "Xray test instance exited before it was ready" {
			return OutboundTestResult{Success: false, Error: errText}
		}
		return OutboundTestResult{Success: false, Error: errText}
	}

	delay, statusCode, err := measureSocksDelay(port, testURL)
	if err != nil {
		return OutboundTestResult{Success: false, Error: "Request failed"}
	}
	return OutboundTestResult{Success: true, Delay: delay, StatusCode: statusCode}
}

func buildOutboundTestConfig(outboundTag string, allOutbounds []map[string]any, testPort int) (map[string]any, error) {
	outbounds := make([]map[string]any, 0, len(allOutbounds))
	for _, outbound := range allOutbounds {
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

func waitForPort(done <-chan error, port int, timeout time.Duration) (bool, string) {
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

func stopTestProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
