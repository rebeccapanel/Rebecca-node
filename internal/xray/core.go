package xray

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Core struct {
	lifecycleMu    sync.Mutex
	testSlotsOnce  sync.Once
	testSlots      chan struct{}
	mu             sync.Mutex
	executablePath string
	assetsPath     string
	cmd            *exec.Cmd
	running        bool
	logs           *LogBus
	version        string
	debug          bool
	startedAt      time.Time
}

const maxConcurrentTestRuntimes = 2

func (c *Core) acquireTestRuntime(ctx context.Context) (func(), bool) {
	c.testSlotsOnce.Do(func() {
		c.testSlots = make(chan struct{}, maxConcurrentTestRuntimes)
	})
	select {
	case c.testSlots <- struct{}{}:
		return func() { <-c.testSlots }, true
	case <-ctx.Done():
		return nil, false
	}
}

func NewCore(executablePath, assetsPath string, debug bool) (*Core, error) {
	core := &Core{
		executablePath: executablePath,
		assetsPath:     assetsPath,
		logs:           NewLogBus(100),
		debug:          debug,
	}
	version, err := core.GetVersion()
	if err != nil {
		return nil, err
	}
	core.version = version
	return core, nil
}

func (c *Core) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

func (c *Core) SetExecutablePath(path string) error {
	c.mu.Lock()
	c.executablePath = path
	c.mu.Unlock()
	version, err := c.GetVersion()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.version = version
	c.mu.Unlock()
	return nil
}

func (c *Core) SetAssetsPath(path string) {
	c.mu.Lock()
	c.assetsPath = path
	c.mu.Unlock()
}

func (c *Core) Logs() *LogBus {
	return c.logs
}

func (c *Core) GetVersion() (string, error) {
	c.mu.Lock()
	executable := c.executablePath
	c.mu.Unlock()

	output, err := exec.Command(executable, "version").CombinedOutput()
	if err != nil {
		return "", err
	}
	match := regexp.MustCompile(`(?m)^Xray ([0-9]+\.[0-9]+\.[0-9]+)`).FindSubmatch(output)
	if len(match) < 2 {
		return "", errors.New("unable to detect Xray version")
	}
	return string(match[1]), nil
}

func (c *Core) Started() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.running
}

func (c *Core) Process() (int, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running || c.cmd == nil || c.cmd.Process == nil {
		return 0, 0
	}
	return c.cmd.Process.Pid, uint64(time.Since(c.startedAt).Seconds())
}

func (c *Core) Start(config *Config) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	return c.start(config)
}

func (c *Core) start(config *Config) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("Xray is started already")
	}
	executable := c.executablePath
	assets := c.assetsPath
	c.mu.Unlock()
	cleanupStaleManagedProcesses(executable)

	if err := config.NormalizeLogPaths(); err != nil {
		return err
	}
	if err := ensureLogFiles(config); err != nil {
		return err
	}
	configJSON, err := config.JSON()
	if err != nil {
		return err
	}

	cmd := exec.Command(executable, "run", "-config", "stdin:")
	configureManagedProcess(cmd)
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := stdin.Write(configJSON); err != nil {
		terminateManagedProcess(cmd)
		return err
	}
	_ = stdin.Close()

	c.mu.Lock()
	c.cmd = cmd
	c.running = true
	c.startedAt = time.Now()
	c.mu.Unlock()

	go c.capture(stdout)
	go c.capture(stderr)
	go func() {
		err := cmd.Wait()
		if err != nil {
			log.Printf("xray exited: %v", err)
		} else if c.debug {
			log.Print("xray exited")
		}
		c.mu.Lock()
		if c.cmd == cmd {
			c.running = false
			c.cmd = nil
			c.startedAt = time.Time{}
		}
		c.mu.Unlock()
	}()

	return nil
}

func (c *Core) Stop() {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	c.stop()
}

func (c *Core) stop() {
	c.mu.Lock()
	cmd := c.cmd
	c.cmd = nil
	c.running = false
	c.startedAt = time.Time{}
	c.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		terminateManagedProcess(cmd)
	}
}

func (c *Core) Restart(config *Config) error {
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	// Reject an invalid replacement without stopping the healthy runtime.
	if err := c.validate(config); err != nil {
		return err
	}
	c.stop()
	return c.start(config)
}

func (c *Core) validate(config *Config) error {
	if err := config.NormalizeLogPaths(); err != nil {
		return err
	}
	if err := ensureLogFiles(config); err != nil {
		return err
	}
	configJSON, err := config.JSON()
	if err != nil {
		return err
	}
	c.mu.Lock()
	executable, assets := c.executablePath, c.assetsPath
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "run", "-test", "-config", "stdin:")
	cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+assets)
	cmd.Stdin = bytes.NewReader(configJSON)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return fmt.Errorf("Xray replacement validation failed; running runtime preserved: %w", ctx.Err())
	}
	if err != nil {
		return fmt.Errorf("Xray replacement validation failed; running runtime preserved: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (c *Core) capture(pipe interface{ Read([]byte) (int, error) }) {
	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		c.logs.Append(line)
		if c.debug {
			log.Print(line)
		}
	}
}

func ensureLogFiles(config *Config) error {
	logConfig, _ := config.data["log"].(map[string]any)
	for _, key := range []string{"access", "error"} {
		path, _ := logConfig[key].(string)
		if path == "" || strings.EqualFold(path, "none") {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		_ = file.Close()
	}
	return nil
}

func LooksStarted(logs []string, version string) bool {
	needle := "Xray " + version + " started"
	for _, line := range logs {
		if bytes.Contains([]byte(line), []byte(needle)) {
			return true
		}
	}
	return false
}
