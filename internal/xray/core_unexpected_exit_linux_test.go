//go:build linux

package xray

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
)

func TestUnexpectedExitNotifiesButStopDoesNot(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "xray")
	script := `#!/bin/sh
if [ "$1" = version ]; then echo 'Xray 26.5.9'; exit 0; fi
if [ "$2" = -test ]; then cat >/dev/null; exit 0; fi
cat >/dev/null
while :; do sleep 0.1; done
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	core, err := NewCore(executable, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	notified := make(chan struct{}, 4)
	core.SetUnexpectedExitHandler(func() { notified <- struct{}{} })
	config, err := NewConfig(`{"inbounds":[],"outbounds":[]}`, "127.0.0.1", appconfig.Settings{XrayAssetsPath: dir, XrayLogDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(config); err != nil {
		t.Fatal(err)
	}
	core.Stop()
	if err := core.Start(config); err != nil {
		t.Fatal(err)
	}
	if err := core.Restart(config); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notified:
		t.Fatal("Stop and Restart must not count as unexpected exits")
	case <-time.After(300 * time.Millisecond):
	}
	pid, _ := core.Process()
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-notified:
	case <-time.After(3 * time.Second):
		t.Fatal("killed process was not reported as an unexpected exit")
	}
	if core.Started() {
		t.Fatal("core still reports running after the process was killed")
	}
}
