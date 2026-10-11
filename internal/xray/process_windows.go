//go:build windows

package xray

import (
	"fmt"
	"os/exec"
)

func configureManagedProcess(cmd *exec.Cmd) {}

func terminateManagedProcess(cmd *exec.Cmd, exited <-chan struct{}) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	_ = cmd.Process.Kill()
	if waitProcessExit(exited, processExitGrace) {
		return nil
	}
	return fmt.Errorf("process %d still running after kill", cmd.Process.Pid)
}

func killManagedProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
