//go:build !windows

package xray

import (
	"fmt"
	"os/exec"
	"syscall"
)

func configureManagedProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateManagedProcess(cmd *exec.Cmd, exited <-chan struct{}) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	if pid <= 0 {
		return cmd.Process.Kill()
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	if waitProcessExit(exited, processExitGrace) {
		return nil
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	if waitProcessExit(exited, processExitGrace) {
		return nil
	}
	return fmt.Errorf("process group %d still running after SIGKILL", pid)
}

func killManagedProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.Process.Pid > 0 {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}
