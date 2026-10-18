//go:build linux

package xray

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func cleanupStaleManagedProcesses(executable string) {
	expected, err := filepath.EvalSymlinks(executable)
	if err != nil {
		expected = executable
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		if procPPID(pid) != 1 {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		exe = staleProcessExecutable(exe)
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		if exe != expected {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || !isManagedXrayCmdline(cmdline) {
			continue
		}
		log.Printf("stopping stale orphaned xray process pid=%d", pid)
		_ = syscall.Kill(pid, syscall.SIGTERM)
		time.Sleep(500 * time.Millisecond)
		if processExists(pid) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func staleProcessExecutable(link string) string {
	return strings.TrimSuffix(link, " (deleted)")
}

func procPPID(pid int) int {
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0
		}
		ppid, _ := strconv.Atoi(fields[1])
		return ppid
	}
	return 0
}

func isManagedXrayCmdline(cmdline []byte) bool {
	parts := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	if len(parts) < 4 {
		return false
	}
	for i := 1; i+2 < len(parts); i++ {
		if string(parts[i]) == "run" && string(parts[i+1]) == "-config" && string(parts[i+2]) == "stdin:" {
			return true
		}
	}
	return false
}

func processExists(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
