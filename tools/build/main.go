package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

type target struct {
	name string
	pkg  string
}

var targets = []target{
	{name: "rebecca-node", pkg: "./cmd/rebecca-node"},
}

func main() {
	goos := envDefault("REBECCA_NODE_GOOS", runtime.GOOS)
	goarch := envDefault("REBECCA_NODE_GOARCH", runtime.GOARCH)
	goarm := os.Getenv("REBECCA_NODE_GOARM")
	distDir := filepath.Join(".", "dist")
	if err := os.RemoveAll(distDir); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		fatal(err)
	}

	for _, item := range targets {
		output := filepath.Join(distDir, item.name+suffix(goos))
		targetLabel := goos + "/" + goarch
		if goarm != "" {
			targetLabel += "/v" + goarm
		}
		fmt.Printf("[build-binary] Building %s from %s for %s\n", item.name, item.pkg, targetLabel)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", output, item.pkg)
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
		if goarm != "" {
			cmd.Env = append(cmd.Env, "GOARM="+goarm)
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatal(err)
		}
	}

	fmt.Println("[build-binary] Build completed:")
	entries, err := os.ReadDir(distDir)
	if err != nil {
		fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			fmt.Printf("  - %s\n", entry.Name())
		}
	}
}

func envDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func suffix(goos string) string {
	if goos == "windows" {
		return ".exe"
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
