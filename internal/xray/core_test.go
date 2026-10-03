package xray

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
)

func TestInvalidReplacementPreservesRunningCore(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "xray")
	script := `#!/bin/sh
if [ "$1" = version ]; then echo 'Xray 26.5.9'; exit 0; fi
if [ "$2" = -test ]; then
  body=$(cat)
  case "$body" in *broken*) echo 'unknown protocol broken'; exit 2;; esac
  exit 0
fi
cat >/dev/null
while :; do sleep 1; done
`
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	core, err := NewCore(executable, dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Stop()
	settings := appconfig.Settings{XrayAssetsPath: dir, XrayLogDir: dir}
	good, err := NewConfig(`{"inbounds":[],"outbounds":[]}`, "127.0.0.1", settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Start(good); err != nil {
		t.Fatal(err)
	}
	before, _ := core.Process()
	bad, err := NewConfig(`{"inbounds":[],"outbounds":[{"protocol":"broken"}]}`, "127.0.0.1", settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Restart(bad); err == nil || !strings.Contains(err.Error(), "unknown protocol broken") {
		t.Fatalf("expected actionable validation error: %v", err)
	}
	after, _ := core.Process()
	if !core.Started() || before == 0 || after != before {
		t.Fatalf("invalid replacement stopped the healthy runtime: before=%d after=%d", before, after)
	}
}
