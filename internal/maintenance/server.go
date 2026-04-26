package maintenance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	appconfig "github.com/rebeccapanel/rebecca-node/internal/config"
)

type Server struct {
	settings appconfig.MaintenanceSettings
	nodeCLI  string
}

func New(settings appconfig.MaintenanceSettings) (*Server, error) {
	cli, err := resolveCLI(settings.NodeCLI)
	if err != nil {
		return nil, err
	}
	return &Server{settings: settings, nodeCLI: cli}, nil
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.localOnly(s.handleHealth))
	mux.HandleFunc("/update", s.localOnly(s.handleUpdate))
	mux.HandleFunc("/restart", s.localOnly(s.handleRestart))
	return http.ListenAndServe(fmt.Sprintf("%s:%d", s.settings.Host, s.settings.Port), mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "cli": s.nodeCLI})
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	s.runCLI(w, "update")
}

func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	s.runCLI(w, "restart", "-n")
}

func (s *Server) runCLI(w http.ResponseWriter, args ...string) {
	cmd := exec.Command(s.nodeCLI, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"detail": map[string]string{
				"message": fmt.Sprintf("Command %s %s failed: %v", s.nodeCLI, strings.Join(args, " "), err),
				"stdout":  stdout.String(),
				"stderr":  stderr.String(),
			},
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "stdout": strings.TrimSpace(stdout.String())})
}

func (s *Server) localOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if _, ok := s.settings.AllowedHosts[host]; !ok {
			writeJSON(w, http.StatusForbidden, map[string]string{"detail": "Only local requests are allowed"})
			return
		}
		next(w, r)
	}
}

func resolveCLI(configured string) (string, error) {
	if strings.TrimSpace(configured) != "" {
		if fileExists(configured) {
			return configured, nil
		}
		return "", errors.New("Unable to locate rebecca-node CLI. Set REBECCA_NODE_SCRIPT_BIN.")
	}
	if path, err := exec.LookPath("rebecca-node"); err == nil {
		return path, nil
	}
	fallback := "/usr/local/bin/rebecca-node"
	if fileExists(fallback) {
		return fallback, nil
	}
	if runtimeFallback := filepath.Join(filepath.Dir(os.Args[0]), executableName("rebecca-node")); fileExists(runtimeFallback) {
		return runtimeFallback, nil
	}
	return "", errors.New("Unable to locate rebecca-node CLI. Set REBECCA_NODE_SCRIPT_BIN.")
}

func executableName(name string) string {
	if strings.HasSuffix(strings.ToLower(os.Args[0]), ".exe") {
		return name + ".exe"
	}
	return name
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
