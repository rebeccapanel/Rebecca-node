package node

import (
	"net/http"
	"strings"
	"time"

	"github.com/rebeccapanel/rebecca-node/internal/xray"
)

type addInboundUserPayload struct {
	SessionID  string           `json:"session_id"`
	InboundTag string           `json:"inbound_tag"`
	User       xray.InboundUser `json:"user"`
}

type removeInboundUserPayload struct {
	SessionID  string `json:"session_id"`
	InboundTag string `json:"inbound_tag"`
	Email      string `json:"email"`
}

func (s *Server) handleAddInboundUser(w http.ResponseWriter, r *http.Request) {
	var payload addInboundUserPayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, "Xray is not started")
		return
	}

	payload.InboundTag = strings.TrimSpace(payload.InboundTag)
	if payload.InboundTag == "" {
		writeError(w, http.StatusUnprocessableEntity, "inbound_tag is required")
		return
	}

	if err := xray.AddInboundUser(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		60*time.Second,
		payload.InboundTag,
		payload.User,
	); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "added"})
}

func (s *Server) handleRemoveInboundUser(w http.ResponseWriter, r *http.Request) {
	var payload removeInboundUserPayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	if !s.core.Started() {
		writeError(w, http.StatusServiceUnavailable, "Xray is not started")
		return
	}

	payload.InboundTag = strings.TrimSpace(payload.InboundTag)
	payload.Email = strings.TrimSpace(payload.Email)
	if payload.InboundTag == "" {
		writeError(w, http.StatusUnprocessableEntity, "inbound_tag is required")
		return
	}
	if payload.Email == "" {
		writeError(w, http.StatusUnprocessableEntity, "email is required")
		return
	}

	if err := xray.RemoveInboundUser(
		s.settings.XrayAPIHost,
		s.settings.XrayAPIPort,
		60*time.Second,
		payload.InboundTag,
		payload.Email,
	); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "removed"})
}
