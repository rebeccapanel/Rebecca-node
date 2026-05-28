package node

import (
	"net/http"
	"strings"
)

type x25519Payload struct {
	SessionID  string `json:"session_id"`
	PrivateKey string `json:"private_key"`
}

type echPayload struct {
	SessionID  string `json:"session_id"`
	ServerName string `json:"server_name"`
}

func (s *Server) handleX25519(w http.ResponseWriter, r *http.Request) {
	var payload x25519Payload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	result, err := s.core.GetX25519(payload.PrivateKey)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleMLDSA65(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		SessionID string `json:"session_id"`
	}
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	result, err := s.core.GetMLDSA65()
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleECH(w http.ResponseWriter, r *http.Request) {
	var payload echPayload
	if !decodeJSON(w, r, &payload) {
		return
	}
	if !s.matchSession(w, payload.SessionID) {
		return
	}
	payload.ServerName = strings.TrimSpace(payload.ServerName)
	if payload.ServerName == "" {
		writeError(w, http.StatusUnprocessableEntity, "server_name is required")
		return
	}
	result, err := s.core.GetECHCert(payload.ServerName)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
