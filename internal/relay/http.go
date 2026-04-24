package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"strconv"
	"strings"

	"vlf-runtime/internal/auth"
	"vlf-runtime/internal/limits"
	"vlf-runtime/internal/metrics"

	"go.uber.org/zap"
)

type ctxKey string

const (
	clientIDKey  ctxKey = "client_id"
	requestIDKey ctxKey = "request_id"
)

type Server struct {
	manager  *Manager
	verifier *auth.Verifier
	metrics  *metrics.Metrics
	logger   *zap.Logger
	mux      *http.ServeMux
	enableMetrics bool
}

func NewServer(manager *Manager, verifier *auth.Verifier, m *metrics.Metrics, logger *zap.Logger, enableMetrics bool) *Server {
	s := &Server{
		manager:  manager,
		verifier: verifier,
		metrics:  m,
		logger:   logger,
		mux:      http.NewServeMux(),
		enableMetrics: enableMetrics,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	if s.enableMetrics {
		s.mux.Handle("/metrics", s.metrics.Handler())
	}
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	s.mux.HandleFunc("/debug/pprof/", pprof.Index)
	s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	s.mux.HandleFunc("/v1/relay/open", s.withAuth(s.handleOpen))
	s.mux.HandleFunc("/v1/relay/send", s.withAuth(s.handleSend))
	s.mux.HandleFunc("/v1/relay/recv", s.withAuth(s.handleRecv))
	s.mux.HandleFunc("/v1/relay/ping", s.withAuth(s.handlePing))
	s.mux.HandleFunc("/v1/relay/close", s.withAuth(s.handleClose))
}

func (s *Server) Handler() http.Handler {
	return s.withRequestID(s.mux)
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if reqID == "" {
			reqID = newRequestID()
		}
		w.Header().Set("X-Request-ID", reqID)

		ctx := context.WithValue(r.Context(), requestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "read body", err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		clientID, err := s.verifier.VerifyHTTP(r, body)
		if err != nil {
			reqLogger := s.requestLogger(r).With(zap.Error(err))
			reqLogger.Warn("relay auth failed")
			writeJSONError(w, http.StatusUnauthorized, "auth failed", err)
			return
		}

		ctx := context.WithValue(r.Context(), clientIDKey, clientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) handleOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req OpenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON", err)
		return
	}

	clientID := mustClientID(r.Context())
	reqLogger := s.requestLogger(r).With(zap.String("client_id", clientID))

	resp, err := s.manager.Open(r.Context(), clientID, req)
	if err != nil {
		status := statusForError(err)
		reqLogger.Warn("relay open failed", zap.Error(err), zap.Int("status", status))
		writeJSONError(w, status, "open failed", err)
		return
	}

	reqLogger.Info("relay open succeeded", zap.String("conn_id", resp.ConnID))
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	connID := strings.TrimSpace(r.URL.Query().Get("conn_id"))
	if connID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conn_id", nil)
		return
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "read body", err)
		return
	}

	clientID := mustClientID(r.Context())
	reqLogger := s.requestLogger(r).With(zap.String("client_id", clientID), zap.String("conn_id", connID))

	resp, err := s.manager.Send(clientID, connID, payload)
	if err != nil {
		status := statusForError(err)
		reqLogger.Warn("relay send failed", zap.Error(err), zap.Int("status", status))
		writeJSONError(w, status, "send failed", err)
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRecv(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	connID := strings.TrimSpace(r.URL.Query().Get("conn_id"))
	if connID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conn_id", nil)
		return
	}

	max := 32768
	if raw := strings.TrimSpace(r.URL.Query().Get("max")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid max", err)
			return
		}
		max = parsed
	}

	clientID := mustClientID(r.Context())
	reqLogger := s.requestLogger(r).With(zap.String("client_id", clientID), zap.String("conn_id", connID))

	data, eos, err := s.manager.Recv(clientID, connID, max)
	if err != nil {
		status := statusForError(err)
		reqLogger.Warn("relay recv failed", zap.Error(err), zap.Int("status", status))
		writeJSONError(w, status, "recv failed", err)
		return
	}

	if len(data) == 0 && !eos {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-VLF-Bytes", strconv.Itoa(len(data)))
	if eos {
		w.Header().Set("X-VLF-EOS", "1")
	} else {
		w.Header().Set("X-VLF-EOS", "0")
	}

	w.WriteHeader(http.StatusOK)
	if len(data) > 0 {
		_, _ = w.Write(data)
	}
}

func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	connID := strings.TrimSpace(r.URL.Query().Get("conn_id"))
	if connID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conn_id", nil)
		return
	}

	clientID := mustClientID(r.Context())
	resp, err := s.manager.Ping(clientID, connID)
	if err != nil {
		status := statusForError(err)
		writeJSONError(w, status, "ping failed", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	connID := strings.TrimSpace(r.URL.Query().Get("conn_id"))
	if connID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing conn_id", nil)
		return
	}

	clientID := mustClientID(r.Context())
	closed := s.manager.Close(connID, clientID, "client_close")
	writeJSON(w, http.StatusOK, CloseResponse{Closed: closed})
}

func (s *Server) requestLogger(r *http.Request) *zap.Logger {
	reqID, _ := r.Context().Value(requestIDKey).(string)
	if reqID == "" {
		reqID = "unknown"
	}
	return s.logger.With(
		zap.String("request_id", reqID),
		zap.String("method", r.Method),
		zap.String("path", r.URL.Path),
	)
}

func mustClientID(ctx context.Context) string {
	clientID, _ := ctx.Value(clientIDKey).(string)
	return clientID
}

func newRequestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "req_fallback"
	}
	return "req_" + hex.EncodeToString(raw)
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrBadRequest):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnknownConn):
		return http.StatusNotFound
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, limits.ErrMaxConnsPerClient), errors.Is(err, limits.ErrMaxTotalConns), errors.Is(err, limits.ErrMaxBytesPerMinute):
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, status int, msg string, err error) {
	type errResp struct {
		Error string `json:"error"`
	}

	if err != nil {
		writeJSON(w, status, errResp{Error: fmt.Sprintf("%s: %v", msg, err)})
		return
	}
	writeJSON(w, status, errResp{Error: msg})
}
