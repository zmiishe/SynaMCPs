package streamablehttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/mcp"
	"github.com/zmiishe/synamcps/internal/session"
)

type Handler struct {
	server   *mcp.Server
	gateway  *auth.Gateway
	sessions *session.Store
}

func NewHandler(server *mcp.Server, gateway *auth.Gateway, sessions *session.Store) *Handler {
	return &Handler{server: server, gateway: gateway, sessions: sessions}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /mcp", h.gateway.Middleware(http.HandlerFunc(h.post)))
	mux.Handle("GET /mcp", http.HandlerFunc(h.get))
	mux.Handle("DELETE /mcp", http.HandlerFunc(h.deleteSession))
}

func (h *Handler) post(w http.ResponseWriter, r *http.Request) {
	p, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	resp, err := h.server.HandleJSONRPC(r.Context(), p, body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      body["id"],
			"error": map[string]any{
				"code":    -32000,
				"message": err.Error(),
			},
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "missing Mcp-Session-Id", http.StatusBadRequest)
		return
	}
	if _, ok := h.sessions.GetMCPSession(sessionID); !ok {
		http.Error(w, "invalid session", http.StatusNotFound)
		return
	}

	streamID := "default"
	lastEvent := r.Header.Get("Last-Event-ID")
	if lastEvent != "" {
		for _, replay := range h.sessions.ReplayFrom(sessionID, streamID, lastEvent) {
			_, _ = w.Write([]byte(replay))
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	eventID := fmt.Sprintf("%d", time.Now().UnixNano())
	payload := "id: " + eventID + "\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"ping\"}\n\n"
	h.sessions.SaveLastEvent(sessionID, streamID, eventID)
	h.sessions.AppendEvent(sessionID, streamID, payload)
	_, _ = w.Write([]byte(payload))
}

func (h *Handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	// For the scaffold we accept delete, no-op for store cleanup.
	w.WriteHeader(http.StatusNoContent)
}
