package legacysse

import "net/http"

type Handler struct{}

func NewHandler() *Handler { return &Handler{} }

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: endpoint\ndata: /messages\n\n"))
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})
}
