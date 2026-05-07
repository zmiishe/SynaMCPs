package observability

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type Pinger interface {
	Ping(ctx context.Context) error
}

type HTTPMetrics struct {
	requestsTotal uint64
	errorsTotal   uint64
	usageExporter interface{ Prometheus() string }
}

func NewHTTPMetrics() *HTTPMetrics { return &HTTPMetrics{} }

func (m *HTTPMetrics) AttachUsageExporter(exporter interface{ Prometheus() string }) {
	m.usageExporter = exporter
}

func (m *HTTPMetrics) Middleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		atomic.AddUint64(&m.requestsTotal, 1)
		reqID := uuid.NewString()
		w.Header().Set("X-Request-Id", reqID)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if rec := recover(); rec != nil {
				atomic.AddUint64(&m.errorsTotal, 1)
				logger.Error("panic in request", "request_id", reqID, "panic", rec, "stack", string(debug.Stack()))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
			if rec.status >= 500 {
				atomic.AddUint64(&m.errorsTotal, 1)
			}
			logger.Info("http_request",
				"request_id", reqID,
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote_addr", r.RemoteAddr,
			)
		}()

		next.ServeHTTP(rec, r)
	})
}

func (m *HTTPMetrics) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w, "http_requests_total %d\n", atomic.LoadUint64(&m.requestsTotal))
		_, _ = fmt.Fprintf(w, "http_errors_total %d\n", atomic.LoadUint64(&m.errorsTotal))
		if m.usageExporter != nil {
			_, _ = w.Write([]byte(m.usageExporter.Prometheus()))
		}
	}
}

func ReadyzHandler(logger *slog.Logger, checks map[string]Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		type result struct {
			OK    bool   `json:"ok"`
			Error string `json:"error,omitempty"`
		}
		out := map[string]result{}
		allOK := true
		for name, checker := range checks {
			if checker == nil {
				out[name] = result{OK: true}
				continue
			}
			if err := checker.Ping(ctx); err != nil {
				allOK = false
				out[name] = result{OK: false, Error: err.Error()}
				logger.Error("readiness check failed", "name", name, "error", err)
			} else {
				out[name] = result{OK: true}
			}
		}
		status := http.StatusOK
		if !allOK {
			status = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      allOK,
			"checks":  out,
			"version": "0.1.0",
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
