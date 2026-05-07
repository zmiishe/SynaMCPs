package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/access"
	"github.com/zmiishe/synamcps/internal/httpapi"
	"github.com/zmiishe/synamcps/internal/knowledge"
	"github.com/zmiishe/synamcps/internal/knowledge/ingest"
	"github.com/zmiishe/synamcps/internal/llm"
	"github.com/zmiishe/synamcps/internal/mcp"
	"github.com/zmiishe/synamcps/internal/observability"
	"github.com/zmiishe/synamcps/internal/session"
	"github.com/zmiishe/synamcps/internal/storage/blob"
	metapg "github.com/zmiishe/synamcps/internal/storage/meta/postgres"
	"github.com/zmiishe/synamcps/internal/storage/vector"
	"github.com/zmiishe/synamcps/internal/storage/vector/pgvector"
	"github.com/zmiishe/synamcps/internal/storage/vector/qdrant"
	"github.com/zmiishe/synamcps/internal/transport/legacysse"
	"github.com/zmiishe/synamcps/internal/transport/streamablehttp"
	"github.com/zmiishe/synamcps/internal/usage"
	"github.com/zmiishe/synamcps/internal/web"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.example.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	sessions := session.NewStore(cfg.Redis)
	gateway := auth.NewGateway(cfg)
	accessStore, err := access.NewStore(context.Background(), cfg.Metadata.DSN)
	if err != nil {
		log.Fatalf("init access store: %v", err)
	}
	accessService := access.NewService(accessStore)
	gateway.SetOpaqueTokenResolver(accessService)
	usageService := usage.NewService(cfg.Redis, cfg.Usage)
	if cfg.Usage.Exporters.VictoriaMetrics.Enabled {
		usageService.StartVictoriaMetricsExporter(context.Background(), cfg.Usage.Exporters.VictoriaMetrics.RemoteWriteURL, time.Duration(cfg.Usage.Exporters.VictoriaMetrics.IntervalSeconds)*time.Second)
	}
	catalog, err := metapg.New(context.Background(), cfg.Metadata.DSN)
	if err != nil {
		log.Fatalf("init metadata catalog: %v", err)
	}
	blobStore, err := blob.NewStore(cfg)
	if err != nil {
		log.Fatalf("init s3 store: %v", err)
	}
	var vec vector.Store
	if cfg.VectorBackend.Active == "qdrant" {
		vec, err = qdrant.New(cfg.VectorBackend.QdrantURL, cfg.VectorBackend.QdrantCollection)
		if err != nil {
			log.Fatalf("init qdrant store: %v", err)
		}
	} else {
		vec, err = pgvector.New(context.Background(), cfg.Metadata.DSN)
		if err != nil {
			log.Fatalf("init pgvector store: %v", err)
		}
	}

	summarizer := llm.NewSimpleSummarizer(cfg.Summarization)
	embedder := llm.NewSimpleEmbeddingProvider(cfg.Embedding)
	pipeline := ingest.NewPipeline(cfg, summarizer, embedder, vec, catalog, blobStore)
	knowledgeService := knowledge.NewService(catalog, vec, pipeline)
	knowledgeService.AttachAccess(accessService, cfg.S3.Bucket)

	rootMux := http.NewServeMux()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	metrics := observability.NewHTTPMetrics()
	metrics.AttachUsageExporter(usageService)
	rootMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	rootMux.Handle("/metrics", metrics.Handler())
	rootMux.Handle("/readyz", observability.ReadyzHandler(logger, map[string]observability.Pinger{
		"redis":    sessions,
		"metadata": catalog,
		"blob":     blobStore,
	}))
	apiRouter := httpapi.NewRouterWithAdmin(gateway, sessions, knowledgeService, accessService, usageService, cfg.S3.Bucket, cfg.Search.Filters.SourceURL.AllowPartialMatch)
	rootMux.Handle("/api/", apiRouter)
	rootMux.HandleFunc("/api/capabilities", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"transports": map[string]bool{
				"streamable_http": cfg.Transport.StreamableHTTP,
				"legacy_sse":      cfg.Transport.LegacySSE,
			},
			"auth_methods": buildAuthMethods(cfg),
		})
	})
	rootMux.Handle("/.well-known/oauth-protected-resource", gateway.ProtectedResourceMetadataHandler())
	rootMux.Handle("/.well-known/oauth-authorization-server", gateway.AuthorizationServerMetadataHandler())

	if cfg.Web.EnableUI {
		rootMux.Handle("/", web.NewHandler(cfg, sessions, accessService))
	}

	mcpServer := mcp.NewServer(sessions, knowledgeService)
	mcpServer.AttachAccess(accessService)
	mcpServer.AttachUsage(usageService)
	if cfg.Transport.StreamableHTTP {
		streamablehttp.NewHandler(mcpServer, gateway, sessions).Register(rootMux)
	}
	if cfg.Transport.LegacySSE {
		legacysse.NewHandler().Register(rootMux)
	}

	server := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           metrics.Middleware(logger, withMiddlewares(rootMux, cfg)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("server listening on %s", cfg.Server.ListenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func buildAuthMethods(cfg config.Config) []string {
	out := make([]string, 0, len(cfg.OAuth.Providers)+1)
	for _, p := range cfg.OAuth.Providers {
		out = append(out, p.Name)
	}
	if cfg.Teleport.Enabled {
		out = append(out, "teleport_proxy")
	}
	return out
}

func withMiddlewares(next http.Handler, cfg config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if !isWebRoute(r.URL.Path) && !isAllowedOrigin(origin, r.Host, cfg.API.AllowedOrigins) {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isWebRoute(path string) bool {
	return path == "/" || path == "/login" || path == "/logout" || strings.HasPrefix(path, "/app")
}

func isAllowedOrigin(origin, host string, allowlist []string) bool {
	if origin == "" {
		return true
	}
	if origin == "http://"+host || origin == "https://"+host {
		return true
	}
	originURL, err := url.Parse(origin)
	if err == nil {
		if sameHost(originURL.Host, host) || isLoopbackHost(originURL.Hostname()) {
			return true
		}
	}
	for _, allowed := range allowlist {
		if allowed == "*" {
			return true
		}
		if allowed == origin {
			return true
		}
	}
	return false
}

func sameHost(a, b string) bool {
	aHost, aPort := splitHostPort(a)
	bHost, bPort := splitHostPort(b)
	return aHost != "" && aHost == bHost && aPort == bPort
}

func splitHostPort(value string) (string, string) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return host, port
	}
	return value, ""
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
