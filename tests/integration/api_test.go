package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/httpapi"
	"github.com/zmiishe/synamcps/internal/knowledge"
	"github.com/zmiishe/synamcps/internal/knowledge/ingest"
	"github.com/zmiishe/synamcps/internal/llm"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/session"
	"github.com/zmiishe/synamcps/internal/storage/blob"
	metapg "github.com/zmiishe/synamcps/internal/storage/meta/postgres"
	"github.com/zmiishe/synamcps/internal/storage/vector/pgvector"
)

func TestCreateAndListKnowledge(t *testing.T) {
	cfg := config.Config{
		OAuth:         config.OAuthConfig{Providers: []config.ProviderConfig{{Name: "keycloak", Issuer: "https://issuer", JWKSURL: "insecure"}}},
		Redis:         config.RedisConfig{TTLHours: 1, KeyPrefix: "test"},
		Chunking:      config.ChunkingConfig{ChunkSize: 10, Overlap: 2},
		S3:            config.S3Config{LargeDocBytes: 1000000},
		Embedding:     config.ModelConfig{Model: "emb"},
		Summarization: config.ModelConfig{Model: "sum", MaxOutputTokens: 10},
	}
	sessions := session.NewStore(cfg.Redis)
	gateway := auth.NewGateway(cfg)
	catalog := metapg.NewInMemory()
	vec := pgvector.NewInMemory()
	blobStore, err := blob.NewStore(config.Config{})
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	p := ingest.NewPipeline(cfg, llm.NewSimpleSummarizer(cfg.Summarization), llm.NewSimpleEmbeddingProvider(cfg.Embedding), vec, catalog, blobStore)
	svc := knowledge.NewService(catalog, vec, p)
	api := httpapi.NewRouter(gateway, sessions, svc, true)

	token := mustDevJWT(t, map[string]any{
		"sub":    "u1",
		"email":  "a@example.com",
		"iss":    "https://issuer",
		"aud":    "syna-mcp",
		"scopes": []string{"knowledge.write.public"},
		"groups": []string{"ops"},
	})

	create := map[string]any{
		"title":      "Doc",
		"text":       "hello world from integration",
		"mimeType":   "text/plain",
		"visibility": string(models.VisibilityPersonal),
	}
	body, _ := json.Marshal(create)
	req := httptest.NewRequest(http.MethodPost, "/api/knowledge", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/knowledge", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRec := httptest.NewRecorder()
	api.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}
}

func mustDevJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadRaw, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadRaw)
	return header + "." + payload + "."
}
