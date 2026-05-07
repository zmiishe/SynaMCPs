package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/web"
)

func TestMCPConnectPageAvailable(t *testing.T) {
	handler := web.NewHandler(config.Config{
		Transport: config.TransportConfig{LegacySSE: true},
		OAuth: config.OAuthConfig{Providers: []config.ProviderConfig{
			{Name: "keycloak"},
			{Name: "google"},
		}},
		Teleport: config.TeleportConfig{Enabled: true},
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/app/mcp-connect")
	if err != nil {
		t.Fatalf("http get: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "MCP Connection Guide") {
		t.Fatalf("missing guide content")
	}
}
