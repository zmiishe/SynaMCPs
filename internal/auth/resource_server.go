package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/models"
)

type principalContextKey string

const PrincipalContextKey principalContextKey = "principal"
const AccessContextKey principalContextKey = "access_context"

type OpaqueTokenResolver interface {
	ResolveBearer(ctx context.Context, raw string) (models.APIAccessContext, bool, error)
}

type Gateway struct {
	router        *ProviderRouter
	cfg           config.Config
	tokenResolver OpaqueTokenResolver
}

func NewGateway(cfg config.Config) *Gateway {
	return &Gateway{router: NewProviderRouter(cfg), cfg: cfg}
}

func (g *Gateway) SetOpaqueTokenResolver(resolver OpaqueTokenResolver) {
	g.tokenResolver = resolver
}

func (g *Gateway) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := extractBearer(r.Header.Get("Authorization"))
		if bearer == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		if g.tokenResolver != nil {
			accessCtx, found, err := g.tokenResolver.ResolveBearer(r.Context(), bearer)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			if found {
				ctx := context.WithValue(r.Context(), PrincipalContextKey, accessCtx.Principal)
				ctx = context.WithValue(ctx, AccessContextKey, accessCtx)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		claims, err := g.router.VerifyAndParseClaims(r.Context(), bearer)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		principal, err := g.router.ToPrincipal(claims)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), PrincipalContextKey, principal)
		ctx = context.WithValue(ctx, AccessContextKey, models.APIAccessContext{
			Principal:     principal,
			AuthMode:      "bearer_jwt",
			GrantedScopes: principal.Scopes,
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func PrincipalFromContext(ctx context.Context) (models.Principal, bool) {
	p, ok := ctx.Value(PrincipalContextKey).(models.Principal)
	return p, ok
}

func AccessContextFromContext(ctx context.Context) (models.APIAccessContext, bool) {
	ac, ok := ctx.Value(AccessContextKey).(models.APIAccessContext)
	return ac, ok
}

type tokenClaims struct {
	jwt.RegisteredClaims
	Email         string              `json:"email"`
	EmailVerified bool                `json:"email_verified"`
	Groups        []string            `json:"groups"`
	Scopes        []string            `json:"scopes"`
	Scope         string              `json:"scope"`
	HD            string              `json:"hd"`
	TeleportRoles []string            `json:"teleport_roles"`
	TeleportAttrs map[string][]string `json:"teleport_traits"`
}

func (g *Gateway) ProtectedResourceMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata := map[string]any{
			"resource":                 "syna-mcp",
			"authorization_servers":    collectIssuers(g.cfg),
			"scopes_supported":         g.cfg.API.Scopes,
			"bearer_methods_supported": []string{"header"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(metadata)
	}
}

func (g *Gateway) AuthorizationServerMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider, ok := preferredProvider(g.cfg)
		if !ok {
			http.Error(w, "no oauth provider configured", http.StatusNotFound)
			return
		}

		issuer := strings.TrimRight(provider.Issuer, "/")
		meta := map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              provider.JWKSURL,
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"code_challenge_methods_supported":      []string{"S256"},
		}

		authEndpoint, tokenEndpoint := defaultOAuthEndpoints(provider.Name, issuer)
		meta["authorization_endpoint"] = authEndpoint
		meta["token_endpoint"] = tokenEndpoint

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
	}
}

func collectIssuers(cfg config.Config) []string {
	out := make([]string, 0, len(cfg.OAuth.Providers)+1)
	for _, p := range cfg.OAuth.Providers {
		out = append(out, p.Issuer)
	}
	if cfg.Teleport.Enabled && cfg.Teleport.Issuer != "" {
		out = append(out, cfg.Teleport.Issuer)
	}
	return out
}

func preferredProvider(cfg config.Config) (config.ProviderConfig, bool) {
	for _, p := range cfg.OAuth.Providers {
		if strings.EqualFold(p.Name, "keycloak") {
			return p, true
		}
	}
	if len(cfg.OAuth.Providers) == 0 {
		return config.ProviderConfig{}, false
	}
	return cfg.OAuth.Providers[0], true
}

func defaultOAuthEndpoints(providerName, issuer string) (authEndpoint string, tokenEndpoint string) {
	if strings.EqualFold(providerName, "keycloak") {
		return fmt.Sprintf("%s/protocol/openid-connect/auth", issuer),
			fmt.Sprintf("%s/protocol/openid-connect/token", issuer)
	}
	return fmt.Sprintf("%s/oauth2/authorize", issuer),
		fmt.Sprintf("%s/oauth2/token", issuer)
}

func extractBearer(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}
