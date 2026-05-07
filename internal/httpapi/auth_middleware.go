package httpapi

import (
	"context"
	"net/http"

	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/session"
)

type AuthResolver struct {
	gateway  *auth.Gateway
	sessions *session.Store
}

func NewAuthResolver(gateway *auth.Gateway, sessions *session.Store) *AuthResolver {
	return &AuthResolver{gateway: gateway, sessions: sessions}
}

func (a *AuthResolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session_id"); err == nil {
			if ws, ok := a.sessions.GetWebSession(c.Value); ok {
				if isMutatingMethod(r.Method) && r.Header.Get("X-CSRF-Token") != ws.CSRFToken {
					http.Error(w, "invalid csrf token", http.StatusForbidden)
					return
				}
				ctx := context.WithValue(r.Context(), auth.PrincipalContextKey, ws.Principal)
				ctx = context.WithValue(ctx, auth.AccessContextKey, models.APIAccessContext{
					Principal:     ws.Principal,
					AuthMode:      "web_session",
					GrantedScopes: ws.Principal.Scopes,
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		a.gateway.Middleware(next).ServeHTTP(w, r)
	})
}

func principalFromRequest(r *http.Request) (models.Principal, bool) {
	return auth.PrincipalFromContext(r.Context())
}

func isMutatingMethod(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}
