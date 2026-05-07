package httpapi

import (
	"net/http"

	"github.com/zmiishe/synamcps/internal/access"
	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/knowledge"
	"github.com/zmiishe/synamcps/internal/session"
	"github.com/zmiishe/synamcps/internal/usage"
)

func NewRouter(gateway *auth.Gateway, sessions *session.Store, service *knowledge.Service, allowPartial bool) http.Handler {
	return NewRouterWithAdmin(gateway, sessions, service, nil, nil, "", allowPartial)
}

func NewRouterWithAdmin(gateway *auth.Gateway, sessions *session.Store, service *knowledge.Service, accessService *access.Service, usageService *usage.Service, s3Bucket string, allowPartial bool) http.Handler {
	mux := http.NewServeMux()
	authResolver := NewAuthResolver(gateway, sessions)
	handler := NewKnowledgeHandler(service, allowPartial)

	if accessService != nil {
		admin := NewAdminHandler(accessService, usageService, s3Bucket)
		mux.Handle("/api/admin/", authResolver.Middleware(admin))
	}
	mux.Handle("GET /api/knowledge", authResolver.Middleware(http.HandlerFunc(handler.List)))
	mux.Handle("POST /api/knowledge", authResolver.Middleware(http.HandlerFunc(handler.Create("api"))))
	mux.Handle("POST /api/admin/knowledge", authResolver.Middleware(http.HandlerFunc(handler.Create("admin"))))
	mux.Handle("POST /api/knowledge/search", authResolver.Middleware(http.HandlerFunc(handler.Search)))
	mux.Handle("GET /api/knowledge/", authResolver.Middleware(http.HandlerFunc(handler.Get)))
	mux.Handle("DELETE /api/knowledge/", authResolver.Middleware(http.HandlerFunc(handler.Delete)))

	return mux
}
