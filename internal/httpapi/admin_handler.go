package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/zmiishe/synamcps/internal/access"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/usage"
)

type AdminHandler struct {
	access *access.Service
	usage  *usage.Service
	s3Bucket string
}

func NewAdminHandler(accessService *access.Service, usageService *usage.Service, s3Bucket string) *AdminHandler {
	return &AdminHandler{access: accessService, usage: usageService, s3Bucket: s3Bucket}
}

func (h *AdminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if h.access != nil {
		_, _, _ = h.access.EnsurePrincipal(r.Context(), p, h.s3Bucket)
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin")
	switch {
	case r.Method == http.MethodGet && path == "/me":
		h.currentUser(w, r, p)
	case r.Method == http.MethodGet && path == "/users":
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.listUsers(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/users/"):
		h.getUser(w, r, path, p)
	case r.Method == http.MethodPost && path == "/users":
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.createUser(w, r)
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/users/"):
		h.updateUser(w, r, path, p)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/password"):
		h.changeUserPassword(w, r, path, p)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/users/"):
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.deleteUser(w, r, path)
	case r.Method == http.MethodGet && path == "/groups":
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.listGroups(w, r)
	case r.Method == http.MethodPost && path == "/groups":
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.createGroup(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/groups/") && !strings.Contains(path, "/members/"):
		if !isPlatformAdmin(p) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.deleteGroup(w, r, path)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/members"):
		h.listGroupMembers(w, r, path)
	case r.Method == http.MethodPut && strings.Contains(path, "/members/"):
		h.addGroupMember(w, r, path)
	case r.Method == http.MethodDelete && strings.Contains(path, "/members/"):
		h.removeGroupMember(w, r, path)
	case r.Method == http.MethodGet && path == "/storages":
		h.listStorages(w, r, p)
	case r.Method == http.MethodPost && path == "/storages":
		h.createStorage(w, r, p)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/storages/") && !strings.Contains(path, "/acl"):
		h.deleteStorage(w, r, path)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/acl"):
		h.storageACL(w, r, path)
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/acl"):
		h.upsertACL(w, r, path, p)
	case r.Method == http.MethodGet && path == "/tokens":
		h.listTokens(w, r, p)
	case r.Method == http.MethodPost && path == "/tokens":
		h.createToken(w, r, p)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/tokens/") && !strings.Contains(path, "/connect-options"):
		h.deleteToken(w, r, path)
	case r.Method == http.MethodPatch && strings.HasSuffix(path, "/rate-limit"):
		h.patchRateLimit(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/revoke"):
		h.revokeToken(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/rotate"):
		h.rotateToken(w, r, path, p)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/connect-options"):
		h.connectOptions(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/connect-options"):
		h.connectOptions(w, r, path)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/usage/series"):
		h.usageSeries(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/usage/summary"):
		h.usageSummary(w, r)
	case r.Method == http.MethodGet && strings.Contains(path, "/usage"):
		h.usageSeries(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *AdminHandler) currentUser(w http.ResponseWriter, r *http.Request, p models.Principal) {
	user, ok, err := h.access.Store().UserBySubjectKey(r.Context(), models.SubjectKeyForPrincipal(p))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, user, http.StatusOK)
}

func (h *AdminHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.access.Store().ListUsers(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, users, http.StatusOK)
}

func (h *AdminHandler) getUser(w http.ResponseWriter, r *http.Request, path string, p models.Principal) {
	user, ok, err := h.access.Store().GetUser(r.Context(), idFromPath(path, 1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !canEditUser(p, user) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, user, http.StatusOK)
}

func (h *AdminHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var req models.User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user, err := h.access.Store().CreateUser(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, user, http.StatusCreated)
}

func (h *AdminHandler) updateUser(w http.ResponseWriter, r *http.Request, path string, p models.Principal) {
	userID := idFromPath(path, 1)
	existing, ok, err := h.access.Store().GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !canEditUser(p, existing) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req models.User
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !isPlatformAdmin(p) {
		req.Status = ""
	}
	updated, err := h.access.Store().UpdateUser(r.Context(), userID, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, updated, http.StatusOK)
}

func (h *AdminHandler) changeUserPassword(w http.ResponseWriter, r *http.Request, path string, p models.Principal) {
	userID := idFromPath(path, 1)
	existing, ok, err := h.access.Store().GetUser(r.Context(), userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !canEditUser(p, existing) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(req.NewPassword) < 8 {
		http.Error(w, "new password must be at least 8 characters", http.StatusUnprocessableEntity)
		return
	}
	if !isPlatformAdmin(p) {
		hasPassword, err := h.access.Store().HasUserPassword(r.Context(), userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if hasPassword {
			ok, err := h.access.Store().CheckUserPassword(r.Context(), userID, req.CurrentPassword)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if !ok {
				http.Error(w, "current password is invalid", http.StatusForbidden)
				return
			}
		}
	}
	if err := h.access.Store().SetUserPassword(r.Context(), userID, req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "password_updated"}, http.StatusOK)
}

func (h *AdminHandler) deleteUser(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.access.Store().DeleteUser(r.Context(), idFromPath(path, 1)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := h.access.Store().ListGroups(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, groups, http.StatusOK)
}

func (h *AdminHandler) createGroup(w http.ResponseWriter, r *http.Request) {
	var req models.Group
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	group, err := h.access.Store().CreateGroup(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, group, http.StatusCreated)
}

func (h *AdminHandler) deleteGroup(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.access.Store().DeleteGroup(r.Context(), idFromPath(path, 1)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) listGroupMembers(w http.ResponseWriter, r *http.Request, path string) {
	members, err := h.access.Store().ListGroupMembers(r.Context(), idFromPath(path, 1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, members, http.StatusOK)
}

func (h *AdminHandler) addGroupMember(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "invalid member path", http.StatusBadRequest)
		return
	}
	if err := h.access.Store().AddGroupMember(r.Context(), parts[1], parts[3], "internal"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) removeGroupMember(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 4 {
		http.Error(w, "invalid member path", http.StatusBadRequest)
		return
	}
	if err := h.access.Store().RemoveGroupMember(r.Context(), parts[1], parts[3]); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) listStorages(w http.ResponseWriter, r *http.Request, p models.Principal) {
	storages, _, err := h.access.AvailableStorages(r.Context(), p, nil, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, storages, http.StatusOK)
}

func (h *AdminHandler) createStorage(w http.ResponseWriter, r *http.Request, p models.Principal) {
	var req models.Storage
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.OwnerSubjectKey == "" {
		req.OwnerSubjectKey = models.SubjectKeyForPrincipal(p)
	}
	if req.S3Bucket == "" {
		req.S3Bucket = h.s3Bucket
	}
	st, err := h.access.Store().CreateStorage(r.Context(), req, models.SubjectKeyForPrincipal(p))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, st, http.StatusCreated)
}

func (h *AdminHandler) deleteStorage(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.access.Store().DeleteStorage(r.Context(), idFromPath(path, 1)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) storageACL(w http.ResponseWriter, r *http.Request, path string) {
	storageID := storageIDFromACLPath(path)
	acl, err := h.access.Store().ACLForStorage(r.Context(), storageID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, acl, http.StatusOK)
}

func (h *AdminHandler) upsertACL(w http.ResponseWriter, r *http.Request, path string, p models.Principal) {
	var req models.ACLBinding
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.StorageID = storageIDFromACLPath(path)
	if req.GrantedBy == "" {
		req.GrantedBy = models.SubjectKeyForPrincipal(p)
	}
	b, err := h.access.Store().UpsertACL(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, b, http.StatusOK)
}

func (h *AdminHandler) listTokens(w http.ResponseWriter, r *http.Request, p models.Principal) {
	tokens, err := h.access.Store().ListTokens(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !isPlatformAdmin(p) {
		filtered := tokens[:0]
		subject := models.SubjectKeyForPrincipal(p)
		for _, token := range tokens {
			if token.OwnerSubjectKey == subject {
				filtered = append(filtered, token)
			}
		}
		tokens = filtered
	}
	writeJSON(w, tokens, http.StatusOK)
}

type createTokenRequest struct {
	Name       string                 `json:"name"`
	Mode       models.AccessMode      `json:"mode"`
	StorageIDs []string               `json:"storageIds"`
	RateLimit  models.RateLimitPolicy `json:"rateLimit"`
	ExpiresAt  *time.Time             `json:"expiresAt,omitempty"`
}

func (h *AdminHandler) createToken(w http.ResponseWriter, r *http.Request, p models.Principal) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Mode == "" {
		req.Mode = models.AccessModeRead
	}
	if len(req.StorageIDs) == 0 {
		_, st, err := h.access.EnsurePrincipal(r.Context(), p, h.s3Bucket)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.StorageIDs = []string{st.ID}
	}
	scopes := make([]models.AccessTokenStorage, 0, len(req.StorageIDs))
	for _, id := range req.StorageIDs {
		scopes = append(scopes, models.AccessTokenStorage{StorageID: id, MaxMode: req.Mode})
	}
	token, raw, err := h.access.Store().CreateToken(r.Context(), access.CreateTokenInput{
		OwnerSubjectKey: models.SubjectKeyForPrincipal(p),
		Name:            req.Name,
		Mode:            req.Mode,
		StorageScopes:   scopes,
		RateLimit:       req.RateLimit,
		ExpiresAt:       req.ExpiresAt,
		CreatedBy:       models.SubjectKeyForPrincipal(p),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"token": token, "rawToken": raw}, http.StatusCreated)
}

func (h *AdminHandler) deleteToken(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.access.Store().DeleteToken(r.Context(), idFromPath(path, 1)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) patchRateLimit(w http.ResponseWriter, r *http.Request, path string) {
	var req models.RateLimitPolicy
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.access.Store().UpdateTokenRateLimit(r.Context(), tokenIDFromPath(path), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "updated", "tokenId": tokenIDFromPath(path)}, http.StatusOK)
}

func (h *AdminHandler) revokeToken(w http.ResponseWriter, r *http.Request, path string) {
	if err := h.access.Store().RevokeToken(r.Context(), tokenIDFromPath(path)); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminHandler) rotateToken(w http.ResponseWriter, r *http.Request, path string, p models.Principal) {
	oldID := tokenIDFromPath(path)
	scopes, _ := h.access.Store().TokenStorages(r.Context(), oldID)
	_ = h.access.Store().RevokeToken(r.Context(), oldID)
	token, raw, err := h.access.Store().CreateToken(r.Context(), access.CreateTokenInput{
		OwnerSubjectKey: models.SubjectKeyForPrincipal(p),
		Name:            "Rotated MCP token",
		Mode:            models.AccessModeRead,
		StorageScopes:   scopes,
		CreatedBy:       models.SubjectKeyForPrincipal(p),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"token": token, "rawToken": raw}, http.StatusCreated)
}

func (h *AdminHandler) connectOptions(w http.ResponseWriter, r *http.Request, path string) {
	client := models.MCPClientKind(r.URL.Query().Get("client"))
	raw := ""
	if r.Method == http.MethodPost {
		var req struct {
			Client   models.MCPClientKind `json:"client"`
			RawToken string               `json:"rawToken"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Client != "" {
			client = req.Client
		}
		raw = req.RawToken
	}
	if client == "" {
		client = models.MCPClientGeneric
	}
	if raw == "" {
		raw = "<rotate-or-create-token-to-reveal>"
	}
	cfg := buildConnectConfig(client, serverBaseURL(r), raw)
	writeJSON(w, cfg, http.StatusOK)
}

func (h *AdminHandler) usageSeries(w http.ResponseWriter, r *http.Request) {
	if h.usage == nil {
		writeJSON(w, []models.UsageSeries{}, http.StatusOK)
		return
	}
	from, to := parseTimeRange(r)
	out := h.usage.Series(r.Context(), r.URL.Query().Get("metric"), r.URL.Query().Get("groupBy"), from, to)
	writeJSON(w, out, http.StatusOK)
}

func (h *AdminHandler) usageSummary(w http.ResponseWriter, r *http.Request) {
	if h.usage == nil {
		writeJSON(w, map[string]any{}, http.StatusOK)
		return
	}
	from, to := parseTimeRange(r)
	writeJSON(w, h.usage.Summary(r.Context(), from, to), http.StatusOK)
}

func storageIDFromACLPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func tokenIDFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func idFromPath(path string, idx int) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > idx {
		return parts[idx]
	}
	return ""
}

func parseTimeRange(r *http.Request) (time.Time, time.Time) {
	from, _ := time.Parse(time.RFC3339, r.URL.Query().Get("from"))
	to, _ := time.Parse(time.RFC3339, r.URL.Query().Get("to"))
	return from, to
}

func serverBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

func buildConnectConfig(client models.MCPClientKind, baseURL, rawToken string) models.TokenConnectConfig {
	body := fmt.Sprintf(`{
  "mcpServers": {
    "syna-knowledge": {
      "url": "%s/mcp",
      "headers": {
        "Authorization": "Bearer %s"
      }
    }
  }
}`, baseURL, rawToken)
	file := "mcp.json"
	instructions := []string{"Add the MCP server configuration.", "Restart MCP tools.", "Run tools/list and verify that only allowed storage tools are visible."}
	switch client {
	case models.MCPClientCursor:
		file = "mcp.json"
		instructions = []string{"Open Cursor settings.", "Add this MCP server configuration.", "Restart MCP tools and verify allowed storage tools."}
	case models.MCPClientClaudeDesktop:
		file = "claude_desktop_config.json"
		instructions = []string{"Open Claude Desktop config.", "Add the mcpServers entry.", "Restart Claude Desktop."}
	case models.MCPClientClaudeCode:
		file = ".mcp.json"
		instructions = []string{"Create or update .mcp.json.", "Start Claude Code in the project.", "Verify tools/list output."}
	}
	return models.TokenConnectConfig{
		Client:         client,
		ServerName:     "syna-knowledge",
		Transport:      "streamable_http",
		ConfigFileName: file,
		ConfigBody:     body,
		Instructions:   instructions,
	}
}

func isPlatformAdmin(p models.Principal) bool {
	for _, scope := range p.Scopes {
		if scope == "platform_admin" || scope == "admin" {
			return true
		}
	}
	return false
}

func canEditUser(p models.Principal, user models.User) bool {
	return isPlatformAdmin(p) || user.SubjectKey == models.SubjectKeyForPrincipal(p)
}
