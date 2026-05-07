package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/zmiishe/synamcps/internal/access"
	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/knowledge"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/session"
	"github.com/zmiishe/synamcps/internal/usage"
)

type Server struct {
	sessions *session.Store
	knowledge *knowledge.Service
	access    *access.Service
	usage     *usage.Service
}

func NewServer(sessions *session.Store, knowledgeService *knowledge.Service) *Server {
	return &Server{sessions: sessions, knowledge: knowledgeService}
}

func (s *Server) AttachAccess(accessService *access.Service) {
	s.access = accessService
}

func (s *Server) AttachUsage(usageService *usage.Service) {
	s.usage = usageService
}

func (s *Server) HandleInitialize(w http.ResponseWriter, p models.Principal) {
	sess := s.sessions.CreateMCPSession(p, 12*time.Hour)
	w.Header().Set("Mcp-Session-Id", sess.SessionID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      "init",
		"result": initializeResult("2024-11-05", sess.SessionID),
	})
}

func (s *Server) HandleJSONRPC(ctx context.Context, p models.Principal, request map[string]any) (map[string]any, error) {
	start := time.Now()
	method, _ := request["method"].(string)
	params, _ := request["params"].(map[string]any)
	id := request["id"]
	storageID := asString(params["storageId"])
	accessCtx, _ := auth.AccessContextFromContext(ctx)
	status := "ok"
	defer func() {
		if s.usage != nil {
			s.usage.Record(ctx, models.UsageEvent{
				TokenID:        accessCtx.TokenID,
				UserSubjectKey: models.SubjectKeyForPrincipal(p),
				StorageID:      storageID,
				Tool:           method,
				Operation:      operationForMethod(method),
				Status:         status,
				LatencyMS:      time.Since(start).Milliseconds(),
			})
		}
	}()

	if accessCtx.AccessToken != nil && s.usage != nil {
		ok, err := s.usage.Allow(ctx, *accessCtx.AccessToken, storageID)
		if err != nil {
			status = "error"
			return nil, err
		}
		if !ok {
			status = "rate_limited"
			return nil, errors.New("rate limit exceeded")
		}
	}

	switch method {
	case "initialize":
		sess := s.sessions.CreateMCPSession(p, 12*time.Hour)
		protocolVersion := asString(params["protocolVersion"])
		if protocolVersion == "" {
			protocolVersion = "2024-11-05"
		}
		return map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"result":  initializeResult(protocolVersion, sess.SessionID),
		}, nil
	case "notifications/initialized":
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]any{}}, nil
	case "tools/list":
		result, err := s.handleToolsList(ctx, p, accessCtx)
		if err != nil {
			status = "error"
			return nil, err
		}
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}, nil
	case "tools/call":
		name := asString(params["name"])
		name = methodForToolName(name)
		arguments, _ := params["arguments"].(map[string]any)
		if arguments == nil {
			arguments = map[string]any{}
		}
		callReq := map[string]any{
			"jsonrpc": "2.0",
			"id":      id,
			"method":  name,
			"params":  arguments,
		}
		resp, err := s.HandleJSONRPC(ctx, p, callReq)
		if err != nil {
			status = statusFromError(err)
			return nil, err
		}
		return toolCallResponse(id, resp["result"]), nil
	case "knowledge.save":
		in := knowledge.SaveInput{
			StorageID:  storageID,
			Title:      asString(params["title"]),
			Text:       asString(params["text"]),
			MimeType:   asString(params["mimeType"]),
			Visibility: models.Visibility(asString(params["visibility"])),
			GroupIDs:   asStringSlice(params["groupIds"]),
			Source:     asString(params["source"]),
			SourceURL:  asString(params["sourceUrl"]),
			Channel:    "mcp",
		}
		doc, err := s.knowledge.Save(ctx, p, in)
		if err != nil {
			status = statusFromError(err)
			return nil, err
		}
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": doc}, nil
	case "knowledge.get":
		doc, err := s.knowledge.Get(ctx, p, asString(params["docId"]))
		if err != nil {
			status = statusFromError(err)
			return nil, err
		}
		storageID = doc.StorageID
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": doc}, nil
	case "knowledge.delete":
		if err := s.knowledge.Delete(ctx, p, asString(params["docId"])); err != nil {
			status = statusFromError(err)
			return nil, err
		}
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": map[string]string{"status": "deleted"}}, nil
	case "knowledge.search":
		req := models.SearchRequest{
			Query: asString(params["query"]),
			TopK:  asInt(params["topK"]),
			Filters: models.PageRequest{
				StorageID:     storageID,
				Source:        asString(params["source"]),
				SourceURL:     asString(params["sourceUrl"]),
				SourceURLMode: asString(params["sourceUrlMode"]),
			},
		}
		hits, err := s.knowledge.Search(ctx, p, req, true)
		if err != nil {
			status = statusFromError(err)
			return nil, err
		}
		return map[string]any{"jsonrpc": "2.0", "id": id, "result": hits}, nil
	default:
		status = "error"
		return nil, errors.New("unknown method")
	}
}

func toolCallResponse(id any, result any) map[string]any {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		raw, _ = json.Marshal(result)
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result": map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": string(raw),
				},
			},
		},
	}
}

func initializeResult(protocolVersion, sessionID string) map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "syna-knowledge-mcp",
			"version": "0.1.0",
		},
		"sessionId": sessionID,
	}
}

func (s *Server) handleToolsList(ctx context.Context, p models.Principal, accessCtx models.APIAccessContext) (map[string]any, error) {
	if s.access == nil {
		return map[string]any{"tools": defaultTools(nil, true)}, nil
	}
	storages, effective, err := s.access.AvailableStorages(ctx, p, accessCtx.AccessToken, accessCtx.AllowedStorage)
	if err != nil {
		return nil, err
	}
	storageEnums := make([]string, 0, len(storages))
	writeAllowed := false
	for _, st := range storages {
		storageEnums = append(storageEnums, st.ID)
		for _, perm := range effective[st.ID].Permissions {
			if perm == models.PermissionDocumentCreate {
				writeAllowed = true
			}
		}
	}
	return map[string]any{
		"tools":    defaultTools(storageEnums, writeAllowed),
		"storages": storages,
	}, nil
}

func defaultTools(storageEnums []string, writeAllowed bool) []map[string]any {
	storageProperty := map[string]any{"type": "string", "description": "Storage ID"}
	if len(storageEnums) > 0 {
		storageProperty["enum"] = storageEnums
	}
	tools := []map[string]any{
		toolDescriptor("knowledge_search", "Search knowledge in an allowed storage", storageProperty, map[string]any{"query": map[string]any{"type": "string"}, "topK": map[string]any{"type": "integer"}}),
		toolDescriptor("knowledge_get", "Get a document by id", storageProperty, map[string]any{"docId": map[string]any{"type": "string"}}),
	}
	if writeAllowed {
		tools = append(tools,
			toolDescriptor("knowledge_save", "Save knowledge into an allowed storage", storageProperty, map[string]any{"title": map[string]any{"type": "string"}, "text": map[string]any{"type": "string"}, "mimeType": map[string]any{"type": "string"}}),
			toolDescriptor("knowledge_delete", "Delete a document from an allowed storage", storageProperty, map[string]any{"docId": map[string]any{"type": "string"}}),
		)
	}
	return tools
}

func methodForToolName(name string) string {
	switch name {
	case "knowledge_search":
		return "knowledge.search"
	case "knowledge_get":
		return "knowledge.get"
	case "knowledge_save":
		return "knowledge.save"
	case "knowledge_delete":
		return "knowledge.delete"
	default:
		return name
	}
}

func toolDescriptor(name, description string, storageProperty map[string]any, extra map[string]any) map[string]any {
	props := map[string]any{"storageId": storageProperty}
	required := []string{"storageId"}
	for k, v := range extra {
		props[k] = v
		required = append(required, k)
	}
	return map[string]any{
		"name":        name,
		"description": description,
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": props,
			"required":   required,
		},
	}
}

func operationForMethod(method string) string {
	switch method {
	case "knowledge.save":
		return "write"
	case "knowledge.delete":
		return "delete"
	case "tools/list":
		return "tools_list"
	case "initialize":
		return "initialize"
	default:
		return "read"
	}
}

func statusFromError(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.Canceled) {
		return "error"
	}
	msg := err.Error()
	if msg == "forbidden" {
		return "forbidden"
	}
	return "error"
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	default:
		return 0
	}
}
