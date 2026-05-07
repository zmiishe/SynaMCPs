package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/zmiishe/synamcps/internal/knowledge"
	"github.com/zmiishe/synamcps/internal/models"
)

type KnowledgeHandler struct {
	service            *knowledge.Service
	allowPartialSource bool
}

func NewKnowledgeHandler(service *knowledge.Service, allowPartialSource bool) *KnowledgeHandler {
	return &KnowledgeHandler{service: service, allowPartialSource: allowPartialSource}
}

func (h *KnowledgeHandler) List(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	page := parsePageRequest(r)
	out, err := h.service.List(r.Context(), p, page)
	if err != nil {
		http.Error(w, err.Error(), statusFromErr(err))
		return
	}
	writeJSON(w, out, http.StatusOK)
}

func (h *KnowledgeHandler) Create(channel string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principalFromRequest(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req CreateKnowledgeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		doc, err := h.service.Save(r.Context(), p, knowledge.SaveInput{
			StorageID:  req.StorageID,
			Title:      req.Title,
			Text:       req.Text,
			MimeType:   req.MimeType,
			Visibility: req.Visibility,
			GroupIDs:   req.GroupIDs,
			Source:     req.Source,
			SourceURL:  req.SourceURL,
			Channel:    channel,
		})
		if err != nil {
			http.Error(w, err.Error(), statusFromErr(err))
			return
		}
		writeJSON(w, doc, http.StatusCreated)
	}
}

func (h *KnowledgeHandler) Get(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	docID := strings.TrimPrefix(r.URL.Path, "/api/knowledge/")
	doc, err := h.service.Get(r.Context(), p, docID)
	if err != nil {
		http.Error(w, err.Error(), statusFromErr(err))
		return
	}
	writeJSON(w, doc, http.StatusOK)
}

func (h *KnowledgeHandler) Delete(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	docID := strings.TrimPrefix(r.URL.Path, "/api/knowledge/")
	if err := h.service.Delete(r.Context(), p, docID); err != nil {
		http.Error(w, err.Error(), statusFromErr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *KnowledgeHandler) Search(w http.ResponseWriter, r *http.Request) {
	p, ok := principalFromRequest(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req SearchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hits, err := h.service.Search(r.Context(), p, models.SearchRequest{
		Query:   req.Query,
		TopK:    req.TopK,
		Filters: req.Filters,
	}, h.allowPartialSource)
	if err != nil {
		http.Error(w, err.Error(), statusFromErr(err))
		return
	}
	writeJSON(w, hits, http.StatusOK)
}

func parsePageRequest(r *http.Request) models.PageRequest {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("pageSize"))
	mode := q.Get("sourceUrlMode")
	if mode == "" {
		mode = "exact"
	}
	return models.PageRequest{
		Page:          page,
		PageSize:      size,
		StorageID:     q.Get("storageId"),
		Source:        q.Get("source"),
		SourceURL:     q.Get("sourceUrl"),
		SourceURLMode: mode,
	}
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func statusFromErr(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case strings.Contains(err.Error(), "forbidden"):
		return http.StatusForbidden
	case strings.Contains(err.Error(), "not found"):
		return http.StatusNotFound
	case strings.Contains(err.Error(), "invalid"):
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}
