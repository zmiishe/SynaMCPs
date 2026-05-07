package httpapi

import "github.com/zmiishe/synamcps/internal/models"

type CreateKnowledgeRequest struct {
	StorageID  string            `json:"storageId"`
	Title      string            `json:"title"`
	Text       string            `json:"text"`
	MimeType   string            `json:"mimeType"`
	Visibility models.Visibility `json:"visibility"`
	GroupIDs   []string          `json:"groupIds"`
	Source     string            `json:"source,omitempty"`
	SourceURL  string            `json:"sourceUrl,omitempty"`
}

type SearchRequest struct {
	Query   string            `json:"query"`
	TopK    int               `json:"topK"`
	Filters models.PageRequest `json:"filters"`
}
