package knowledge

import (
	"context"
	"errors"
	"strings"

	"github.com/zmiishe/synamcps/internal/access"
	"github.com/zmiishe/synamcps/internal/auth"
	"github.com/zmiishe/synamcps/internal/knowledge/ingest"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/policy"
	"github.com/zmiishe/synamcps/internal/storage/meta"
	"github.com/zmiishe/synamcps/internal/storage/vector"
)

type Service struct {
	catalog     meta.Catalog
	vectorStore vector.Store
	pipeline    *ingest.Pipeline
	access      *access.Service
	s3Bucket    string
}

func NewService(c meta.Catalog, v vector.Store, p *ingest.Pipeline) *Service {
	return &Service{catalog: c, vectorStore: v, pipeline: p}
}

func (s *Service) AttachAccess(accessService *access.Service, s3Bucket string) {
	s.access = accessService
	s.s3Bucket = s3Bucket
}

type SaveInput struct {
	StorageID  string            `json:"storageId"`
	Title      string            `json:"title"`
	Text       string            `json:"text"`
	MimeType   string            `json:"mimeType"`
	Visibility models.Visibility `json:"visibility"`
	GroupIDs   []string          `json:"groupIds"`
	Source     string            `json:"source,omitempty"`
	SourceURL  string            `json:"sourceUrl,omitempty"`
	Channel    string            `json:"-"`
}

func (s *Service) Save(ctx context.Context, p models.Principal, in SaveInput) (models.DocumentRecord, error) {
	if in.Visibility == "" {
		in.Visibility = models.VisibilityPersonal
	}
	if in.GroupIDs == nil {
		in.GroupIDs = []string{}
	}
	storageID := in.StorageID
	s3Prefix := ""
	if s.access != nil {
		if storageID == "" {
			_, st, err := s.access.EnsurePrincipal(ctx, p, s.s3Bucket)
			if err != nil {
				return models.DocumentRecord{}, err
			}
			storageID = st.ID
			s3Prefix = st.S3Prefix
		} else {
			st, ok, err := s.access.Store().GetStorage(ctx, storageID)
			if err != nil {
				return models.DocumentRecord{}, err
			}
			if !ok {
				return models.DocumentRecord{}, errors.New("storage not found")
			}
			s3Prefix = st.S3Prefix
		}
		if _, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), storageID, models.PermissionDocumentCreate); err != nil || !ok {
			if err != nil {
				return models.DocumentRecord{}, err
			}
			return models.DocumentRecord{}, errors.New("forbidden")
		}
	} else if !policy.CanWrite(p, in.Visibility, in.GroupIDs) {
		return models.DocumentRecord{}, errors.New("forbidden")
	}
	return s.pipeline.Save(ctx, ingest.SaveRequest{
		Principal:  p,
		StorageID:  storageID,
		S3Prefix:   s3Prefix,
		Title:      in.Title,
		Body:       in.Text,
		MimeType:   in.MimeType,
		Visibility: in.Visibility,
		GroupIDs:   in.GroupIDs,
		Source:     in.Source,
		SourceURL:  in.SourceURL,
		Channel:    in.Channel,
	})
}

func (s *Service) Get(ctx context.Context, p models.Principal, id string) (models.DocumentRecord, error) {
	doc, ok, err := s.catalog.Get(ctx, id)
	if err != nil {
		return models.DocumentRecord{}, err
	}
	if !ok {
		return models.DocumentRecord{}, errors.New("not found")
	}
	if s.access != nil {
		if _, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), doc.StorageID, models.PermissionDocumentRead); err != nil || !ok {
			if err != nil {
				return models.DocumentRecord{}, err
			}
			return models.DocumentRecord{}, errors.New("forbidden")
		}
	} else if !policy.CanRead(p, doc) {
		return models.DocumentRecord{}, errors.New("forbidden")
	}
	return doc, nil
}

func (s *Service) List(ctx context.Context, p models.Principal, page models.PageRequest) (models.PaginatedKnowledgeList, error) {
	if s.access != nil && page.StorageID != "" {
		if _, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), page.StorageID, models.PermissionDocumentRead); err != nil || !ok {
			if err != nil {
				return models.PaginatedKnowledgeList{}, err
			}
			return models.PaginatedKnowledgeList{}, errors.New("forbidden")
		}
	}
	all, err := s.catalog.List(ctx, page)
	if err != nil {
		return models.PaginatedKnowledgeList{}, err
	}
	filtered := make([]models.DocumentRecord, 0, len(all.Items))
	for _, d := range all.Items {
		if s.canReadDoc(ctx, p, d) {
			filtered = append(filtered, d)
		}
	}
	all.Items = filtered
	all.Total = int64(len(filtered))
	all.HasNext = int64(all.Page*all.PageSize) < all.Total
	return all, nil
}

func (s *Service) Delete(ctx context.Context, p models.Principal, id string) error {
	doc, ok, err := s.catalog.Get(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("not found")
	}
	if s.access != nil {
		if _, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), doc.StorageID, models.PermissionDocumentDelete); err != nil || !ok {
			if err != nil {
				return err
			}
			return errors.New("forbidden")
		}
	} else if !policy.CanDelete(p, doc) {
		return errors.New("forbidden")
	}
	if err := s.vectorStore.DeleteByDocID(ctx, id); err != nil {
		return err
	}
	return s.catalog.Delete(ctx, id)
}

func (s *Service) Search(ctx context.Context, p models.Principal, req models.SearchRequest, allowPartial bool) ([]models.SearchHit, error) {
	page := req.Filters
	if s.access != nil && page.StorageID != "" {
		if _, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), page.StorageID, models.PermissionSearchRead); err != nil || !ok {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("forbidden")
		}
	}

	if page.SourceURLMode == "" {
		page.SourceURLMode = "exact"
	}
	if page.SourceURLMode == "partial" && !allowPartial {
		page.SourceURLMode = "exact"
	}

	queryVec := []float32{0.1, 0.2}
	recs, err := s.vectorStore.Search(ctx, queryVec, req.TopK, page)
	if err != nil {
		return nil, err
	}

	hits := make([]models.SearchHit, 0, len(recs))
	for _, r := range recs {
		doc, ok, err := s.catalog.Get(ctx, r.Payload.DocID)
		if err != nil || !ok {
			continue
		}
		if !s.canReadDoc(ctx, p, doc) {
			continue
		}
		snippet := r.Text
		if req.Query != "" {
			snippet = extractSnippet(r.Text, req.Query)
		}
		hits = append(hits, models.SearchHit{
			DocID:      doc.DocID,
			Title:      doc.Title,
			Snippet:    snippet,
			Score:      1.0,
			Visibility: doc.Visibility,
			Source:     doc.Source,
			SourceURL:  doc.SourceURL,
		})
	}
	return hits, nil
}

func (s *Service) canReadDoc(ctx context.Context, p models.Principal, d models.DocumentRecord) bool {
	if s.access == nil {
		return policy.CanRead(p, d)
	}
	_, ok, err := s.access.CanAccessStorage(ctx, p, accessTokenFromContext(ctx), tokenScopesFromContext(ctx), d.StorageID, models.PermissionDocumentRead)
	return err == nil && ok
}

func accessTokenFromContext(ctx context.Context) *models.AccessToken {
	ac, ok := auth.AccessContextFromContext(ctx)
	if !ok {
		return nil
	}
	return ac.AccessToken
}

func tokenScopesFromContext(ctx context.Context) []models.AccessTokenStorage {
	ac, ok := auth.AccessContextFromContext(ctx)
	if !ok {
		return nil
	}
	return ac.AllowedStorage
}

func extractSnippet(text, query string) string {
	if query == "" {
		return text
	}
	lower := strings.ToLower(text)
	q := strings.ToLower(query)
	idx := strings.Index(lower, q)
	if idx < 0 {
		if len(text) > 180 {
			return text[:180]
		}
		return text
	}
	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(query) + 100
	if end > len(text) {
		end = len(text)
	}
	return text[start:end]
}
