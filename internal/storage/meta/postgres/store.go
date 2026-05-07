package postgres

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zmiishe/synamcps/internal/models"
)

type Store struct {
	mu    sync.RWMutex
	docs  map[string]models.DocumentRecord
	pool  *pgxpool.Pool
	useDB bool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return NewInMemory(), nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create pg pool: %w", err)
	}
	s := &Store{
		docs:  map[string]models.DocumentRecord{},
		pool:  pool,
		useDB: true,
	}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func NewInMemory() *Store {
	return &Store{docs: map[string]models.DocumentRecord{}}
}

func (s *Store) migrate(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	ddl := `
CREATE TABLE IF NOT EXISTS knowledge_documents (
  doc_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  visibility TEXT NOT NULL,
  group_ids TEXT[] NOT NULL DEFAULT '{}',
  title TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  source TEXT NOT NULL,
  source_url TEXT,
  source_hash TEXT,
  s3_key TEXT,
  summary_chunk_id TEXT,
  status TEXT NOT NULL,
  body TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_docs_source ON knowledge_documents(source);
CREATE INDEX IF NOT EXISTS idx_knowledge_docs_updated ON knowledge_documents(updated_at DESC);
ALTER TABLE knowledge_documents ADD COLUMN IF NOT EXISTS storage_id TEXT NOT NULL DEFAULT 'legacy';
CREATE INDEX IF NOT EXISTS idx_knowledge_docs_storage ON knowledge_documents(storage_id);
`
	_, err := s.pool.Exec(ctx, ddl)
	return err
}

func (s *Store) Ping(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	return s.pool.Ping(ctx)
}

func (s *Store) Save(_ context.Context, doc models.DocumentRecord) error {
	doc.StorageID = defaultStorageID(doc.StorageID)
	if doc.GroupIDs == nil {
		doc.GroupIDs = []string{}
	}
	if s.useDB {
		return s.saveDB(context.Background(), doc)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[doc.DocID] = doc
	return nil
}

func (s *Store) Get(_ context.Context, docID string) (models.DocumentRecord, bool, error) {
	if s.useDB {
		return s.getDB(context.Background(), docID)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.docs[docID]
	return v, ok, nil
}

func (s *Store) Delete(_ context.Context, docID string) error {
	if s.useDB {
		_, err := s.pool.Exec(context.Background(), `DELETE FROM knowledge_documents WHERE doc_id=$1`, docID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, docID)
	return nil
}

func (s *Store) List(_ context.Context, page models.PageRequest) (models.PaginatedKnowledgeList, error) {
	if s.useDB {
		return s.listDB(context.Background(), page)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := make([]models.DocumentRecord, 0, len(s.docs))
	for _, d := range s.docs {
		if page.StorageID != "" && d.StorageID != page.StorageID {
			continue
		}
		if page.Source != "" && d.Source != page.Source {
			continue
		}
		if page.SourceURL != "" {
			if page.SourceURLMode == "partial" {
				if !contains(d.SourceURL, page.SourceURL) {
					continue
				}
			} else if d.SourceURL != page.SourceURL {
				continue
			}
		}
		items = append(items, d)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt.After(items[j].UpdatedAt) })

	ps := page.PageSize
	if ps <= 0 {
		ps = 20
	}
	p := page.Page
	if p <= 0 {
		p = 1
	}
	start := (p - 1) * ps
	if start > len(items) {
		start = len(items)
	}
	end := start + ps
	if end > len(items) {
		end = len(items)
	}

	return models.PaginatedKnowledgeList{
		Items:    items[start:end],
		Page:     p,
		PageSize: ps,
		Total:    int64(len(items)),
		HasNext:  end < len(items),
	}, nil
}

func (s *Store) All(_ context.Context) ([]models.DocumentRecord, error) {
	if s.useDB {
		rows, err := s.pool.Query(context.Background(), `SELECT doc_id, storage_id, owner_id, visibility, group_ids, title, mime_type, source, COALESCE(source_url,''), COALESCE(source_hash,''), COALESCE(s3_key,''), COALESCE(summary_chunk_id,''), status, COALESCE(body,''), created_at, updated_at FROM knowledge_documents`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []models.DocumentRecord{}
		for rows.Next() {
			var doc models.DocumentRecord
			if err := rows.Scan(&doc.DocID, &doc.StorageID, &doc.OwnerID, &doc.Visibility, &doc.GroupIDs, &doc.Title, &doc.MimeType, &doc.Source, &doc.SourceURL, &doc.SourceHash, &doc.S3Key, &doc.SummaryChunkID, &doc.Status, &doc.Body, &doc.CreatedAt, &doc.UpdatedAt); err != nil {
				return nil, err
			}
			out = append(out, doc)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.DocumentRecord, 0, len(s.docs))
	for _, d := range s.docs {
		out = append(out, d)
	}
	return out, nil
}

func contains(haystack, needle string) bool {
	return needle == "" || (len(haystack) >= len(needle) && (haystack == needle || (len(haystack) > len(needle) && indexOf(haystack, needle) >= 0)))
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func defaultStorageID(id string) string {
	if id == "" {
		return "legacy"
	}
	return id
}

func (s *Store) saveDB(ctx context.Context, doc models.DocumentRecord) error {
	if doc.GroupIDs == nil {
		doc.GroupIDs = []string{}
	}
	if doc.CreatedAt.IsZero() {
		doc.CreatedAt = time.Now().UTC()
	}
	if doc.UpdatedAt.IsZero() {
		doc.UpdatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `
INSERT INTO knowledge_documents (
  doc_id, storage_id, owner_id, visibility, group_ids, title, mime_type, source, source_url,
  source_hash, s3_key, summary_chunk_id, status, body, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (doc_id) DO UPDATE SET
  storage_id=EXCLUDED.storage_id,
  owner_id=EXCLUDED.owner_id,
  visibility=EXCLUDED.visibility,
  group_ids=EXCLUDED.group_ids,
  title=EXCLUDED.title,
  mime_type=EXCLUDED.mime_type,
  source=EXCLUDED.source,
  source_url=EXCLUDED.source_url,
  source_hash=EXCLUDED.source_hash,
  s3_key=EXCLUDED.s3_key,
  summary_chunk_id=EXCLUDED.summary_chunk_id,
  status=EXCLUDED.status,
  body=EXCLUDED.body,
  updated_at=EXCLUDED.updated_at`,
		doc.DocID, defaultStorageID(doc.StorageID), doc.OwnerID, string(doc.Visibility), doc.GroupIDs, doc.Title, doc.MimeType, doc.Source, doc.SourceURL,
		doc.SourceHash, doc.S3Key, doc.SummaryChunkID, doc.Status, doc.Body, doc.CreatedAt, doc.UpdatedAt)
	return err
}

func (s *Store) getDB(ctx context.Context, docID string) (models.DocumentRecord, bool, error) {
	row := s.pool.QueryRow(ctx, `
SELECT doc_id, storage_id, owner_id, visibility, group_ids, title, mime_type, source, COALESCE(source_url,''), COALESCE(source_hash,''), COALESCE(s3_key,''), COALESCE(summary_chunk_id,''), status, COALESCE(body,''), created_at, updated_at
FROM knowledge_documents WHERE doc_id=$1`, docID)
	var doc models.DocumentRecord
	err := row.Scan(&doc.DocID, &doc.StorageID, &doc.OwnerID, &doc.Visibility, &doc.GroupIDs, &doc.Title, &doc.MimeType, &doc.Source, &doc.SourceURL, &doc.SourceHash, &doc.S3Key, &doc.SummaryChunkID, &doc.Status, &doc.Body, &doc.CreatedAt, &doc.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return models.DocumentRecord{}, false, nil
		}
		return models.DocumentRecord{}, false, err
	}
	return doc, true, nil
}

func (s *Store) listDB(ctx context.Context, page models.PageRequest) (models.PaginatedKnowledgeList, error) {
	ps := page.PageSize
	if ps <= 0 {
		ps = 20
	}
	p := page.Page
	if p <= 0 {
		p = 1
	}
	offset := (p - 1) * ps

	where := "TRUE"
	args := []any{}
	argn := 1
	if page.Source != "" {
		where += fmt.Sprintf(" AND source=$%d", argn)
		args = append(args, page.Source)
		argn++
	}
	if page.SourceURL != "" {
		if page.SourceURLMode == "partial" {
			where += fmt.Sprintf(" AND source_url ILIKE $%d", argn)
			args = append(args, "%"+page.SourceURL+"%")
		} else {
			where += fmt.Sprintf(" AND source_url=$%d", argn)
			args = append(args, page.SourceURL)
		}
		argn++
	}
	if page.StorageID != "" {
		where += fmt.Sprintf(" AND storage_id=$%d", argn)
		args = append(args, page.StorageID)
		argn++
	}

	countSQL := "SELECT count(1) FROM knowledge_documents WHERE " + where
	var total int64
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return models.PaginatedKnowledgeList{}, err
	}

	query := fmt.Sprintf(`
SELECT doc_id, storage_id, owner_id, visibility, group_ids, title, mime_type, source, COALESCE(source_url,''), COALESCE(source_hash,''), COALESCE(s3_key,''), COALESCE(summary_chunk_id,''), status, COALESCE(body,''), created_at, updated_at
FROM knowledge_documents
WHERE %s
ORDER BY updated_at DESC
LIMIT $%d OFFSET $%d`, where, argn, argn+1)
	args = append(args, ps, offset)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return models.PaginatedKnowledgeList{}, err
	}
	defer rows.Close()

	out := []models.DocumentRecord{}
	for rows.Next() {
		var doc models.DocumentRecord
		if err := rows.Scan(&doc.DocID, &doc.StorageID, &doc.OwnerID, &doc.Visibility, &doc.GroupIDs, &doc.Title, &doc.MimeType, &doc.Source, &doc.SourceURL, &doc.SourceHash, &doc.S3Key, &doc.SummaryChunkID, &doc.Status, &doc.Body, &doc.CreatedAt, &doc.UpdatedAt); err != nil {
			return models.PaginatedKnowledgeList{}, err
		}
		out = append(out, doc)
	}
	if rows.Err() != nil {
		return models.PaginatedKnowledgeList{}, rows.Err()
	}
	return models.PaginatedKnowledgeList{
		Items:    out,
		Page:     p,
		PageSize: ps,
		Total:    total,
		HasNext:  int64(offset+len(out)) < total,
	}, nil
}
