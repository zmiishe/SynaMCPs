package pgvector

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/storage/vector"
)

type Store struct {
	mu      sync.RWMutex
	records []vector.Record
	pool    *pgxpool.Pool
	useDB   bool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	if dsn == "" {
		return NewInMemory(), nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{pool: pool, useDB: true}
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func NewInMemory() *Store { return &Store{records: []vector.Record{}} }

func (s *Store) migrate(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	ddl := `
CREATE TABLE IF NOT EXISTS knowledge_vectors (
  chunk_id TEXT PRIMARY KEY,
  doc_id TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  embedding_json JSONB NOT NULL,
  text_content TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_knowledge_vectors_doc_id ON knowledge_vectors(doc_id);
`
	_, err := s.pool.Exec(ctx, ddl)
	return err
}

func (s *Store) Upsert(ctx context.Context, rec vector.Record) error {
	if s.useDB {
		return s.upsertDB(ctx, rec)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func (s *Store) Search(ctx context.Context, query []float32, topK int, filter models.PageRequest) ([]vector.Record, error) {
	if s.useDB {
		return s.searchDB(ctx, query, topK, filter)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]vector.Record, 0, len(s.records))
	for _, r := range s.records {
		if filter.StorageID != "" && r.Payload.StorageID != filter.StorageID {
			continue
		}
		if filter.Source != "" && r.Payload.Source != filter.Source {
			continue
		}
		if filter.SourceURL != "" {
			if filter.SourceURLMode == "partial" {
				if !contains(r.Payload.SourceURL, filter.SourceURL) {
					continue
				}
			} else if r.Payload.SourceURL != filter.SourceURL {
				continue
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Payload.DocID < out[j].Payload.DocID })

	if topK <= 0 || topK > len(out) {
		topK = len(out)
	}
	scored := make([]scoredRecord, 0, len(out))
	for _, r := range out[:topK] {
		scored = append(scored, scoredRecord{rec: r, score: cosine(query, r.Vector)})
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].score > scored[j].score })
	result := make([]vector.Record, 0, len(scored))
	for _, s := range scored {
		result = append(result, s.rec)
	}
	return result, nil
}

func (s *Store) DeleteByDocID(ctx context.Context, docID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM knowledge_vectors WHERE doc_id=$1`, docID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.records[:0]
	for _, r := range s.records {
		if r.Payload.DocID != docID {
			filtered = append(filtered, r)
		}
	}
	s.records = filtered
	return nil
}

func (s *Store) Ping(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	return s.pool.Ping(ctx)
}

func contains(haystack, needle string) bool {
	return needle == "" || indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

func (s *Store) upsertDB(ctx context.Context, rec vector.Record) error {
	payloadRaw, err := json.Marshal(rec.Payload)
	if err != nil {
		return err
	}
	vecRaw, err := json.Marshal(rec.Vector)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO knowledge_vectors (chunk_id, doc_id, payload_json, embedding_json, text_content)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (chunk_id) DO UPDATE SET
  doc_id=EXCLUDED.doc_id,
  payload_json=EXCLUDED.payload_json,
  embedding_json=EXCLUDED.embedding_json,
  text_content=EXCLUDED.text_content
`, rec.Payload.ChunkID, rec.Payload.DocID, payloadRaw, vecRaw, rec.Text)
	return err
}

func (s *Store) searchDB(ctx context.Context, query []float32, topK int, filter models.PageRequest) ([]vector.Record, error) {
	where := "TRUE"
	args := []any{}
	argn := 1
	if filter.Source != "" {
		where += fmt.Sprintf(" AND payload_json->>'Source' = $%d", argn)
		args = append(args, filter.Source)
		argn++
	}
	if filter.StorageID != "" {
		where += fmt.Sprintf(" AND payload_json->>'StorageID' = $%d", argn)
		args = append(args, filter.StorageID)
		argn++
	}
	if filter.SourceURL != "" {
		if filter.SourceURLMode == "partial" {
			where += fmt.Sprintf(" AND payload_json->>'SourceURL' ILIKE $%d", argn)
			args = append(args, "%"+filter.SourceURL+"%")
		} else {
			where += fmt.Sprintf(" AND payload_json->>'SourceURL' = $%d", argn)
			args = append(args, filter.SourceURL)
		}
		argn++
	}
	querySQL := fmt.Sprintf("SELECT payload_json, embedding_json, text_content FROM knowledge_vectors WHERE %s", where)
	rows, err := s.pool.Query(ctx, querySQL, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scored := []scoredRecord{}
	for rows.Next() {
		var payloadRaw, vecRaw []byte
		var text string
		if err := rows.Scan(&payloadRaw, &vecRaw, &text); err != nil {
			return nil, err
		}
		var payload models.VectorPayload
		if err := json.Unmarshal(payloadRaw, &payload); err != nil {
			return nil, err
		}
		var vec []float32
		if err := json.Unmarshal(vecRaw, &vec); err != nil {
			return nil, err
		}
		rec := vector.Record{Vector: vec, Payload: payload, Text: text}
		scored = append(scored, scoredRecord{rec: rec, score: cosine(query, vec)})
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	sort.Slice(scored, func(i, j int) bool { return scored[i].score > scored[j].score })
	if topK <= 0 || topK > len(scored) {
		topK = len(scored)
	}
	out := make([]vector.Record, 0, topK)
	for _, item := range scored[:topK] {
		out = append(out, item.rec)
	}
	return out, nil
}

type scoredRecord struct {
	rec   vector.Record
	score float64
}

func cosine(a, b []float32) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		av := float64(a[i])
		bv := float64(b[i])
		dot += av * bv
		na += av * av
		nb += bv * bv
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
