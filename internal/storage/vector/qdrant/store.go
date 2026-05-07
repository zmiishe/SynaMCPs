package qdrant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/zmiishe/synamcps/internal/models"
	"github.com/zmiishe/synamcps/internal/storage/vector"
	"github.com/zmiishe/synamcps/internal/storage/vector/pgvector"
)

type Store struct {
	baseURL    string
	collection string
	client     *http.Client
	fallback   *pgvector.Store
}

func New(baseURL, collection string) (*Store, error) {
	if baseURL == "" {
		return &Store{fallback: pgvector.NewInMemory()}, nil
	}
	if collection == "" {
		collection = "knowledge"
	}
	return &Store{
		baseURL:    strings.TrimRight(baseURL, "/"),
		collection: collection,
		client:     &http.Client{},
	}, nil
}

func (s *Store) Upsert(ctx context.Context, rec vector.Record) error {
	if s.fallback != nil {
		return s.fallback.Upsert(ctx, rec)
	}
	body := map[string]any{
		"points": []map[string]any{
			{
				"id":      rec.Payload.ChunkID + "-" + uuid.NewString(),
				"vector":  rec.Vector,
				"payload": qdrantPayload(rec),
			},
		},
	}
	return s.post(ctx, fmt.Sprintf("/collections/%s/points", s.collection), body)
}

func (s *Store) Search(ctx context.Context, query []float32, topK int, filter models.PageRequest) ([]vector.Record, error) {
	if s.fallback != nil {
		return s.fallback.Search(ctx, query, topK, filter)
	}
	if topK <= 0 {
		topK = 10
	}
	body := map[string]any{
		"vector": query,
		"limit":  topK,
	}
	raw, err := s.postJSON(ctx, fmt.Sprintf("/collections/%s/points/search", s.collection), body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result []struct {
			Payload map[string]any `json:"payload"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	out := make([]vector.Record, 0, len(resp.Result))
	for _, item := range resp.Result {
		payload := fromQdrantPayload(item.Payload)
		if filter.StorageID != "" && payload.StorageID != filter.StorageID {
			continue
		}
		if filter.Source != "" && payload.Source != filter.Source {
			continue
		}
		if filter.SourceURL != "" {
			if filter.SourceURLMode == "partial" {
				if !strings.Contains(payload.SourceURL, filter.SourceURL) {
					continue
				}
			} else if payload.SourceURL != filter.SourceURL {
				continue
			}
		}
		out = append(out, vector.Record{Payload: payload})
	}
	return out, nil
}

func (s *Store) DeleteByDocID(ctx context.Context, docID string) error {
	if s.fallback != nil {
		return s.fallback.DeleteByDocID(ctx, docID)
	}
	body := map[string]any{
		"filter": map[string]any{
			"must": []map[string]any{
				{"key": "doc_id", "match": map[string]any{"value": docID}},
			},
		},
	}
	return s.post(ctx, fmt.Sprintf("/collections/%s/points/delete", s.collection), body)
}

func (s *Store) Ping(ctx context.Context) error {
	if s.fallback != nil {
		return nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/collections", nil)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("qdrant ping failed")
	}
	return nil
}

func (s *Store) post(ctx context.Context, path string, payload any) error {
	_, err := s.postJSON(ctx, path, payload)
	return err
}

func (s *Store) postJSON(ctx context.Context, path string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("qdrant status %d", resp.StatusCode)
	}
	return ioReadAll(resp.Body)
}

func qdrantPayload(rec vector.Record) map[string]any {
	return map[string]any{
		"doc_id":      rec.Payload.DocID,
		"storage_id":  rec.Payload.StorageID,
		"chunk_id":    rec.Payload.ChunkID,
		"visibility":  string(rec.Payload.Visibility),
		"owner_id":    rec.Payload.OwnerID,
		"group_ids":   rec.Payload.GroupIDs,
		"is_summary":  rec.Payload.IsSummary,
		"source":      rec.Payload.Source,
		"source_url":  rec.Payload.SourceURL,
		"s3_key":      rec.Payload.S3Key,
		"source_hash": rec.Payload.SourceHash,
		"text":        rec.Text,
	}
}

func fromQdrantPayload(m map[string]any) models.VectorPayload {
	return models.VectorPayload{
		DocID:      asString(m["doc_id"]),
		StorageID:  asString(m["storage_id"]),
		ChunkID:    asString(m["chunk_id"]),
		Visibility: models.Visibility(asString(m["visibility"])),
		OwnerID:    asString(m["owner_id"]),
		GroupIDs:   asStringSlice(m["group_ids"]),
		IsSummary:  asBool(m["is_summary"]),
		Source:     asString(m["source"]),
		SourceURL:  asString(m["source_url"]),
		S3Key:      asString(m["s3_key"]),
		SourceHash: asString(m["source_hash"]),
	}
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func ioReadAll(r io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
