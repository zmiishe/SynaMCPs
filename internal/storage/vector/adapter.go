package vector

import (
	"context"

	"github.com/zmiishe/synamcps/internal/models"
)

type Record struct {
	Vector  []float32
	Payload models.VectorPayload
	Text    string
}

type Store interface {
	Upsert(ctx context.Context, rec Record) error
	Search(ctx context.Context, query []float32, topK int, filter models.PageRequest) ([]Record, error)
	DeleteByDocID(ctx context.Context, docID string) error
}
