package meta

import (
	"context"

	"github.com/zmiishe/synamcps/internal/models"
)

type Catalog interface {
	Save(ctx context.Context, doc models.DocumentRecord) error
	Get(ctx context.Context, docID string) (models.DocumentRecord, bool, error)
	Delete(ctx context.Context, docID string) error
	List(ctx context.Context, page models.PageRequest) (models.PaginatedKnowledgeList, error)
	All(ctx context.Context) ([]models.DocumentRecord, error)
}
