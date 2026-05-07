package llm

import (
	"context"
	"strings"

	"github.com/zmiishe/synamcps/internal/config"
)

type Summarizer interface {
	Summarize(ctx context.Context, text string) (summary string, model string, err error)
}

type EmbeddingProvider interface {
	Embed(ctx context.Context, text string) ([]float32, string, error)
}

type SimpleSummarizer struct {
	cfg config.ModelConfig
}

func NewSimpleSummarizer(cfg config.ModelConfig) *SimpleSummarizer {
	return &SimpleSummarizer{cfg: cfg}
}

func (s *SimpleSummarizer) Summarize(_ context.Context, text string) (string, string, error) {
	max := s.cfg.MaxOutputTokens
	if max <= 0 {
		max = 400
	}

	words := strings.Fields(text)
	if len(words) > max {
		words = words[:max]
	}
	return strings.Join(words, " "), s.cfg.Model, nil
}

type SimpleEmbeddingProvider struct {
	cfg config.ModelConfig
}

func NewSimpleEmbeddingProvider(cfg config.ModelConfig) *SimpleEmbeddingProvider {
	return &SimpleEmbeddingProvider{cfg: cfg}
}

func (e *SimpleEmbeddingProvider) Embed(_ context.Context, text string) ([]float32, string, error) {
	// Deterministic placeholder vector to keep adapters and tests simple.
	vec := []float32{float32(len(text)%101) / 100, float32(len(strings.Fields(text))%101) / 100}
	return vec, e.cfg.Model, nil
}
