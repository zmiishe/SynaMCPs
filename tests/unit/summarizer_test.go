package unit

import (
	"context"
	"strings"
	"testing"

	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/llm"
)

func TestSummarizerRespectsTokenLimit(t *testing.T) {
	s := llm.NewSimpleSummarizer(config.ModelConfig{Model: "sum-model", MaxOutputTokens: 3})
	out, model, err := s.Summarize(context.Background(), "a b c d e")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if model != "sum-model" {
		t.Fatalf("model mismatch: %s", model)
	}
	if got := len(strings.Fields(out)); got != 3 {
		t.Fatalf("expected 3 words, got %d", got)
	}
}
