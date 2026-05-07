package usage

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/models"
)

type Service struct {
	redis     *redis.Client
	prefix    string
	retention time.Duration
	defaultRL models.RateLimitPolicy
	mu        sync.RWMutex
	counters  map[string]int64
	events    []models.UsageEvent
}

func (s *Service) StartVictoriaMetricsExporter(ctx context.Context, remoteWriteURL string, interval time.Duration) {
	if remoteWriteURL == "" {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		client := &http.Client{Timeout: 10 * time.Second}
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				body := []byte(s.Prometheus())
				if len(body) == 0 {
					continue
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, remoteWriteURL, bytes.NewReader(body))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "text/plain")
				resp, err := client.Do(req)
				if err == nil && resp != nil {
					_ = resp.Body.Close()
				}
			}
		}
	}()
}

func NewService(redisCfg config.RedisConfig, usageCfg config.UsageConfig) *Service {
	s := &Service{
		prefix:    redisCfg.KeyPrefix,
		retention: time.Duration(usageCfg.RetentionHours) * time.Hour,
		defaultRL: models.RateLimitPolicy{
			Enabled:           usageCfg.Enabled,
			RequestsPerMinute: usageCfg.DefaultRateLimit.RequestsPerMinute,
			RequestsPerHour:   usageCfg.DefaultRateLimit.RequestsPerHour,
			RequestsPerDay:    usageCfg.DefaultRateLimit.RequestsPerDay,
			Burst:             usageCfg.DefaultRateLimit.Burst,
		},
		counters: map[string]int64{},
	}
	if s.prefix == "" {
		s.prefix = "syna"
	}
	if s.retention <= 0 {
		s.retention = 720 * time.Hour
	}
	if redisCfg.Addr != "" {
		s.redis = redis.NewClient(&redis.Options{Addr: redisCfg.Addr, Password: redisCfg.Password, DB: redisCfg.DB})
	}
	return s
}

func (s *Service) Allow(ctx context.Context, token models.AccessToken, storageID string) (bool, error) {
	policy := token.RateLimit
	if !policy.Enabled {
		policy = s.defaultRL
	}
	if !policy.Enabled {
		return true, nil
	}
	checks := []struct {
		name   string
		limit  int
		window time.Duration
	}{
		{"minute", firstPositive(policy.RequestsPerMinute, s.defaultRL.RequestsPerMinute), time.Minute},
		{"hour", firstPositive(policy.RequestsPerHour, s.defaultRL.RequestsPerHour), time.Hour},
		{"day", firstPositive(policy.RequestsPerDay, s.defaultRL.RequestsPerDay), 24 * time.Hour},
	}
	for _, check := range checks {
		if check.limit <= 0 {
			continue
		}
		ok, err := s.incrementWindow(ctx, fmt.Sprintf("rl:%s:%s", token.ID, check.name), check.limit, check.window)
		if err != nil || !ok {
			return ok, err
		}
		if storageID != "" {
			ok, err := s.incrementWindow(ctx, fmt.Sprintf("rl:%s:%s:%s", token.ID, storageID, check.name), check.limit, check.window)
			if err != nil || !ok {
				return ok, err
			}
		}
	}
	return true, nil
}

func (s *Service) Record(ctx context.Context, event models.UsageEvent) {
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	labels := map[string]string{
		"token_id":         event.TokenID,
		"user_subject_key": event.UserSubjectKey,
		"storage_id":       event.StorageID,
		"tool":             event.Tool,
		"status":           event.Status,
	}
	s.mu.Lock()
	s.events = append(s.events, event)
	if len(s.events) > 10000 {
		s.events = s.events[len(s.events)-10000:]
	}
	s.counters[counterKey("syna_mcp_requests_total", labels)]++
	if event.Status == "rate_limited" {
		s.counters[counterKey("syna_mcp_rate_limited_total", labels)]++
	}
	if event.Status == "error" || event.Status == "forbidden" {
		s.counters[counterKey("syna_mcp_errors_total", labels)]++
	}
	s.counters[counterKey("syna_mcp_bytes_in_total", labels)] += event.BytesIn
	s.counters[counterKey("syna_mcp_bytes_out_total", labels)] += event.BytesOut
	s.mu.Unlock()

	if s.redis == nil {
		return
	}
	ts := event.CreatedAt.UnixMilli()
	_ = s.redis.Do(ctx, "TS.ADD", s.key("ts:usage:req:token:"+event.TokenID), ts, 1, "RETENTION", int64(s.retention/time.Millisecond), "ON_DUPLICATE", "SUM").Err()
	if event.UserSubjectKey != "" {
		_ = s.redis.Do(ctx, "TS.ADD", s.key("ts:usage:req:user:"+event.UserSubjectKey), ts, 1, "RETENTION", int64(s.retention/time.Millisecond), "ON_DUPLICATE", "SUM").Err()
	}
	if event.StorageID != "" {
		_ = s.redis.Do(ctx, "TS.ADD", s.key("ts:usage:req:storage:"+event.StorageID), ts, 1, "RETENTION", int64(s.retention/time.Millisecond), "ON_DUPLICATE", "SUM").Err()
		_ = s.redis.Do(ctx, "TS.ADD", s.key("ts:usage:req:token_storage:"+event.TokenID+":"+event.StorageID), ts, 1, "RETENTION", int64(s.retention/time.Millisecond), "ON_DUPLICATE", "SUM").Err()
	}
	if event.LatencyMS > 0 {
		_ = s.redis.Do(ctx, "TS.ADD", s.key("ts:usage:latency_ms:token:"+event.TokenID), ts, event.LatencyMS, "RETENTION", int64(s.retention/time.Millisecond)).Err()
	}
	bucket := event.CreatedAt.Truncate(time.Minute).Unix()
	field := strings.Join([]string{event.TokenID, event.UserSubjectKey, event.StorageID, event.Tool, event.Status}, "|")
	_ = s.redis.HIncrBy(ctx, s.key(fmt.Sprintf("usage:req:%d", bucket)), field, 1).Err()
	_ = s.redis.Expire(ctx, s.key(fmt.Sprintf("usage:req:%d", bucket)), s.retention).Err()
}

func (s *Service) Series(_ context.Context, metric, groupBy string, from, to time.Time) []models.UsageSeries {
	if metric == "" {
		metric = "requests"
	}
	if groupBy == "" {
		groupBy = "storage"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	points := map[string]int64{}
	for _, e := range s.events {
		if !from.IsZero() && e.CreatedAt.Before(from) {
			continue
		}
		if !to.IsZero() && e.CreatedAt.After(to) {
			continue
		}
		key := groupValue(e, groupBy)
		points[key]++
	}
	out := make([]models.UsageSeries, 0, len(points))
	for k, v := range points {
		out = append(out, models.UsageSeries{
			Metric: metric,
			Labels: map[string]string{groupBy: k},
			Points: []models.UsagePoint{{Timestamp: time.Now().UTC(), Value: v}},
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Labels[groupBy] < out[j].Labels[groupBy] })
	return out
}

func (s *Service) Summary(ctx context.Context, from, to time.Time) map[string]any {
	return map[string]any{
		"series": s.Series(ctx, "requests", "storage", from, to),
	}
}

func (s *Service) Prometheus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var b strings.Builder
	names := make([]string, 0, len(s.counters))
	for k := range s.counters {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		name, labels := splitCounterKey(k)
		b.WriteString(name)
		if labels != "" {
			b.WriteString("{")
			b.WriteString(labels)
			b.WriteString("}")
		}
		b.WriteString(fmt.Sprintf(" %d\n", s.counters[k]))
	}
	return b.String()
}

func (s *Service) incrementWindow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if s.redis == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		k := s.key(key + ":" + fmt.Sprintf("%d", time.Now().Unix()/int64(window.Seconds())))
		s.counters[k]++
		return s.counters[k] <= int64(limit), nil
	}
	redisKey := s.key(key + ":" + fmt.Sprintf("%d", time.Now().Unix()/int64(window.Seconds())))
	n, err := s.redis.Incr(ctx, redisKey).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		_ = s.redis.Expire(ctx, redisKey, window).Err()
	}
	return n <= int64(limit), nil
}

func (s *Service) key(key string) string {
	return s.prefix + ":" + key
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func groupValue(e models.UsageEvent, groupBy string) string {
	switch groupBy {
	case "token":
		return e.TokenID
	case "user":
		return e.UserSubjectKey
	case "tool":
		return e.Tool
	case "status":
		return e.Status
	default:
		return e.StorageID
	}
}

func counterKey(name string, labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf(`%s="%s"`, k, escapeLabel(v)))
	}
	sort.Strings(parts)
	return name + "|" + strings.Join(parts, ",")
}

func splitCounterKey(key string) (string, string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) != 2 {
		return key, ""
	}
	return parts[0], parts[1]
}

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return v
}
