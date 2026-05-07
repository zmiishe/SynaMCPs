package session

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/models"
)

type Store struct {
	mu           sync.RWMutex
	mcpSessions  map[string]models.Session
	webSessions  map[string]models.WebSession
	streamState  map[string]string
	streamEvents map[string][]string
	redis        *redis.Client
	prefix       string
	ttl          time.Duration
}

func NewStore(cfg config.RedisConfig) *Store {
	store := &Store{
		mcpSessions:  map[string]models.Session{},
		webSessions:  map[string]models.WebSession{},
		streamState:  map[string]string{},
		streamEvents: map[string][]string{},
		prefix:       cfg.KeyPrefix,
		ttl:          time.Duration(cfg.TTLHours) * time.Hour,
	}
	if cfg.Addr != "" {
		store.redis = redis.NewClient(&redis.Options{
			Addr:     cfg.Addr,
			Password: cfg.Password,
			DB:       cfg.DB,
		})
	}
	return store
}

func (s *Store) CreateMCPSession(p models.Principal, ttl time.Duration) models.Session {
	session := models.Session{
		SessionID:         uuid.NewString(),
		Principal:         p,
		Transport:         "streamable_http",
		CurrentStreams:    []string{},
		LastEventByStream: map[string]string{},
		ExpiresAt:         time.Now().Add(ttl),
	}

	s.persist("mcp:session:"+session.SessionID, session, session.ExpiresAt)
	s.mu.Lock()
	s.mcpSessions[session.SessionID] = session
	s.mu.Unlock()
	return session
}

func (s *Store) GetMCPSession(id string) (models.Session, bool) {
	if v, ok := s.loadMCPSession(id); ok {
		return v, true
	}
	s.mu.RLock()
	v, ok := s.mcpSessions[id]
	s.mu.RUnlock()
	return v, ok && time.Now().Before(v.ExpiresAt)
}

func (s *Store) CreateWebSession(p models.Principal, ttl time.Duration) models.WebSession {
	session := models.WebSession{
		SessionID: uuid.NewString(),
		Principal: p,
		CSRFToken: uuid.NewString(),
		ExpiresAt: time.Now().Add(ttl),
	}

	s.persist("web:session:"+session.SessionID, session, session.ExpiresAt)
	s.mu.Lock()
	s.webSessions[session.SessionID] = session
	s.mu.Unlock()
	return session
}

func (s *Store) GetWebSession(id string) (models.WebSession, bool) {
	if v, ok := s.loadWebSession(id); ok {
		return v, true
	}
	s.mu.RLock()
	v, ok := s.webSessions[id]
	s.mu.RUnlock()
	return v, ok && time.Now().Before(v.ExpiresAt)
}

func (s *Store) SaveLastEvent(sessionID, streamID, eventID string) {
	s.mu.Lock()
	key := sessionID + ":" + streamID
	s.streamState[key] = eventID
	s.mu.Unlock()
	s.persistString("mcp:stream:"+key+":last_event", eventID, time.Now().Add(s.ttl))
}

func (s *Store) LastEvent(sessionID, streamID string) string {
	if s.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		key := s.redisKey("mcp:stream:" + sessionID + ":" + streamID + ":last_event")
		val, err := s.redis.Get(ctx, key).Result()
		if err == nil {
			return val
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.streamState[sessionID+":"+streamID]
}

func (s *Store) AppendEvent(sessionID, streamID, payload string) {
	s.mu.Lock()
	key := sessionID + ":" + streamID
	s.streamEvents[key] = append(s.streamEvents[key], payload)
	if len(s.streamEvents[key]) > 100 {
		s.streamEvents[key] = s.streamEvents[key][len(s.streamEvents[key])-100:]
	}
	events := append([]string(nil), s.streamEvents[key]...)
	s.mu.Unlock()
	s.persist("mcp:events:"+key, events, time.Now().Add(s.ttl))
}

func (s *Store) ReplayFrom(sessionID, streamID, afterEvent string) []string {
	if s.redis != nil {
		var events []string
		if ok := s.load("mcp:events:"+sessionID+":"+streamID, &events); ok {
			return filterAfter(events, afterEvent)
		}
	}
	s.mu.RLock()
	key := sessionID + ":" + streamID
	events := s.streamEvents[key]
	s.mu.RUnlock()
	return filterAfter(events, afterEvent)
}

func filterAfter(events []string, afterEvent string) []string {
	if afterEvent == "" {
		return append([]string(nil), events...)
	}
	for i, e := range events {
		if e == afterEvent {
			return append([]string(nil), events[i+1:]...)
		}
	}
	return append([]string(nil), events...)
}

func (s *Store) persist(key string, value any, expiresAt time.Time) {
	if s.redis == nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = s.ttl
	}
	_ = s.redis.Set(ctx, s.redisKey(key), raw, ttl).Err()
}

func (s *Store) persistString(key string, value string, expiresAt time.Time) {
	if s.redis == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = s.ttl
	}
	_ = s.redis.Set(ctx, s.redisKey(key), value, ttl).Err()
}

func (s *Store) load(key string, out any) bool {
	if s.redis == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	raw, err := s.redis.Get(ctx, s.redisKey(key)).Bytes()
	if err != nil {
		return false
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false
	}
	return true
}

func (s *Store) loadMCPSession(id string) (models.Session, bool) {
	var out models.Session
	if !s.load("mcp:session:"+id, &out) {
		return models.Session{}, false
	}
	if time.Now().After(out.ExpiresAt) {
		return models.Session{}, false
	}
	return out, true
}

func (s *Store) loadWebSession(id string) (models.WebSession, bool) {
	var out models.WebSession
	if !s.load("web:session:"+id, &out) {
		return models.WebSession{}, false
	}
	if time.Now().After(out.ExpiresAt) {
		return models.WebSession{}, false
	}
	return out, true
}

func (s *Store) redisKey(key string) string {
	prefix := s.prefix
	if prefix == "" {
		prefix = "syna"
	}
	return fmt.Sprintf("%s:%s", prefix, key)
}

func (s *Store) Ping(ctx context.Context) error {
	if s.redis == nil {
		return nil
	}
	if err := s.redis.Ping(ctx).Err(); err != nil {
		return err
	}
	return nil
}

func (s *Store) IsPersistent() bool {
	return s.redis != nil
}
