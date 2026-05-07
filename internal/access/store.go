package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/zmiishe/synamcps/internal/models"
)

type Store struct {
	mu          sync.RWMutex
	users       map[string]models.User
	groups      map[string]models.Group
	memberships []models.GroupMembership
	storages    map[string]models.Storage
	acl         map[string]models.ACLBinding
	tokens      map[string]models.AccessToken
	tokenByHash map[string]string
	tokenScopes []models.AccessTokenStorage
	audit       []models.AuditEvent
	pool        *pgxpool.Pool
	useDB       bool
}

func NewStore(ctx context.Context, dsn string) (*Store, error) {
	s := NewInMemoryStore()
	if dsn == "" {
		return s, nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("create access pg pool: %w", err)
	}
	s.pool = pool
	s.useDB = true
	if err := s.migrate(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func NewInMemoryStore() *Store {
	return &Store{
		users:       map[string]models.User{},
		groups:      map[string]models.Group{},
		storages:    map[string]models.Storage{},
		acl:         map[string]models.ACLBinding{},
		tokens:      map[string]models.AccessToken{},
		tokenByHash: map[string]string{},
	}
}

func (s *Store) migrate(ctx context.Context) error {
	ddl := `
CREATE TABLE IF NOT EXISTS access_users (
  id TEXT PRIMARY KEY,
  subject_key TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  issuer TEXT,
  external_subject TEXT NOT NULL,
  email TEXT,
  display_name TEXT,
  status TEXT NOT NULL,
  password_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL,
  last_seen_at TIMESTAMPTZ NOT NULL
);
ALTER TABLE access_users ADD COLUMN IF NOT EXISTS password_hash TEXT;
CREATE TABLE IF NOT EXISTS access_groups (
  id TEXT PRIMARY KEY,
  subject_key TEXT NOT NULL UNIQUE,
  source TEXT NOT NULL,
  issuer TEXT,
  external_group_id TEXT,
  name TEXT NOT NULL,
  managed_by TEXT NOT NULL,
  sync_status TEXT,
  last_synced_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS access_group_memberships (
  group_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (group_id, user_id)
);
CREATE TABLE IF NOT EXISTS storages (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  owner_subject_key TEXT NOT NULL,
  visibility TEXT NOT NULL,
  default_access TEXT NOT NULL,
  storage_kind TEXT NOT NULL,
  s3_bucket TEXT,
  s3_prefix TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL,
  archived_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS storage_acl_bindings (
  id TEXT PRIMARY KEY,
  storage_id TEXT NOT NULL,
  subject_key TEXT NOT NULL,
  role TEXT NOT NULL,
  granted_by TEXT,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL,
  UNIQUE(storage_id, subject_key, role)
);
CREATE INDEX IF NOT EXISTS idx_storage_acl_subject ON storage_acl_bindings(subject_key);
CREATE TABLE IF NOT EXISTS access_tokens (
  id TEXT PRIMARY KEY,
  owner_subject_key TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  mode TEXT NOT NULL,
  allowed_permissions TEXT[] NOT NULL DEFAULT '{}',
  rate_limit_enabled BOOLEAN NOT NULL DEFAULT true,
  rate_limit_rpm INTEGER NOT NULL DEFAULT 0,
  rate_limit_rph INTEGER NOT NULL DEFAULT 0,
  rate_limit_rpd INTEGER NOT NULL DEFAULT 0,
  burst_limit INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_by TEXT,
  created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS access_token_storages (
  token_id TEXT NOT NULL,
  storage_id TEXT NOT NULL,
  max_mode TEXT NOT NULL,
  tool_allowlist TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (token_id, storage_id)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_subject_key TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  storage_id TEXT,
  created_at TIMESTAMPTZ NOT NULL
);
`
	_, err := s.pool.Exec(ctx, ddl)
	return err
}

func (s *Store) UpsertUserFromPrincipal(ctx context.Context, p models.Principal) (models.User, error) {
	now := time.Now().UTC()
	subject := models.SubjectKeyForPrincipal(p)
	id := subjectID(subject)
	user := models.User{
		ID:              id,
		SubjectKey:      subject,
		Source:          sourceOf(p),
		Issuer:          p.Issuer,
		ExternalSubject: p.UserID,
		Email:           p.Email,
		DisplayName:     p.Email,
		Status:          "active",
		CreatedAt:       now,
		LastSeenAt:       now,
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `
INSERT INTO access_users (id, subject_key, source, issuer, external_subject, email, display_name, status, created_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (subject_key) DO UPDATE SET email=EXCLUDED.email, display_name=EXCLUDED.display_name, status=EXCLUDED.status, last_seen_at=EXCLUDED.last_seen_at`,
			user.ID, user.SubjectKey, user.Source, user.Issuer, user.ExternalSubject, user.Email, user.DisplayName, user.Status, user.CreatedAt, user.LastSeenAt)
		return user, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.users[user.ID]; ok {
		user.CreatedAt = existing.CreatedAt
	}
	s.users[user.ID] = user
	return user, nil
}

func (s *Store) CreateUser(ctx context.Context, user models.User) (models.User, error) {
	now := time.Now().UTC()
	if user.ID == "" {
		if user.SubjectKey != "" {
			user.ID = subjectID(user.SubjectKey)
		} else {
			user.ID = uuid.NewString()
		}
	}
	if user.Source == "" {
		user.Source = "internal"
	}
	if user.ExternalSubject == "" {
		user.ExternalSubject = user.ID
	}
	if user.SubjectKey == "" {
		user.SubjectKey = models.SubjectRef{Kind: models.SubjectUser, Source: user.Source, Issuer: user.Issuer, ExternalID: user.ExternalSubject}.Key()
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Email
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.CreatedAt.IsZero() {
		user.CreatedAt = now
	}
	if user.LastSeenAt.IsZero() {
		user.LastSeenAt = now
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `
INSERT INTO access_users (id, subject_key, source, issuer, external_subject, email, display_name, status, created_at, last_seen_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (subject_key) DO UPDATE SET email=EXCLUDED.email, display_name=EXCLUDED.display_name, status=EXCLUDED.status`,
			user.ID, user.SubjectKey, user.Source, user.Issuer, user.ExternalSubject, user.Email, user.DisplayName, user.Status, user.CreatedAt, user.LastSeenAt)
		return user, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return user, nil
}

func (s *Store) ListUsers(ctx context.Context) ([]models.User, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, subject_key, source, COALESCE(issuer,''), external_subject, COALESCE(email,''), COALESCE(display_name,''), status, created_at, last_seen_at FROM access_users ORDER BY last_seen_at DESC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.User
		for rows.Next() {
			var u models.User
			if err := rows.Scan(&u.ID, &u.SubjectKey, &u.Source, &u.Issuer, &u.ExternalSubject, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt, &u.LastSeenAt); err != nil {
				return nil, err
			}
			out = append(out, u)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func (s *Store) GetUser(ctx context.Context, userID string) (models.User, bool, error) {
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, subject_key, source, COALESCE(issuer,''), external_subject, COALESCE(email,''), COALESCE(display_name,''), status, created_at, last_seen_at FROM access_users WHERE id=$1`, userID)
		var u models.User
		if err := row.Scan(&u.ID, &u.SubjectKey, &u.Source, &u.Issuer, &u.ExternalSubject, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt, &u.LastSeenAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return models.User{}, false, nil
			}
			return models.User{}, false, err
		}
		return u, true, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[userID]
	return u, ok, nil
}

func (s *Store) UserBySubjectKey(ctx context.Context, subjectKey string) (models.User, bool, error) {
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, subject_key, source, COALESCE(issuer,''), external_subject, COALESCE(email,''), COALESCE(display_name,''), status, created_at, last_seen_at FROM access_users WHERE subject_key=$1`, subjectKey)
		var u models.User
		if err := row.Scan(&u.ID, &u.SubjectKey, &u.Source, &u.Issuer, &u.ExternalSubject, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt, &u.LastSeenAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return models.User{}, false, nil
			}
			return models.User{}, false, err
		}
		return u, true, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.SubjectKey == subjectKey {
			return u, true, nil
		}
	}
	return models.User{}, false, nil
}

func (s *Store) UpdateUser(ctx context.Context, userID string, patch models.User) (models.User, error) {
	existing, ok, err := s.GetUser(ctx, userID)
	if err != nil {
		return models.User{}, err
	}
	if !ok {
		return models.User{}, errors.New("user not found")
	}
	if patch.Email != "" {
		existing.Email = patch.Email
	}
	if patch.DisplayName != "" {
		existing.DisplayName = patch.DisplayName
	}
	if patch.Status != "" {
		existing.Status = patch.Status
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `UPDATE access_users SET email=$1, display_name=$2, status=$3 WHERE id=$4`,
			existing.Email, existing.DisplayName, existing.Status, existing.ID)
		return existing, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[existing.ID] = existing
	return existing, nil
}

func (s *Store) SetUserPassword(ctx context.Context, userID, password string) error {
	if password == "" {
		return errors.New("password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `UPDATE access_users SET password_hash=$1 WHERE id=$2`, string(hash), userID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	user, ok := s.users[userID]
	if !ok {
		return errors.New("user not found")
	}
	user.PasswordHash = string(hash)
	s.users[userID] = user
	return nil
}

func (s *Store) CheckUserPassword(ctx context.Context, userID, password string) (bool, error) {
	hash, err := s.userPasswordHash(ctx, userID)
	if err != nil || hash == "" {
		return false, err
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, nil
}

func (s *Store) HasUserPassword(ctx context.Context, userID string) (bool, error) {
	hash, err := s.userPasswordHash(ctx, userID)
	return hash != "", err
}

func (s *Store) AuthenticateUser(ctx context.Context, username, password string) (models.User, bool, error) {
	if username == "" || password == "" {
		return models.User{}, false, nil
	}
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, subject_key, source, COALESCE(issuer,''), external_subject, COALESCE(email,''), COALESCE(display_name,''), status, COALESCE(password_hash,''), created_at, last_seen_at
FROM access_users
WHERE status='active' AND (email=$1 OR id=$1 OR external_subject=$1)
LIMIT 1`, username)
		var u models.User
		if err := row.Scan(&u.ID, &u.SubjectKey, &u.Source, &u.Issuer, &u.ExternalSubject, &u.Email, &u.DisplayName, &u.Status, &u.PasswordHash, &u.CreatedAt, &u.LastSeenAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return models.User{}, false, nil
			}
			return models.User{}, false, err
		}
		if u.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
			return models.User{}, false, nil
		}
		return u, true, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.users {
		if u.Status == "active" && (u.Email == username || u.ID == username || u.ExternalSubject == username) {
			if u.PasswordHash != "" && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
				return u, true, nil
			}
			return models.User{}, false, nil
		}
	}
	return models.User{}, false, nil
}

func (s *Store) userPasswordHash(ctx context.Context, userID string) (string, error) {
	if s.useDB {
		var hash string
		err := s.pool.QueryRow(ctx, `SELECT COALESCE(password_hash,'') FROM access_users WHERE id=$1`, userID).Scan(&hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("user not found")
		}
		return hash, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[userID]
	if !ok {
		return "", errors.New("user not found")
	}
	return user.PasswordHash, nil
}

func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM access_group_memberships WHERE user_id=$1; DELETE FROM access_users WHERE id=$1`, userID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, userID)
	filtered := s.memberships[:0]
	for _, m := range s.memberships {
		if m.UserID != userID {
			filtered = append(filtered, m)
		}
	}
	s.memberships = filtered
	return nil
}

func (s *Store) CreateGroup(ctx context.Context, g models.Group) (models.Group, error) {
	now := time.Now().UTC()
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	if g.Source == "" {
		g.Source = "internal"
	}
	if g.ManagedBy == "" {
		g.ManagedBy = "internal"
	}
	if g.SubjectKey == "" {
		g.SubjectKey = models.SubjectRef{Kind: models.SubjectGroup, Source: g.Source, Issuer: g.Issuer, ExternalID: g.ID}.Key()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = now
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `INSERT INTO access_groups (id, subject_key, source, issuer, external_group_id, name, managed_by, sync_status, last_synced_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (subject_key) DO UPDATE SET name=EXCLUDED.name, sync_status=EXCLUDED.sync_status, last_synced_at=EXCLUDED.last_synced_at`,
			g.ID, g.SubjectKey, g.Source, g.Issuer, g.ExternalGroupID, g.Name, g.ManagedBy, g.SyncStatus, g.LastSyncedAt, g.CreatedAt)
		return g, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[g.ID] = g
	return g, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]models.Group, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, subject_key, source, COALESCE(issuer,''), COALESCE(external_group_id,''), name, managed_by, COALESCE(sync_status,''), last_synced_at, created_at FROM access_groups ORDER BY name`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.Group
		for rows.Next() {
			var g models.Group
			if err := rows.Scan(&g.ID, &g.SubjectKey, &g.Source, &g.Issuer, &g.ExternalGroupID, &g.Name, &g.ManagedBy, &g.SyncStatus, &g.LastSyncedAt, &g.CreatedAt); err != nil {
				return nil, err
			}
			out = append(out, g)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Group, 0, len(s.groups))
	for _, g := range s.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteGroup(ctx context.Context, groupID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM access_group_memberships WHERE group_id=$1; DELETE FROM access_groups WHERE id=$1`, groupID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, groupID)
	filtered := s.memberships[:0]
	for _, m := range s.memberships {
		if m.GroupID != groupID {
			filtered = append(filtered, m)
		}
	}
	s.memberships = filtered
	return nil
}

func (s *Store) AddGroupMember(ctx context.Context, groupID, userID, source string) error {
	if source == "" {
		source = "internal"
	}
	m := models.GroupMembership{GroupID: groupID, UserID: userID, Source: source, CreatedAt: time.Now().UTC()}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `INSERT INTO access_group_memberships (group_id, user_id, source, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT (group_id, user_id) DO UPDATE SET source=EXCLUDED.source`, m.GroupID, m.UserID, m.Source, m.CreatedAt)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.memberships = append(s.memberships, m)
	return nil
}

func (s *Store) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM access_group_memberships WHERE group_id=$1 AND user_id=$2`, groupID, userID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	filtered := s.memberships[:0]
	for _, m := range s.memberships {
		if !(m.GroupID == groupID && m.UserID == userID) {
			filtered = append(filtered, m)
		}
	}
	s.memberships = filtered
	return nil
}

func (s *Store) ListGroupMembers(ctx context.Context, groupID string) ([]models.GroupMembership, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT group_id, user_id, source, created_at, expires_at FROM access_group_memberships WHERE group_id=$1 ORDER BY created_at DESC`, groupID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.GroupMembership
		for rows.Next() {
			var m models.GroupMembership
			if err := rows.Scan(&m.GroupID, &m.UserID, &m.Source, &m.CreatedAt, &m.ExpiresAt); err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []models.GroupMembership
	for _, m := range s.memberships {
		if m.GroupID == groupID {
			out = append(out, m)
		}
	}
	return out, nil
}

func (s *Store) CreateStorage(ctx context.Context, storage models.Storage, actor string) (models.Storage, error) {
	now := time.Now().UTC()
	if storage.ID == "" {
		storage.ID = uuid.NewString()
	}
	if storage.Slug == "" {
		storage.Slug = storage.ID
	}
	if storage.Name == "" {
		storage.Name = storage.Slug
	}
	if storage.Kind == "" {
		storage.Kind = models.StorageKindKnowledge
	}
	if storage.DefaultAccess == "" {
		storage.DefaultAccess = models.AccessModeNone
	}
	if storage.Status == "" {
		storage.Status = models.StorageStatusActive
	}
	if storage.S3Prefix == "" {
		storage.S3Prefix = "storages/" + storage.ID + "/"
	}
	storage.CreatedAt = zeroTime(storage.CreatedAt, now)
	storage.UpdatedAt = now
	if s.useDB {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return models.Storage{}, err
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO storages (id, slug, name, owner_subject_key, visibility, default_access, storage_kind, s3_bucket, s3_prefix, status, created_at, updated_at, archived_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			storage.ID, storage.Slug, storage.Name, storage.OwnerSubjectKey, string(storage.Visibility), string(storage.DefaultAccess), string(storage.Kind), storage.S3Bucket, storage.S3Prefix, string(storage.Status), storage.CreatedAt, storage.UpdatedAt, storage.ArchivedAt)
		if err != nil {
			return models.Storage{}, err
		}
		owner := models.ACLBinding{ID: uuid.NewString(), StorageID: storage.ID, SubjectKey: storage.OwnerSubjectKey, Role: models.RoleStorageOwner, GrantedBy: actor, CreatedAt: now}
		if _, err := tx.Exec(ctx, `INSERT INTO storage_acl_bindings (id, storage_id, subject_key, role, granted_by, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
			owner.ID, owner.StorageID, owner.SubjectKey, string(owner.Role), owner.GrantedBy, owner.ExpiresAt, owner.CreatedAt); err != nil {
			return models.Storage{}, err
		}
		return storage, tx.Commit(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storages[storage.ID] = storage
	owner := models.ACLBinding{ID: uuid.NewString(), StorageID: storage.ID, SubjectKey: storage.OwnerSubjectKey, Role: models.RoleStorageOwner, GrantedBy: actor, CreatedAt: now}
	s.acl[owner.ID] = owner
	return storage, nil
}

func (s *Store) EnsurePersonalStorage(ctx context.Context, p models.Principal, bucket string) (models.Storage, error) {
	subject := models.SubjectKeyForPrincipal(p)
	slug := "personal-" + subjectID(subject)
	if existing, ok, err := s.StorageBySlug(ctx, slug); err != nil || ok {
		return existing, err
	}
	return s.CreateStorage(ctx, models.Storage{
		Slug:            slug,
		Name:            "Personal storage",
		OwnerSubjectKey: subject,
		Visibility:      models.VisibilityPersonal,
		DefaultAccess:   models.AccessModeNone,
		S3Bucket:        bucket,
	}, subject)
}

func (s *Store) StorageBySlug(ctx context.Context, slug string) (models.Storage, bool, error) {
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, slug, name, owner_subject_key, visibility, default_access, storage_kind, COALESCE(s3_bucket,''), s3_prefix, status, created_at, updated_at, archived_at FROM storages WHERE slug=$1`, slug)
		return scanStorage(row)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, st := range s.storages {
		if st.Slug == slug {
			return st, true, nil
		}
	}
	return models.Storage{}, false, nil
}

func (s *Store) GetStorage(ctx context.Context, id string) (models.Storage, bool, error) {
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, slug, name, owner_subject_key, visibility, default_access, storage_kind, COALESCE(s3_bucket,''), s3_prefix, status, created_at, updated_at, archived_at FROM storages WHERE id=$1`, id)
		return scanStorage(row)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.storages[id]
	return st, ok, nil
}

func (s *Store) ListStorages(ctx context.Context) ([]models.Storage, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, slug, name, owner_subject_key, visibility, default_access, storage_kind, COALESCE(s3_bucket,''), s3_prefix, status, created_at, updated_at, archived_at FROM storages ORDER BY updated_at DESC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.Storage
		for rows.Next() {
			st, _, err := scanStorage(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, st)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Storage, 0, len(s.storages))
	for _, st := range s.storages {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

func (s *Store) DeleteStorage(ctx context.Context, storageID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM storage_acl_bindings WHERE storage_id=$1; DELETE FROM access_token_storages WHERE storage_id=$1; DELETE FROM storages WHERE id=$1`, storageID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.storages, storageID)
	for id, b := range s.acl {
		if b.StorageID == storageID {
			delete(s.acl, id)
		}
	}
	filtered := s.tokenScopes[:0]
	for _, scope := range s.tokenScopes {
		if scope.StorageID != storageID {
			filtered = append(filtered, scope)
		}
	}
	s.tokenScopes = filtered
	return nil
}

func (s *Store) UpsertACL(ctx context.Context, b models.ACLBinding) (models.ACLBinding, error) {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now().UTC()
	}
	if s.useDB {
		_, err := s.pool.Exec(ctx, `INSERT INTO storage_acl_bindings (id, storage_id, subject_key, role, granted_by, expires_at, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (storage_id, subject_key, role) DO UPDATE SET granted_by=EXCLUDED.granted_by, expires_at=EXCLUDED.expires_at`,
			b.ID, b.StorageID, b.SubjectKey, string(b.Role), b.GrantedBy, b.ExpiresAt, b.CreatedAt)
		return b, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acl[b.ID] = b
	return b, nil
}

func (s *Store) ACLForStorage(ctx context.Context, storageID string) ([]models.ACLBinding, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, storage_id, subject_key, role, COALESCE(granted_by,''), expires_at, created_at FROM storage_acl_bindings WHERE storage_id=$1`, storageID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanACLRows(rows)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []models.ACLBinding
	for _, b := range s.acl {
		if b.StorageID == storageID {
			out = append(out, b)
		}
	}
	return out, nil
}

func (s *Store) ACLForSubject(ctx context.Context, subjectKeys []string) ([]models.ACLBinding, error) {
	if len(subjectKeys) == 0 {
		return nil, nil
	}
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, storage_id, subject_key, role, COALESCE(granted_by,''), expires_at, created_at FROM storage_acl_bindings WHERE subject_key = ANY($1)`, subjectKeys)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanACLRows(rows)
	}
	set := map[string]struct{}{}
	for _, k := range subjectKeys {
		set[k] = struct{}{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []models.ACLBinding
	for _, b := range s.acl {
		if _, ok := set[b.SubjectKey]; ok {
			out = append(out, b)
		}
	}
	return out, nil
}

type CreateTokenInput struct {
	OwnerSubjectKey string
	Name            string
	Mode            models.AccessMode
	StorageScopes   []models.AccessTokenStorage
	RateLimit       models.RateLimitPolicy
	ExpiresAt       *time.Time
	CreatedBy       string
}

func (s *Store) CreateToken(ctx context.Context, in CreateTokenInput) (models.AccessToken, string, error) {
	if in.OwnerSubjectKey == "" {
		return models.AccessToken{}, "", errors.New("owner subject key is required")
	}
	if in.Mode == "" {
		in.Mode = models.AccessModeRead
	}
	raw, err := newRawToken()
	if err != nil {
		return models.AccessToken{}, "", err
	}
	now := time.Now().UTC()
	token := models.AccessToken{
		ID:              uuid.NewString(),
		OwnerSubjectKey: in.OwnerSubjectKey,
		TokenHash:       HashToken(raw),
		Name:            in.Name,
		Mode:            in.Mode,
		RateLimit:       in.RateLimit,
		ExpiresAt:       in.ExpiresAt,
		CreatedBy:       in.CreatedBy,
		CreatedAt:       now,
	}
	if token.Name == "" {
		token.Name = "MCP token"
	}
	if s.useDB {
		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return models.AccessToken{}, "", err
		}
		defer tx.Rollback(ctx)
		if err := insertToken(ctx, tx, token); err != nil {
			return models.AccessToken{}, "", err
		}
		for _, scope := range in.StorageScopes {
			scope.TokenID = token.ID
			if scope.CreatedAt.IsZero() {
				scope.CreatedAt = now
			}
			if scope.MaxMode == "" {
				scope.MaxMode = token.Mode
			}
			if scope.ToolAllowlist == nil {
				scope.ToolAllowlist = []string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO access_token_storages (token_id, storage_id, max_mode, tool_allowlist, created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (token_id, storage_id) DO UPDATE SET max_mode=EXCLUDED.max_mode, tool_allowlist=EXCLUDED.tool_allowlist`,
				scope.TokenID, scope.StorageID, string(scope.MaxMode), scope.ToolAllowlist, scope.CreatedAt); err != nil {
				return models.AccessToken{}, "", err
			}
		}
		return token, raw, tx.Commit(ctx)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.ID] = token
	s.tokenByHash[token.TokenHash] = token.ID
	for _, scope := range in.StorageScopes {
		scope.TokenID = token.ID
		if scope.CreatedAt.IsZero() {
			scope.CreatedAt = now
		}
		if scope.MaxMode == "" {
			scope.MaxMode = token.Mode
		}
		s.tokenScopes = append(s.tokenScopes, scope)
	}
	return token, raw, nil
}

func (s *Store) ResolveToken(ctx context.Context, raw string) (models.AccessToken, []models.AccessTokenStorage, bool, error) {
	hash := HashToken(raw)
	var token models.AccessToken
	var ok bool
	if s.useDB {
		row := s.pool.QueryRow(ctx, `SELECT id, owner_subject_key, token_hash, name, mode, allowed_permissions, rate_limit_enabled, rate_limit_rpm, rate_limit_rph, rate_limit_rpd, burst_limit, expires_at, revoked_at, last_used_at, COALESCE(created_by,''), created_at FROM access_tokens WHERE token_hash=$1`, hash)
		t, found, err := scanToken(row)
		if err != nil || !found {
			return models.AccessToken{}, nil, found, err
		}
		token, ok = t, true
	} else {
		s.mu.RLock()
		id, found := s.tokenByHash[hash]
		if found {
			token, ok = s.tokens[id]
		}
		s.mu.RUnlock()
	}
	if !ok {
		return models.AccessToken{}, nil, false, nil
	}
	if token.RevokedAt != nil || (token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt)) {
		return models.AccessToken{}, nil, true, errors.New("token is revoked or expired")
	}
	scopes, err := s.TokenStorages(ctx, token.ID)
	if err != nil {
		return models.AccessToken{}, nil, true, err
	}
	_ = s.MarkTokenUsed(ctx, token.ID)
	return token, scopes, true, nil
}

func (s *Store) ListTokens(ctx context.Context) ([]models.AccessToken, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT id, owner_subject_key, token_hash, name, mode, allowed_permissions, rate_limit_enabled, rate_limit_rpm, rate_limit_rph, rate_limit_rpd, burst_limit, expires_at, revoked_at, last_used_at, COALESCE(created_by,''), created_at FROM access_tokens ORDER BY created_at DESC`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.AccessToken
		for rows.Next() {
			t, _, err := scanToken(rows)
			if err != nil {
				return nil, err
			}
			out = append(out, t)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.AccessToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) TokenStorages(ctx context.Context, tokenID string) ([]models.AccessTokenStorage, error) {
	if s.useDB {
		rows, err := s.pool.Query(ctx, `SELECT token_id, storage_id, max_mode, tool_allowlist, created_at FROM access_token_storages WHERE token_id=$1`, tokenID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []models.AccessTokenStorage
		for rows.Next() {
			var scope models.AccessTokenStorage
			var maxMode string
			if err := rows.Scan(&scope.TokenID, &scope.StorageID, &maxMode, &scope.ToolAllowlist, &scope.CreatedAt); err != nil {
				return nil, err
			}
			scope.MaxMode = models.AccessMode(maxMode)
			out = append(out, scope)
		}
		return out, rows.Err()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []models.AccessTokenStorage
	for _, scope := range s.tokenScopes {
		if scope.TokenID == tokenID {
			out = append(out, scope)
		}
	}
	return out, nil
}

func (s *Store) RevokeToken(ctx context.Context, tokenID string) error {
	now := time.Now().UTC()
	if s.useDB {
		_, err := s.pool.Exec(ctx, `UPDATE access_tokens SET revoked_at=$1 WHERE id=$2`, now, tokenID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return nil
	}
	t.RevokedAt = &now
	s.tokens[tokenID] = t
	return nil
}

func (s *Store) DeleteToken(ctx context.Context, tokenID string) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `DELETE FROM access_token_storages WHERE token_id=$1; DELETE FROM access_tokens WHERE id=$1`, tokenID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tokens[tokenID]; ok {
		delete(s.tokenByHash, t.TokenHash)
	}
	delete(s.tokens, tokenID)
	filtered := s.tokenScopes[:0]
	for _, scope := range s.tokenScopes {
		if scope.TokenID != tokenID {
			filtered = append(filtered, scope)
		}
	}
	s.tokenScopes = filtered
	return nil
}

func (s *Store) UpdateTokenRateLimit(ctx context.Context, tokenID string, policy models.RateLimitPolicy) error {
	if s.useDB {
		_, err := s.pool.Exec(ctx, `UPDATE access_tokens SET rate_limit_enabled=$1, rate_limit_rpm=$2, rate_limit_rph=$3, rate_limit_rpd=$4, burst_limit=$5 WHERE id=$6`,
			policy.Enabled, policy.RequestsPerMinute, policy.RequestsPerHour, policy.RequestsPerDay, policy.Burst, tokenID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return nil
	}
	t.RateLimit = policy
	s.tokens[tokenID] = t
	return nil
}

func (s *Store) MarkTokenUsed(ctx context.Context, tokenID string) error {
	now := time.Now().UTC()
	if s.useDB {
		_, err := s.pool.Exec(ctx, `UPDATE access_tokens SET last_used_at=$1 WHERE id=$2`, now, tokenID)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[tokenID]
	if !ok {
		return nil
	}
	t.LastUsedAt = &now
	s.tokens[tokenID] = t
	return nil
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func newRawToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "syna_" + hex.EncodeToString(buf), nil
}

func subjectID(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])[:24]
}

func sourceOf(p models.Principal) string {
	if p.AuthSource != "" {
		return p.AuthSource
	}
	return "internal"
}

func zeroTime(v, fallback time.Time) time.Time {
	if v.IsZero() {
		return fallback
	}
	return v
}

type storageScanner interface {
	Scan(dest ...any) error
}

func scanStorage(row storageScanner) (models.Storage, bool, error) {
	var st models.Storage
	var visibility, defaultAccess, kind, status string
	err := row.Scan(&st.ID, &st.Slug, &st.Name, &st.OwnerSubjectKey, &visibility, &defaultAccess, &kind, &st.S3Bucket, &st.S3Prefix, &status, &st.CreatedAt, &st.UpdatedAt, &st.ArchivedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.Storage{}, false, nil
		}
		return models.Storage{}, false, err
	}
	st.Visibility = models.Visibility(visibility)
	st.DefaultAccess = models.AccessMode(defaultAccess)
	st.Kind = models.StorageKind(kind)
	st.Status = models.StorageStatus(status)
	return st, true, nil
}

func scanACLRows(rows pgx.Rows) ([]models.ACLBinding, error) {
	var out []models.ACLBinding
	for rows.Next() {
		var b models.ACLBinding
		var role string
		if err := rows.Scan(&b.ID, &b.StorageID, &b.SubjectKey, &role, &b.GrantedBy, &b.ExpiresAt, &b.CreatedAt); err != nil {
			return nil, err
		}
		b.Role = models.StorageRole(role)
		out = append(out, b)
	}
	return out, rows.Err()
}

type tokenScanner interface {
	Scan(dest ...any) error
}

func scanToken(row tokenScanner) (models.AccessToken, bool, error) {
	var t models.AccessToken
	var mode string
	var permissions []string
	err := row.Scan(&t.ID, &t.OwnerSubjectKey, &t.TokenHash, &t.Name, &mode, &permissions, &t.RateLimit.Enabled, &t.RateLimit.RequestsPerMinute, &t.RateLimit.RequestsPerHour, &t.RateLimit.RequestsPerDay, &t.RateLimit.Burst, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return models.AccessToken{}, false, nil
		}
		return models.AccessToken{}, false, err
	}
	t.Mode = models.AccessMode(mode)
	t.AllowedPermissions = make([]models.StoragePermission, 0, len(permissions))
	for _, p := range permissions {
		t.AllowedPermissions = append(t.AllowedPermissions, models.StoragePermission(p))
	}
	return t, true, nil
}

type txExec interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconnCommandTag, error)
}

type pgconnCommandTag interface{}

func insertToken(ctx context.Context, tx pgx.Tx, token models.AccessToken) error {
	permissions := make([]string, 0, len(token.AllowedPermissions))
	for _, p := range token.AllowedPermissions {
		permissions = append(permissions, string(p))
	}
	_, err := tx.Exec(ctx, `INSERT INTO access_tokens (id, owner_subject_key, token_hash, name, mode, allowed_permissions, rate_limit_enabled, rate_limit_rpm, rate_limit_rph, rate_limit_rpd, burst_limit, expires_at, revoked_at, last_used_at, created_by, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		token.ID, token.OwnerSubjectKey, token.TokenHash, token.Name, string(token.Mode), permissions, token.RateLimit.Enabled, token.RateLimit.RequestsPerMinute, token.RateLimit.RequestsPerHour, token.RateLimit.RequestsPerDay, token.RateLimit.Burst, token.ExpiresAt, token.RevokedAt, token.LastUsedAt, token.CreatedBy, token.CreatedAt)
	return err
}

func RolePermissions(role models.StorageRole) []models.StoragePermission {
	switch role {
	case models.RoleStorageOwner, models.RoleStorageAdmin:
		return []models.StoragePermission{
			models.PermissionStorageRead,
			models.PermissionDocumentRead,
			models.PermissionSearchRead,
			models.PermissionDocumentCreate,
			models.PermissionDocumentUpdate,
			models.PermissionDocumentDelete,
			models.PermissionACLManage,
			models.PermissionTokenManage,
			models.PermissionStorageDelete,
		}
	case models.RoleStorageWriter:
		return []models.StoragePermission{
			models.PermissionStorageRead,
			models.PermissionDocumentRead,
			models.PermissionSearchRead,
			models.PermissionDocumentCreate,
			models.PermissionDocumentUpdate,
			models.PermissionDocumentDelete,
		}
	case models.RoleStorageReader:
		return []models.StoragePermission{
			models.PermissionStorageRead,
			models.PermissionDocumentRead,
			models.PermissionSearchRead,
		}
	default:
		return nil
	}
}

func ModePermissions(mode models.AccessMode) []models.StoragePermission {
	if mode == models.AccessModeReadWrite {
		return RolePermissions(models.RoleStorageWriter)
	}
	if mode == models.AccessModeRead {
		return RolePermissions(models.RoleStorageReader)
	}
	return nil
}

func SubjectKeys(p models.Principal) []string {
	keys := []string{models.SubjectKeyForPrincipal(p), "all:authenticated"}
	keys = append(keys, models.GroupSubjectKeysForPrincipal(p)...)
	return dedupe(keys)
}

func dedupe(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
