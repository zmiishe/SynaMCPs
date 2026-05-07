package access

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/zmiishe/synamcps/internal/models"
)

type Service struct {
	store *Store
}

func NewService(store *Store) *Service {
	return &Service{store: store}
}

func (s *Service) Store() *Store { return s.store }

func (s *Service) EnsurePrincipal(ctx context.Context, p models.Principal, defaultBucket string) (models.User, models.Storage, error) {
	user, err := s.store.UpsertUserFromPrincipal(ctx, p)
	if err != nil {
		return models.User{}, models.Storage{}, err
	}
	for _, groupKey := range models.GroupSubjectKeysForPrincipal(p) {
		parts := strings.Split(groupKey, ":")
		name := groupKey
		if len(parts) > 0 {
			name = parts[len(parts)-1]
		}
		_, _ = s.store.CreateGroup(ctx, models.Group{
			ID:              subjectIDForService(groupKey),
			SubjectKey:      groupKey,
			Source:          p.AuthSource,
			Issuer:          p.Issuer,
			ExternalGroupID: name,
			Name:            name,
			ManagedBy:       "external",
			SyncStatus:      "claims",
		})
	}
	storage, err := s.store.EnsurePersonalStorage(ctx, p, defaultBucket)
	if err != nil {
		return models.User{}, models.Storage{}, err
	}
	return user, storage, nil
}

func (s *Service) ResolveBearer(ctx context.Context, raw string) (models.APIAccessContext, bool, error) {
	token, scopes, found, err := s.store.ResolveToken(ctx, raw)
	if err != nil || !found {
		return models.APIAccessContext{}, found, err
	}
	p := models.Principal{
		UserID:     token.OwnerSubjectKey,
		SubjectKey: token.OwnerSubjectKey,
		AuthSource: "access_token",
		Scopes:     []string{"mcp.token"},
	}
	return models.APIAccessContext{
		Principal:      p,
		AuthMode:       "access_token",
		TokenID:        token.ID,
		AccessToken:    &token,
		AllowedStorage: scopes,
	}, true, nil
}

func (s *Service) CanAccessStorage(ctx context.Context, p models.Principal, token *models.AccessToken, tokenScopes []models.AccessTokenStorage, storageID string, permission models.StoragePermission) (models.EffectiveAccess, bool, error) {
	if storageID == "" {
		return models.EffectiveAccess{}, false, errors.New("storage id is required")
	}
	subjectKeys := SubjectKeys(p)
	acl, err := s.store.ACLForSubject(ctx, subjectKeys)
	if err != nil {
		return models.EffectiveAccess{}, false, err
	}

	userPerms := map[models.StoragePermission]struct{}{}
	for _, b := range acl {
		if b.StorageID != storageID {
			continue
		}
		for _, perm := range RolePermissions(b.Role) {
			userPerms[perm] = struct{}{}
		}
	}

	mode := models.AccessModeReadWrite
	if token != nil {
		mode = models.AccessModeNone
		for _, scope := range tokenScopes {
			if scope.StorageID == storageID {
				mode = intersectMode(token.Mode, scope.MaxMode)
				break
			}
		}
		for _, perm := range ModePermissions(mode) {
			if _, ok := userPerms[perm]; ok {
				continue
			}
		}
	} else {
		if len(userPerms) == 0 && hasScope(p.Scopes, "platform_admin") {
			userPerms[permission] = struct{}{}
		}
	}

	effective := map[models.StoragePermission]struct{}{}
	for perm := range userPerms {
		if token != nil && !slices.Contains(ModePermissions(mode), perm) {
			continue
		}
		effective[perm] = struct{}{}
	}
	if token != nil && len(token.AllowedPermissions) > 0 {
		allowed := map[models.StoragePermission]struct{}{}
		for _, perm := range token.AllowedPermissions {
			allowed[perm] = struct{}{}
		}
		for perm := range effective {
			if _, ok := allowed[perm]; !ok {
				delete(effective, perm)
			}
		}
	}
	out := models.EffectiveAccess{
		StorageID:  storageID,
		SubjectKey: models.SubjectKeyForPrincipal(p),
		Mode:       mode,
	}
	if token != nil {
		out.TokenID = token.ID
	}
	for perm := range effective {
		out.Permissions = append(out.Permissions, perm)
	}
	_, ok := effective[permission]
	return out, ok, nil
}

func (s *Service) AvailableStorages(ctx context.Context, p models.Principal, token *models.AccessToken, tokenScopes []models.AccessTokenStorage) ([]models.Storage, map[string]models.EffectiveAccess, error) {
	all, err := s.store.ListStorages(ctx)
	if err != nil {
		return nil, nil, err
	}
	out := []models.Storage{}
	accessByStorage := map[string]models.EffectiveAccess{}
	for _, st := range all {
		eff, ok, err := s.CanAccessStorage(ctx, p, token, tokenScopes, st.ID, models.PermissionStorageRead)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			out = append(out, st)
			accessByStorage[st.ID] = eff
		}
	}
	return out, accessByStorage, nil
}

func intersectMode(a, b models.AccessMode) models.AccessMode {
	if a == models.AccessModeNone || b == models.AccessModeNone {
		return models.AccessModeNone
	}
	if a == models.AccessModeRead || b == models.AccessModeRead {
		return models.AccessModeRead
	}
	return models.AccessModeReadWrite
}

func hasScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func subjectIDForService(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])[:24]
}
