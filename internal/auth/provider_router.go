package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/zmiishe/synamcps/internal/config"
	"github.com/zmiishe/synamcps/internal/models"
)

type ProviderRouter struct {
	cfg      config.Config
	verifier map[string]jwt.Keyfunc
	mu       sync.RWMutex
}

func NewProviderRouter(cfg config.Config) *ProviderRouter {
	r := &ProviderRouter{
		cfg:      cfg,
		verifier: map[string]jwt.Keyfunc{},
	}
	r.bootstrapVerifiers()
	return r
}

func (r *ProviderRouter) bootstrapVerifiers() {
	for _, p := range r.cfg.OAuth.Providers {
		r.configureVerifier(p.Issuer, p.JWKSURL)
	}
	if r.cfg.Teleport.Enabled && r.cfg.Teleport.Issuer != "" {
		// Teleport can also expose JWKS endpoint; fallback to standard pattern if not configured.
		jwksURL := strings.TrimRight(r.cfg.Teleport.Issuer, "/") + "/.well-known/jwks.json"
		r.configureVerifier(r.cfg.Teleport.Issuer, jwksURL)
	}
}

func (r *ProviderRouter) configureVerifier(issuer, jwksURL string) {
	if issuer == "" || jwksURL == "" {
		return
	}
	provider, err := keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
	if err != nil {
		return
	}
	r.mu.Lock()
	r.verifier[issuer] = provider.Keyfunc
	r.mu.Unlock()
}

func (r *ProviderRouter) VerifyAndParseClaims(ctx context.Context, rawToken string) (tokenClaims, error) {
	unverified := tokenClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	_, _, err := parser.ParseUnverified(rawToken, &unverified)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("parse unverified token: %w", err)
	}
	if unverified.Issuer == "" {
		return tokenClaims{}, errors.New("missing issuer")
	}
	if p, err := r.providerByIssuer(unverified.Issuer); err == nil && p.JWKSURL == "insecure" {
		if len(unverified.Scopes) == 0 && unverified.Scope != "" {
			unverified.Scopes = strings.Fields(unverified.Scope)
		}
		return unverified, nil
	}
	keyf, err := r.keyfuncByIssuer(ctx, unverified.Issuer)
	if err != nil {
		return tokenClaims{}, err
	}
	verified := tokenClaims{}
	_, err = jwt.ParseWithClaims(rawToken, &verified, keyf,
		jwt.WithIssuer(unverified.Issuer),
		jwt.WithLeeway(30),
	)
	if err != nil {
		return tokenClaims{}, fmt.Errorf("verify token: %w", err)
	}
	if aud := r.audienceByIssuer(unverified.Issuer); aud != "" && !hasAudience(verified.Audience, aud) {
		return tokenClaims{}, errors.New("audience mismatch")
	}
	if len(verified.Scopes) == 0 && verified.Scope != "" {
		verified.Scopes = strings.Fields(verified.Scope)
	}
	return verified, nil
}

func (r *ProviderRouter) keyfuncByIssuer(ctx context.Context, issuer string) (jwt.Keyfunc, error) {
	r.mu.RLock()
	keyf, ok := r.verifier[issuer]
	r.mu.RUnlock()
	if ok {
		return keyf, nil
	}
	provider, err := r.providerByIssuer(issuer)
	if err != nil {
		return nil, err
	}
	if provider.JWKSURL == "" {
		return nil, fmt.Errorf("no jwks configured for issuer %q", issuer)
	}
	kf, err := keyfunc.NewDefaultCtx(ctx, []string{provider.JWKSURL})
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.verifier[issuer] = kf.Keyfunc
	r.mu.Unlock()
	return kf.Keyfunc, nil
}

func (r *ProviderRouter) ToPrincipal(claims tokenClaims) (models.Principal, error) {
	if r.isTeleport(claims) {
		p := models.Principal{
			UserID:        claims.Subject,
			Issuer:        claims.Issuer,
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			Groups:        claims.Groups,
			Scopes:        claims.Scopes,
			AuthSource:    "teleport_proxy",
			TeleportRoles: claims.TeleportRoles,
		}
		p.SubjectKey = models.SubjectKeyForPrincipal(p)
		p.GroupSubjectKeys = models.GroupSubjectKeysForPrincipal(p)
		return p, nil
	}

	if !r.isKnownIssuer(claims.Issuer) {
		return models.Principal{}, errors.New("unknown issuer")
	}

	if strings.Contains(claims.Issuer, "google") && len(r.cfg.OAuth.GoogleDomains) > 0 {
		if !claims.EmailVerified {
			return models.Principal{}, errors.New("google email not verified")
		}
		if !r.allowedGoogleDomain(claims.Email) {
			return models.Principal{}, errors.New("google domain denied")
		}
	}

	p := models.Principal{
		UserID:        claims.Subject,
		Issuer:        claims.Issuer,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Groups:        claims.Groups,
		Scopes:        claims.Scopes,
		AuthSource:    "oauth",
	}
	p.SubjectKey = models.SubjectKeyForPrincipal(p)
	p.GroupSubjectKeys = models.GroupSubjectKeysForPrincipal(p)
	return p, nil
}

func (r *ProviderRouter) isTeleport(c tokenClaims) bool {
	if !r.cfg.Teleport.Enabled {
		return false
	}
	return c.Issuer == r.cfg.Teleport.Issuer && hasAudience(c.Audience, r.cfg.Teleport.Audience)
}

func (r *ProviderRouter) isKnownIssuer(issuer string) bool {
	for _, p := range r.cfg.OAuth.Providers {
		if p.Issuer == issuer {
			return true
		}
	}
	return false
}

func (r *ProviderRouter) allowedGoogleDomain(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	d := parts[1]
	for _, allowed := range r.cfg.OAuth.GoogleDomains {
		if strings.EqualFold(d, allowed) {
			return true
		}
	}
	return false
}

func (r *ProviderRouter) providerByIssuer(issuer string) (config.ProviderConfig, error) {
	for _, p := range r.cfg.OAuth.Providers {
		if p.Issuer == issuer {
			return p, nil
		}
	}
	return config.ProviderConfig{}, fmt.Errorf("unknown provider issuer: %s", issuer)
}

func (r *ProviderRouter) audienceByIssuer(issuer string) string {
	for _, p := range r.cfg.OAuth.Providers {
		if p.Issuer == issuer && p.Audience != "" {
			return p.Audience
		}
	}
	if issuer == r.cfg.Teleport.Issuer {
		return r.cfg.Teleport.Audience
	}
	return ""
}

func hasAudience(auds jwt.ClaimStrings, expected string) bool {
	for _, aud := range auds {
		if aud == expected {
			return true
		}
	}
	return false
}
