package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	tokenCacheSize = 1024
)

type InstallationTokenSource interface {
	Token(ctx context.Context, repos []string, perms Permissions) (*InstallationToken, error)
}

type installationTokenSource struct {
	appTokenSource *AppTokenSource
	installationID string
	client         *http.Client

	cache *lru.Cache[tokenCacheKey, *InstallationToken]
}

func NewInstallationTokenSource(tokenSource *AppTokenSource, installationID string, client *http.Client) InstallationTokenSource {
	if client == nil {
		client = http.DefaultClient
	}

	// SAFETY: allocating with a positive integer is infallible.
	cache, _ := lru.New[tokenCacheKey, *InstallationToken](tokenCacheSize)

	return &installationTokenSource{
		appTokenSource: tokenSource,
		installationID: installationID,
		client:         client,
		cache:          cache,
	}
}

func (i *installationTokenSource) Token(ctx context.Context, repos []string, perms Permissions) (*InstallationToken, error) {
	now := time.Now()
	key := newTokenCacheKey(repos, perms)

	cacheEntry, _ := i.cache.Get(key)

	if !cacheEntry.Expired(now) {
		return cacheEntry, nil
	}

	token, err := i.generateToken(ctx, repos, perms)

	if err != nil {
		return nil, err
	}

	i.cache.Add(key, token)

	return token, nil
}

func (i *installationTokenSource) generateToken(ctx context.Context, repos []string, perms Permissions) (*InstallationToken, error) {
	appToken, err := i.appTokenSource.Token(ctx)

	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", i.installationID)

	var requestBody bytes.Buffer

	err = json.NewEncoder(&requestBody).Encode(struct {
		Repositories []string          `json:"repositories,omitempty"`
		Permissions  map[string]string `json:"permissions,omitempty"`
	}{
		Repositories: repos,
		Permissions:  perms,
	})

	if err != nil {
		// This is unreachable, but we're in a security-sensitive context and it's easy enough to return the error, so
		// we'll do that here.
		return nil, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &requestBody)

	if err != nil {
		return nil, err
	}

	request.Header.Add("Authorization", "Bearer "+appToken.jwt)
	request.Header.Add("Accept", "application/vnd.github+json")
	request.Header.Add("X-GitHub-Api-Version", "2026-03-10")

	response, err := i.client.Do(request)

	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected status code from GitHub API (%d): %s", response.StatusCode, body)
	}

	var tr InstallationToken

	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("unexpected response body from GitHub API: %s", body)
	}

	return &tr, nil
}

type tokenCacheKey string

func newTokenCacheKey(repositories []string, permissions Permissions) tokenCacheKey {
	slices.Sort(repositories)

	h := sha256.New()
	e := json.NewEncoder(h)

	err := e.Encode(struct {
		r []string
		p Permissions
	}{repositories, permissions})

	if err != nil {
		// The Encode call is infallible, but we're in a security-sensitive context, so we'll panic instead of
		// potentially causing a cache collision.
		panic(fmt.Errorf("unreachable: %w", err))
	}

	return tokenCacheKey(h.Sum([]byte{}))
}

type InstallationToken struct {
	AccessToken string    `json:"token"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (t *InstallationToken) Expired(now time.Time) bool {
	if t == nil {
		return true
	}

	return t.ExpiresAt.Sub(now) > (30 * time.Minute)
}
