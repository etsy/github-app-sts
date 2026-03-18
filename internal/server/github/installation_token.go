package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type InstallationTokenSource interface {
	Token(ctx context.Context) (*InstallationToken, error)
}

type installationTokenSource struct {
	appTokenSource *AppTokenSource
	installationID string
	client         *http.Client

	mutex sync.Mutex
	token *InstallationToken
}

func NewInstallationTokenSource(a *AppTokenSource, installationID string, client *http.Client) InstallationTokenSource {
	if client == nil {
		client = http.DefaultClient
	}

	return &installationTokenSource{appTokenSource: a, installationID: installationID, client: client}
}

func (i *installationTokenSource) Token(ctx context.Context) (*InstallationToken, error) {
	now := time.Now()

	i.mutex.Lock()
	defer i.mutex.Unlock()

	if !i.token.Expired(now) {
		return i.token, nil
	}

	token, err := i.generateToken(ctx)

	if err != nil {
		return nil, err
	}

	i.token = token

	return i.token, nil
}

func (i *installationTokenSource) generateToken(ctx context.Context) (*InstallationToken, error) {
	appToken, err := i.appTokenSource.Token(ctx)

	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", i.installationID)

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)

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
