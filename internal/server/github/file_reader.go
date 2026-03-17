package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// Maximum allowed size of a file: 1 MB.
const maxResponseBytes = 1 * 1024 * 1024

type FileReader struct {
	tokenSource *InstallationTokenSource
	client      *http.Client
}

func NewFileReader(tokenSource *InstallationTokenSource, client *http.Client) *FileReader {
	if client == nil {
		client = http.DefaultClient
	}

	return &FileReader{tokenSource, client}
}

func (f *FileReader) ReadFile(ctx context.Context, owner, repo, path string) (string, error) {
	token, err := f.tokenSource.Token(ctx)

	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return "", err
	}

	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Accept", "application/vnd.github.raw+json") // This ensures GitHub returns the raw content
	request.Header.Add("X-GitHub-Api-Version", "2022-11-28")

	response, err := f.client.Do(request)

	if err != nil {
		return "", fmt.Errorf("could not fetch file content: %w", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))

	if err != nil {
		return "", fmt.Errorf("could read response body from GitHub: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code from GitHub API (%d): %s", response.StatusCode, body)
	}

	return string(body), nil
}
