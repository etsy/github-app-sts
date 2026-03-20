package github

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	// Maximum allowed size of a file: 1 MB.
	maxResponseBytes = 1 * 1024 * 1024
	fileCacheSize    = 1024
	fileCacheTTL     = 1 * time.Minute
)

var getNow = time.Now

type FileReader struct {
	tokenSource InstallationTokenSource
	client      *http.Client

	cache *lru.Cache[string, fileCacheEntry]
}

func NewFileReader(tokenSource InstallationTokenSource, client *http.Client) *FileReader {
	if client == nil {
		client = http.DefaultClient
	}

	// SAFETY: allocating with a positive integer is infallible.
	lru, _ := lru.New[string, fileCacheEntry](fileCacheSize)

	return &FileReader{tokenSource, client, lru}
}

func (f *FileReader) ReadFile(ctx context.Context, owner, repo, path string) ([]byte, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/contents/%s", owner, repo, path)
	now := getNow()

	cacheEntry, _ := f.cache.Get(url)

	if !cacheEntry.Expired(now) {
		return cacheEntry.content, nil
	}

	if err := f.readFile(ctx, url, &cacheEntry); err != nil {
		return nil, err
	}

	cacheEntry.fetched = now

	f.cache.Add(url, cacheEntry)

	return cacheEntry.content, nil
}

func (f *FileReader) readFile(ctx context.Context, url string, entry *fileCacheEntry) error {
	token, err := f.tokenSource.Token(ctx, nil, map[string]string{"contents": "read"})

	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)

	if err != nil {
		return err
	}

	request.Header.Set("Authorization", "Bearer "+token.AccessToken)
	request.Header.Set("Accept", "application/vnd.github.raw+json") // This ensures GitHub returns the raw content
	request.Header.Add("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("If-None-Match", entry.etag)

	response, err := f.client.Do(request)

	if err != nil {
		return fmt.Errorf("could not fetch file content: %w", err)
	}

	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))

	if err != nil {
		return fmt.Errorf("could read response body from GitHub: %w", err)
	}

	if response.StatusCode == http.StatusNotModified {
		return nil
	}

	if response.StatusCode == http.StatusNotFound {
		return &FileNotFoundError{url}
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from GitHub API (%d): %s", response.StatusCode, body)
	}

	entry.content = body
	entry.etag = response.Header.Get("ETag")

	return nil
}

type FileNotFoundError struct {
	URL string
}

func (e *FileNotFoundError) Error() string {
	return fmt.Sprintf("file not found: %s", e.URL)
}

type fileCacheEntry struct {
	content []byte
	etag    string
	fetched time.Time
}

func (f *fileCacheEntry) Expired(now time.Time) bool {
	return now.Sub(f.fetched) > fileCacheTTL
}
