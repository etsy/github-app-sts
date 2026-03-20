package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type fakeInstallationTokenSource struct{}

func (f *fakeInstallationTokenSource) Owner() string {
	return "fake-owner"
}

func (f *fakeInstallationTokenSource) Token(_ context.Context, _repos []string, _perms Permissions) (*InstallationToken, error) {
	return &InstallationToken{
		AccessToken: "fake-token",
		ExpiresAt:   time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

func TestFileReaderCaching(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	getNow = func() time.Time { return now }
	t.Cleanup(func() { getNow = time.Now })

	var fileRequestCount atomic.Int64
	var lastIfNoneMatch atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileRequestCount.Add(1)
		lastIfNoneMatch.Store(r.Header.Get("If-None-Match"))

		if r.Header.Get("If-None-Match") == `"etag-v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", `"etag-v1"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("file content v1"))
	}))
	defer srv.Close()

	// Create a client that rewrites all requests to the test server.
	client := &http.Client{
		Transport: rewriteHostTransport{
			host:      srv.Listener.Addr().String(),
			scheme:    "http",
			transport: http.DefaultTransport,
		},
	}

	reader := NewFileReader(&fakeInstallationTokenSource{}, client)

	ctx := context.Background()

	t.Run("first request fetches from server", func(t *testing.T) {
		fileRequestCount.Store(0)

		content, err := reader.ReadFile(ctx, "repo", "path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(content) != "file content v1" {
			t.Errorf("got %q, want %q", content, "file content v1")
		}

		if fileRequestCount.Load() != 1 {
			t.Errorf("expected 1 request, got %d", fileRequestCount.Load())
		}
	})

	t.Run("within TTL returns cached content without request", func(t *testing.T) {
		fileRequestCount.Store(0)

		content, err := reader.ReadFile(ctx, "repo", "path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(content) != "file content v1" {
			t.Errorf("got %q, want %q", content, "file content v1")
		}

		if fileRequestCount.Load() != 0 {
			t.Errorf("expected 0 requests, got %d", fileRequestCount.Load())
		}
	})

	t.Run("after TTL sends If-None-Match and returns cached on 304", func(t *testing.T) {
		fileRequestCount.Store(0)
		now = now.Add(fileCacheTTL + time.Second)

		content, err := reader.ReadFile(ctx, "repo", "path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(content) != "file content v1" {
			t.Errorf("got %q, want %q", content, "file content v1")
		}

		if fileRequestCount.Load() != 1 {
			t.Errorf("expected 1 request, got %d", fileRequestCount.Load())
		}

		if v, _ := lastIfNoneMatch.Load().(string); v != `"etag-v1"` {
			t.Errorf("expected If-None-Match %q, got %q", `"etag-v1"`, v)
		}
	})

	t.Run("after TTL updates content on 200", func(t *testing.T) {
		fileRequestCount.Store(0)
		now = now.Add(fileCacheTTL + time.Second)

		// Replace handler to return new content.
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fileRequestCount.Add(1)
			w.Header().Set("ETag", `"etag-v2"`)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("file content v2"))
		})

		content, err := reader.ReadFile(ctx, "owner", "path")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if string(content) != "file content v2" {
			t.Errorf("got %q, want %q", content, "file content v2")
		}

		if fileRequestCount.Load() != 1 {
			t.Errorf("expected 1 request, got %d", fileRequestCount.Load())
		}
	})
}

// rewriteHostTransport rewrites request URLs to point to the test server.
type rewriteHostTransport struct {
	host      string
	scheme    string
	transport http.RoundTripper
}

func (t rewriteHostTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Host = t.host
	r.URL.Scheme = t.scheme
	return t.transport.RoundTrip(r)
}
