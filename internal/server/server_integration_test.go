package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/etsy/github-app-sts/internal/server"
	"github.com/etsy/github-app-sts/internal/server/config"
	"github.com/etsy/github-app-sts/internal/testutil"
)

const (
	oidcTestAddr   = "localhost:19876"
	oidcTestIssuer = "http://localhost:19876"
)

func TestTokenExchangeIntegration(t *testing.T) {
	testutil.SkipUnlessIntegrationTest(t, "server")

	clientID := testutil.MustGetenv(t, "GITHUB_APP_CLIENT_ID")
	installationID := testutil.MustGetenv(t, "GITHUB_APP_INSTALLATION_ID")
	owner := testutil.MustGetenv(t, "GITHUB_INTEGRATION_TEST_OWNER")
	repo := testutil.MustGetenv(t, "GITHUB_INTEGRATION_TEST_REPO")
	scope := testutil.GetenvOrDefault("GITHUB_INTEGRATION_TEST_SCOPE", "this-policy-is-used-in-a-local-integration-test")

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// 1. Start oidctest server on a fixed address.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	oidcServer := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{
				PublicKey: priv.Public(),
				KeyID:     "test-key",
				Algorithm: "RS256",
			},
		},
	}

	listener, err := net.Listen("tcp", oidcTestAddr)
	if err != nil {
		t.Fatalf("listening on %s: %v", oidcTestAddr, err)
	}

	oidcHTTPServer := &http.Server{Handler: oidcServer}

	go oidcHTTPServer.Serve(listener)
	defer oidcHTTPServer.Close()

	oidcServer.SetIssuer(oidcTestIssuer)

	// 2. Build config programmatically.
	port := 0
	cfg := &config.Config{
		Audience:       ptr(oidcTestIssuer),
		Port:           &port,
		AllowedIssuers: []string{oidcTestIssuer},
		PolicyReaderApp: &config.AppConfig{
			ClientID:   &clientID,
			PrivateKey: config.PrivateKeyConfig{EnvVar: "GITHUB_APP_PRIVATE_KEY"},
			Installations: map[string]int64{
				owner: mustParseInt64(t, installationID),
			},
		},
		STSTargetApps: []*config.AppConfig{
			{
				ClientID:   &clientID,
				PrivateKey: config.PrivateKeyConfig{EnvVar: "GITHUB_APP_PRIVATE_KEY"},
				Installations: map[string]int64{
					owner: mustParseInt64(t, installationID),
				},
			},
		},
	}

	// 3. Create the server using the real wiring.
	srv, err := server.New(ctx, logger, cfg)
	if err != nil {
		t.Fatalf("creating server: %v", err)
	}

	ts := httptest.NewServer(srv.Handler)
	defer ts.Close()

	// 4. Sign a JWT matching the test policy.
	claims, err := json.Marshal(map[string]any{
		"iss": oidcTestIssuer,
		"aud": oidcTestIssuer,
		"sub": "test-subject",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}

	token := oidctest.SignIDToken(priv, "test-key", "RS256", string(claims))

	// 5. Send the token exchange request.
	resp, err := http.PostForm(ts.URL+"/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
		"subject_token":      {token},
		"resource":           {fmt.Sprintf("https://github.com/%s/%s", owner, repo)},
		"scope":              {scope},
	})
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}

	if result.AccessToken == "" {
		t.Fatal("access_token is empty")
	}

	t.Logf("got access_token (length=%d), expires_in=%d", len(result.AccessToken), result.ExpiresIn)

	// 6. Verify the token works against the GitHub API.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo), nil)
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+result.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	ghResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GitHub API request: %v", err)
	}
	defer ghResp.Body.Close()

	if ghResp.StatusCode != http.StatusOK {
		ghBody, _ := io.ReadAll(ghResp.Body)
		t.Fatalf("GitHub API returned %d: %s", ghResp.StatusCode, ghBody)
	}

	t.Log("successfully verified token against GitHub API")
}

func ptr(s string) *string {
	return &s
}

func mustParseInt64(t *testing.T, s string) int64 {
	t.Helper()

	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("parsing %q as int64: %v", s, err)
	}

	return n
}
