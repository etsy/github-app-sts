package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
	"github.com/etsy/github-app-sts/internal/server/policy"
)

func TestExtractIssuer(t *testing.T) {
	v := &Verifier{
		verifiers: map[string]*gooidc.IDTokenVerifier{
			"https://known-issuer.example.com": nil,
		},
	}

	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid known issuer",
			token: fakeJWT(t, map[string]any{"iss": "https://known-issuer.example.com"}),
			want:  "https://known-issuer.example.com",
		},
		{
			name:    "malformed JWT - too few parts",
			token:   "not-a-jwt",
			wantErr: true,
		},
		{
			name:    "malformed JWT - invalid base64",
			token:   "header.!!!invalid!!!.signature",
			wantErr: true,
		},
		{
			name:    "malformed JWT - invalid JSON",
			token:   "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
			wantErr: true,
		},
		{
			name:    "missing issuer claim",
			token:   fakeJWT(t, map[string]any{"sub": "someone"}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := v.ExtractIssuer(tt.token)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}

	s := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{
				PublicKey: priv.Public(),
				KeyID:     "test-key",
				Algorithm: "RS256",
			},
		},
	}

	srv := httptest.NewServer(s)
	defer srv.Close()
	s.SetIssuer(srv.URL)

	ctx := context.Background()

	v, err := NewVerifier(ctx, []string{srv.URL}, "test-audience", nil)
	if err != nil {
		t.Fatalf("creating verifier: %v", err)
	}

	makeToken := func(claims map[string]any) string {
		defaults := map[string]any{
			"iss": srv.URL,
			"aud": "test-audience",
			"sub": "repo:myorg/myrepo:ref:refs/heads/main",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}
		for k, val := range claims {
			defaults[k] = val
		}

		raw, err := json.Marshal(defaults)
		if err != nil {
			t.Fatalf("marshaling claims: %v", err)
		}

		return oidctest.SignIDToken(priv, "test-key", "RS256", string(raw))
	}

	makePolicy := func(issuer, subject, claims string) *policy.Policy {
		p, err := policy.NewPolicy("1", issuer, subject, claims, map[string]string{"contents": "read"}, []string{"myrepo"}, "myorg", "myorg/myrepo")
		if err != nil {
			t.Fatalf("creating policy: %v", err)
		}
		return p
	}

	tests := []struct {
		name    string
		token   string
		policy  *policy.Policy
		wantErr bool
	}{
		{
			name:   "valid token matching policy",
			token:  makeToken(nil),
			policy: makePolicy(srv.URL, "repo:myorg/myrepo:ref:refs/heads/main", ""),
		},
		{
			name:   "valid token matching policy with regex subject",
			token:  makeToken(nil),
			policy: makePolicy(srv.URL, "repo:myorg/myrepo:.*", ""),
		},
		{
			name:   "valid token matching policy with CEL claims",
			token:  makeToken(map[string]any{"ref": "refs/heads/main"}),
			policy: makePolicy(srv.URL, "repo:myorg/myrepo:.*", `claims.ref == "refs/heads/main"`),
		},
		{
			name:    "issuer mismatch",
			token:   makeToken(nil),
			policy:  makePolicy("https://other-issuer.example.com", "repo:myorg/myrepo:.*", ""),
			wantErr: true,
		},
		{
			name:    "subject mismatch",
			token:   makeToken(nil),
			policy:  makePolicy(srv.URL, "repo:other-org/other-repo:.*", ""),
			wantErr: true,
		},
		{
			name:    "CEL claims evaluate to false",
			token:   makeToken(map[string]any{"ref": "refs/heads/develop"}),
			policy:  makePolicy(srv.URL, "repo:myorg/myrepo:.*", `claims.ref == "refs/heads/main"`),
			wantErr: true,
		},
		{
			name:    "expired token",
			token:   makeToken(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
			policy:  makePolicy(srv.URL, "repo:myorg/myrepo:.*", ""),
			wantErr: true,
		},
		{
			name:    "unknown issuer",
			token:   makeToken(nil),
			policy:  makePolicy(srv.URL, "repo:myorg/myrepo:.*", ""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := tt.policy.Issuer
			if tt.name == "unknown issuer" {
				issuer = "https://unknown.example.com"
			}

			err := v.Verify(ctx, issuer, tt.token, tt.policy)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// fakeJWT builds a JWT with an arbitrary payload, without a real signature.
func fakeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}

	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fakesig"
}
