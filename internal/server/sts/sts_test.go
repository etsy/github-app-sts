package sts

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/etsy/github-app-sts/internal/server/github"
	"github.com/etsy/github-app-sts/internal/server/policy"
)

func TestParseResource(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantOrg  string
		wantRepo string
		wantErr  bool
	}{
		{
			name:    "valid org resource",
			input:   "https://github.com/myorg",
			wantOrg: "myorg",
		},
		{
			name:     "valid repo resource",
			input:    "https://github.com/myorg/myrepo",
			wantOrg:  "myorg",
			wantRepo: "myrepo",
		},
		{
			name:    "rejects http scheme",
			input:   "http://github.com/myorg",
			wantErr: true,
		},
		{
			name:    "rejects non-github host",
			input:   "https://gitlab.com/myorg",
			wantErr: true,
		},
		{
			name:    "rejects too many path segments",
			input:   "https://github.com/myorg/myrepo/extra",
			wantErr: true,
		},
		{
			name:    "rejects path traversal",
			input:   "https://github.com/myorg/../other",
			wantErr: true,
		},
		{
			name:    "rejects no path",
			input:   "https://github.com",
			wantErr: true,
		},
		{
			name:    "rejects empty path",
			input:   "https://github.com/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var details ExchangeDetails

			err := parseResource(tt.input, &details)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if details.TargetOrganization != tt.wantOrg {
				t.Errorf("org = %q, want %q", details.TargetOrganization, tt.wantOrg)
			}

			if details.TargetRepository != tt.wantRepo {
				t.Errorf("repo = %q, want %q", details.TargetRepository, tt.wantRepo)
			}
		})
	}
}

func TestParseScope(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid scope",
			input: "my-policy",
			want:  "my-policy",
		},
		{
			name:  "valid scope with slash",
			input: "sub/my-policy",
			want:  "sub/my-policy",
		},
		{
			name:  "valid scope with double dot in name",
			input: "..meow",
			want:  "..meow",
		},
		{
			name:    "rejects dot prefix",
			input:   "./my-policy",
			wantErr: true,
		},
		{
			name:    "rejects leading path traversal",
			input:   "../my-policy",
			wantErr: true,
		},
		{
			name:    "rejects bare double dot",
			input:   "..",
			wantErr: true,
		},
		{
			name:    "rejects interior path traversal",
			input:   "foo/../bar",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateScope(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Fakes for ExchangeToken tests

type fakeVerifier struct {
	issuer    string
	issuerErr error
	verifyErr error
}

func (f *fakeVerifier) ExtractIssuer(token string) (string, error) {
	return f.issuer, f.issuerErr
}

func (f *fakeVerifier) Verify(_ context.Context, issuer, token string, p *policy.Policy) error {
	return f.verifyErr
}

type fakePolicyLoader struct {
	policy *policy.Policy
	err    error

	calledRepo bool
	calledOrg  bool
}

func (f *fakePolicyLoader) LoadRepositoryPolicy(_ context.Context, repo, name string) (*policy.Policy, error) {
	f.calledRepo = true
	return f.policy, f.err
}

func (f *fakePolicyLoader) LoadOrganizationPolicy(_ context.Context, name string) (*policy.Policy, error) {
	f.calledOrg = true
	return f.policy, f.err
}

type fakeTokenSource struct {
	token *github.InstallationToken
	err   error
}

func (f *fakeTokenSource) Owner() string {
	return "myorg"
}

func (f *fakeTokenSource) Token(_ context.Context, repos []string, perms github.Permissions) (*github.InstallationToken, error) {
	return f.token, f.err
}

func testPolicy(targetApp string) *policy.Policy {
	p, _ := policy.NewPolicy(
		targetApp,
		"https://token.actions.githubusercontent.com",
		"repo:myorg/myrepo:.*",
		"",
		map[string]string{"contents": "read"},
		[]string{"myrepo"},
	)
	return p
}

func TestExchangeToken(t *testing.T) {
	validToken := &github.InstallationToken{
		AccessToken: "ghs_test123",
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	tests := []struct {
		name         string
		service      *Service
		token        string
		resource     string
		scope        string
		wantErr      bool
		wantErrKind  ErrorKind
		wantRepoLoad bool
		wantOrgLoad  bool
	}{
		{
			name: "successful repo exchange",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://token.actions.githubusercontent.com"},
				loaders:  map[string]policyLoader{"myorg": &fakePolicyLoader{policy: testPolicy("deploy-bot")}},
				apps: AppRegistry{
					"myorg": map[string]github.InstallationTokenSource{
						"deploy-bot": &fakeTokenSource{token: validToken},
					},
				},
			},
			token:        "fake.jwt.token",
			resource:     "https://github.com/myorg/myrepo",
			scope:        "my-policy",
			wantRepoLoad: true,
		},
		{
			name: "successful org exchange",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://token.actions.githubusercontent.com"},
				loaders:  map[string]policyLoader{"myorg": &fakePolicyLoader{policy: testPolicy("deploy-bot")}},
				apps: AppRegistry{
					"myorg": map[string]github.InstallationTokenSource{
						"deploy-bot": &fakeTokenSource{token: validToken},
					},
				},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg",
			scope:       "my-policy",
			wantOrgLoad: true,
		},
		{
			name: "invalid subject token",
			service: &Service{
				verifier: &fakeVerifier{issuerErr: fmt.Errorf("bad token")},
			},
			token:       "bad-token",
			resource:    "https://github.com/myorg/myrepo",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInvalidToken,
		},
		{
			name: "invalid resource",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://issuer.example.com"},
			},
			token:       "fake.jwt.token",
			resource:    "not-a-url",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInvalidResource,
		},
		{
			name: "invalid scope",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://issuer.example.com"},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg",
			scope:       "./traversal",
			wantErr:     true,
			wantErrKind: ErrKindInvalidScope,
		},
		{
			name: "policy load fails",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://issuer.example.com"},
				loaders:  map[string]policyLoader{"myorg": &fakePolicyLoader{err: fmt.Errorf("not found")}},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg/myrepo",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInternal,
		},
		{
			name: "verification fails",
			service: &Service{
				verifier: &fakeVerifier{
					issuer:    "https://token.actions.githubusercontent.com",
					verifyErr: fmt.Errorf("token rejected"),
				},
				loaders: map[string]policyLoader{"myorg": &fakePolicyLoader{policy: testPolicy("deploy-bot")}},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg/myrepo",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInvalidToken,
		},
		{
			name: "unknown target app",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://token.actions.githubusercontent.com"},
				loaders:  map[string]policyLoader{"myorg": &fakePolicyLoader{policy: testPolicy("nonexistent-app")}},
				apps:     AppRegistry{},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg/myrepo",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInternal,
		},
		{
			name: "token source fails",
			service: &Service{
				verifier: &fakeVerifier{issuer: "https://token.actions.githubusercontent.com"},
				loaders:  map[string]policyLoader{"myorg": &fakePolicyLoader{policy: testPolicy("deploy-bot")}},
				apps: AppRegistry{
					"myorg": map[string]github.InstallationTokenSource{
						"deploy-bot": &fakeTokenSource{err: fmt.Errorf("github error")},
					}},
			},
			token:       "fake.jwt.token",
			resource:    "https://github.com/myorg/myrepo",
			scope:       "my-policy",
			wantErr:     true,
			wantErrKind: ErrKindInternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.service.ExchangeToken(context.Background(), tt.token, tt.resource, tt.scope)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				var stsError *Error

				if errors.As(err, &stsError) {
					if stsError.Kind != tt.wantErrKind {
						t.Errorf("expected error kind %d, got %d: %v", tt.wantErrKind, stsError.Kind, err)
					}
				} else {
					t.Errorf("expected Error, got %T: %v", err, err)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if loader, ok := tt.service.loaders["myorg"].(*fakePolicyLoader); ok {
				if tt.wantRepoLoad && !loader.calledRepo {
					t.Error("expected LoadRepositoryPolicy to be called")
				}
				if tt.wantOrgLoad && !loader.calledOrg {
					t.Error("expected LoadOrganizationPolicy to be called")
				}
				if tt.wantRepoLoad && loader.calledOrg {
					t.Error("expected only LoadRepositoryPolicy, but LoadOrganizationPolicy was also called")
				}
				if tt.wantOrgLoad && loader.calledRepo {
					t.Error("expected only LoadOrganizationPolicy, but LoadRepositoryPolicy was also called")
				}
			}

			if result.Token.AccessToken != validToken.AccessToken {
				t.Errorf("got token %q, want %q", result.Token.AccessToken, validToken.AccessToken)
			}
		})
	}
}
