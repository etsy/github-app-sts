package sts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/etsy/github-app-sts/internal/server/github"
	"github.com/etsy/github-app-sts/internal/server/oidc"
	"github.com/etsy/github-app-sts/internal/server/policy"
)

// AppRegistry is a map of org (owner) -> target app alias -> InstallationTokenSource.
type AppRegistry map[string]map[string]github.InstallationTokenSource

type Result struct {
	Token   *github.InstallationToken
	Details *ExchangeDetails
}

type Error struct {
	Kind    ErrorKind
	Message string
	Details *ExchangeDetails
	Err     error
}

func (e *Error) Error() string { return "exchange error" }
func (e *Error) Unwrap() error { return e.Err }

type ErrorKind int

const (
	ErrKindInternal ErrorKind = iota
	ErrKindInvalidToken
	ErrKindInvalidResource
	ErrKindInvalidScope
)

type ExchangeDetails struct {
	SubjectTokenHash  string
	ResourceParameter string
	ScopeParameter    string

	SubjectTokenIssuer string

	TargetOrganization string
	TargetRepository   string

	PolicyTargetApp    string
	PolicyPermissions  github.Permissions
	PolicyRepositories []string

	AllowedByPolicy bool
}

type Service struct {
	verifier tokenVerifier
	loaders  map[string]policyLoader
	apps     AppRegistry
}

func New(verifier *oidc.Verifier, loaders map[string]*policy.Loader, apps AppRegistry) *Service {
	compatibleLoaders := make(map[string]policyLoader, len(loaders))
	for k, v := range loaders {
		compatibleLoaders[k] = v
	}

	return &Service{
		verifier,
		compatibleLoaders,
		apps,
	}
}

func (s *Service) ExchangeToken(ctx context.Context, subjectToken, resource, scope string) (*Result, error) {
	d := ExchangeDetails{
		SubjectTokenHash:  hashSubjectToken(subjectToken),
		ResourceParameter: resource,
		ScopeParameter:    scope,
	}

	var err error

	d.SubjectTokenIssuer, err = s.verifier.ExtractIssuer(subjectToken)

	if err != nil {
		return nil, &Error{ErrKindInvalidToken, "invalid subject token", &d, err}
	}

	if err := parseResource(resource, &d); err != nil {
		return nil, &Error{ErrKindInvalidResource, "invalid resource", &d, err}
	}

	if err := validateScope(scope); err != nil {
		return nil, &Error{ErrKindInvalidScope, "invalid scope", &d, err}
	}

	targetLoader, ok := s.loaders[d.TargetOrganization]

	if !ok {
		return nil, &Error{ErrKindInvalidResource, "invalid resource", &d, fmt.Errorf("unknown organization: %s", d.TargetOrganization)}
	}

	var pol *policy.Policy

	if d.TargetRepository == "" {
		pol, err = targetLoader.LoadOrganizationPolicy(ctx, scope)
	} else {
		pol, err = targetLoader.LoadRepositoryPolicy(ctx, d.TargetRepository, scope)
	}

	if err != nil {
		kind := ErrKindInternal

		var notFoundError *policy.NotFoundError

		if errors.As(err, &notFoundError) {
			kind = ErrKindInvalidScope
		}

		msg := "invalid scope"
		if kind == ErrKindInternal {
			msg = "internal server error"
		}

		return nil, &Error{kind, msg, &d, fmt.Errorf("could not load policy: %w", err)}
	}

	d.PolicyTargetApp = pol.TargetApp
	d.PolicyRepositories = pol.Repositories
	d.PolicyPermissions = pol.Permissions

	if err := s.verifier.Verify(ctx, d.SubjectTokenIssuer, subjectToken, pol); err != nil {
		// This is a *tiny* lie. The verification could fail because of a server error, for example in the case of
		// needing to refresh the OIDC JWK values. This is rare compared to other types of failures, however.
		return nil, &Error{ErrKindInvalidToken, "invalid subject token", &d, fmt.Errorf("rejected by verifier: %w", err)}
	}

	d.AllowedByPolicy = true

	targetInstallations, ok := s.apps[d.TargetOrganization]

	if !ok {
		return nil, &Error{ErrKindInternal, "internal server error", &d, fmt.Errorf("policy app does not appear to be installed in the target org")}
	}

	tokenSource, ok := targetInstallations[pol.TargetApp]

	if !ok {
		return nil, &Error{ErrKindInternal, fmt.Sprintf("policy references unknown app: %s", pol.TargetApp), &d, fmt.Errorf("policy references unknown app: %s", pol.TargetApp)}
	}

	token, err := tokenSource.Token(ctx, pol.Repositories, pol.Permissions)

	if err != nil {
		return nil, &Error{ErrKindInternal, "internal server error", &d, err}
	}

	return &Result{token, &d}, nil
}

func hashSubjectToken(token string) string {
	h := sha256.Sum256([]byte(token))

	return hex.EncodeToString(h[:])
}

func parseResource(resource string, details *ExchangeDetails) error {
	u, err := url.Parse(resource)

	if err != nil {
		return fmt.Errorf("resource is not a valid URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("resource must use HTTPS scheme, got: %q", u.Scheme)
	}

	if u.Host != "github.com" {
		return fmt.Errorf("resource host must be github.com, got: %q", u.Host)
	}

	cleanedPath := path.Clean(u.Path)

	if cleanedPath != u.Path {
		return errors.New("resource path must not contain path traversal")
	}

	if cleanedPath == "/" {
		return errors.New("resource path is empty")
	}

	// remove the leading '/' (e.g. /myorg/repo), then split into ['myorg', 'repo']
	parts := strings.Split(strings.TrimPrefix(cleanedPath, "/"), "/")

	switch len(parts) {
	case 1:
		// org scope: https://github.com/{owner}
		details.TargetOrganization = parts[0]

	case 2:
		// repo scope: https://github.com/{owner}/{repo}
		details.TargetOrganization, details.TargetRepository = parts[0], parts[1]

	default:
		return fmt.Errorf("resource path must have 1 or 2 segments (org or org/repo), got: %d", len(parts))
	}

	return nil
}

func validateScope(scope string) error {
	p := path.Clean(scope)

	if p != scope || strings.HasPrefix(p, "../") || p == ".." {
		return errors.New("scope must not contain path traversal")
	}

	return nil
}

type tokenVerifier interface {
	ExtractIssuer(token string) (string, error)
	Verify(ctx context.Context, issuer, token string, p *policy.Policy) error
}

type policyLoader interface {
	LoadRepositoryPolicy(ctx context.Context, repo, name string) (*policy.Policy, error)
	LoadOrganizationPolicy(ctx context.Context, name string) (*policy.Policy, error)
}
