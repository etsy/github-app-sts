package sts

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/ericnorris/github-app-sts/internal/server/github"
	"github.com/ericnorris/github-app-sts/internal/server/oidc"
	"github.com/ericnorris/github-app-sts/internal/server/policy"
)

type ValidationError struct {
	message string
	cause   error
}

func (e *ValidationError) Error() string { return e.message }
func (e *ValidationError) Unwrap() error { return e.cause }

type Service struct {
	verifier *oidc.Verifier
	loader   *policy.Loader

	apps map[int64]github.InstallationTokenSource
}

func New(verifier *oidc.Verifier, loader *policy.Loader, apps map[int64]github.InstallationTokenSource) *Service {
	return &Service{
		verifier,
		loader,
		apps,
	}
}

func (s *Service) ExchangeToken(ctx context.Context, subjectToken, resource, scope string) (*github.InstallationToken, error) {
	issuer, err := s.verifier.ExtractIssuer(subjectToken)

	if err != nil {
		return nil, &ValidationError{"invalid subject token", err}
	}

	parsedResource, err := parseResource(resource)

	if err != nil {
		return nil, &ValidationError{"invalid resource", err}
	}

	parsedScope, err := parseScope(scope)

	if err != nil {
		return nil, &ValidationError{"invalid scope", err}
	}

	var pol *policy.Policy

	if parsedResource.repo == "" {
		pol, err = s.loader.LoadOrganizationPolicy(ctx, parsedResource.org, string(parsedScope))
	} else {
		pol, err = s.loader.LoadRepositoryPolicy(ctx, parsedResource.org, parsedResource.repo, string(parsedScope))
	}

	if err != nil {
		return nil, fmt.Errorf("could not load policy: %w", err)
	}

	if err := s.verifier.Verify(ctx, issuer, subjectToken, pol); err != nil {
		return nil, fmt.Errorf("rejected by verifier: %w", err)
	}

	tokenSource, ok := s.apps[pol.AppID]

	if !ok {
		return nil, fmt.Errorf("policy references unknown app: %d", pol.AppID)
	}

	return tokenSource.Token(ctx, pol.Repositories, pol.Permissions)
}

type parsedResource struct {
	org  string
	repo string
}

func parseResource(resource string) (*parsedResource, error) {
	u, err := url.Parse(resource)

	if err != nil {
		return nil, fmt.Errorf("resource is not a valid URL: %w", err)
	}

	if u.Scheme != "https" {
		return nil, fmt.Errorf("resource must use HTTPS scheme, got: %q", u.Scheme)
	}

	if u.Host != "github.com" {
		return nil, fmt.Errorf("resource host must be github.com, got: %q", u.Host)
	}

	cleanedPath := path.Clean(u.Path)

	if cleanedPath != u.Path {
		return nil, errors.New("resource path must not contain path traversal")
	}

	// remove the leading '/' (e.g. /myorg/repo), then split into ['myorg', 'repo']
	parts := strings.Split(strings.TrimPrefix(cleanedPath, "/"), "/")

	switch len(parts) {
	case 1:
		// org scope: https://github.com/{owner}
		return &parsedResource{parts[0], ""}, nil

	case 2:
		// repo scope: https://github.com/{owner}/{repo}
		return &parsedResource{parts[0], parts[1]}, nil

	default:
		return nil, fmt.Errorf("resource path must have 1 or 2 segments (org or org/repo), got: %d", len(parts))
	}
}

type parsedScope string

func parseScope(scope string) (parsedScope, error) {
	p := path.Clean(scope)

	if p != scope {
		return "", errors.New("scope must not contain path traversal")
	}

	return parsedScope(p), nil
}
