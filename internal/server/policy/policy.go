package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ericnorris/github-app-sts/internal/server/github"
	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

type FileReader interface {
	ReadFile(ctx context.Context, owner, repo, path string) ([]byte, error)
}

type Loader struct {
	reader        FileReader
	orgPolicyRepo string
}

func NewLoader(reader FileReader, orgPolicyRepo string) *Loader {
	return &Loader{reader, orgPolicyRepo}
}

func (l *Loader) LoadRepositoryPolicy(ctx context.Context, owner, repo, name string) (*Policy, error) {
	path := fmt.Sprintf(".github/sts/%s.yaml", name)

	policyContents, err := l.reader.ReadFile(ctx, owner, repo, path)

	if err != nil {
		var ghNotFound *github.FileNotFoundError

		if errors.As(err, &ghNotFound) {
			return nil, &NotFoundError{err}
		}

		return nil, fmt.Errorf("loading policy file: %w", err)
	}

	var rp struct {
		AppID       int64             `yaml:"app_id"`
		Issuer      string            `yaml:"issuer"`
		Subject     string            `yaml:"subject"`
		Claims      string            `yaml:"claims,omitempty"`
		Permissions map[string]string `yaml:"permissions"`
	}

	if err := yaml.Unmarshal([]byte(policyContents), &rp); err != nil {
		return nil, fmt.Errorf("could not parse repository policy: %w", err)
	}

	for name := range rp.Permissions {
		if isOrganizationPermission(name) {
			return nil, fmt.Errorf("repository policies cannot contain organization permission '%q'", name)
		}
	}

	return NewPolicy(
		rp.AppID,
		rp.Issuer,
		rp.Subject,
		rp.Claims,
		rp.Permissions,
		[]string{repo},
	)
}

func (l *Loader) LoadOrganizationPolicy(ctx context.Context, owner, name string) (*Policy, error) {
	path := fmt.Sprintf(".github/sts/%s.yaml", name)

	policyContents, err := l.reader.ReadFile(ctx, owner, l.orgPolicyRepo, path)

	if err != nil {
		var ghNotFound *github.FileNotFoundError

		if errors.As(err, &ghNotFound) {
			return nil, &NotFoundError{err}
		}

		return nil, fmt.Errorf("loading policy file: %w", err)
	}

	var op struct {
		AppID        int64             `yaml:"app_id"`
		Issuer       string            `yaml:"issuer"`
		Subject      string            `yaml:"subject"`
		Claims       string            `yaml:"claims,omitempty"`
		Permissions  map[string]string `yaml:"permissions"`
		Repositories []string          `yaml:"repositories"`
	}

	if err := yaml.Unmarshal(policyContents, &op); err != nil {
		return nil, fmt.Errorf("could not parse organization policy: %w", err)
	}

	return NewPolicy(
		op.AppID,
		op.Issuer,
		op.Subject,
		op.Claims,
		op.Permissions,
		op.Repositories,
	)
}

type NotFoundError struct {
	Err error
}

func (e *NotFoundError) Error() string { return "policy not found" }
func (e *NotFoundError) Unwrap() error { return e.Err }

type Policy struct {
	AppID   int64
	Issuer  string
	Subject *regexp.Regexp
	Claims  cel.Program

	Permissions  map[string]string
	Repositories []string
}

func (p *Policy) EvaluateClaims(claims map[string]any) (bool, error) {
	if p.Claims == nil {
		return true, nil
	}

	out, _, err := p.Claims.Eval(map[string]any{
		"claims": claims,
	})

	if err != nil {
		return false, fmt.Errorf("could not evaluate 'claims' expression: %w", err)
	}

	// SAFETY: we've enforced that this must be a bool in the NewPolicy method.
	return out.Value().(bool), nil
}

func NewPolicy(
	appID int64,
	issuer string,
	subject string,
	claims string,
	permissions map[string]string,
	repositories []string,
) (*Policy, error) {
	subjectRegex, err := regexp.Compile("^" + subject + "$")

	if err != nil {
		return nil, fmt.Errorf("could not compile subject pattern: %w", err)
	}

	p := &Policy{
		AppID:        appID,
		Issuer:       issuer,
		Subject:      subjectRegex,
		Permissions:  permissions,
		Repositories: repositories,
	}

	if claims == "" {
		return p, nil
	}

	env, err := cel.NewEnv(
		cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
	)

	if err != nil {
		return nil, fmt.Errorf("could not create CEL environment: %w", err)
	}

	ast, iss := env.Compile(claims)

	if iss.Err() != nil {
		return nil, fmt.Errorf("could not compile CEL expression: %w", iss.Err())
	}

	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("CEL expression must return a bool, got %s", ast.OutputType())
	}

	program, err := env.Program(ast)

	if err != nil {
		return nil, fmt.Errorf("could not create CEL program: %w", err)
	}

	p.Claims = program

	return p, nil
}

// Organization permissions that are not prefixed with "organization_".
var organizationPermissions = map[string]bool{
	"administration":                                 true,
	"custom_properties_for_organizations":            true,
	"enterprise_custom_properties_for_organizations": true,
	"members": true,
	"plan":    true,
}

func isOrganizationPermission(name string) bool {
	return strings.HasPrefix(name, "organization_") || organizationPermissions[name]
}
