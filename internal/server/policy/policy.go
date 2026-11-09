package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/etsy/github-app-sts/internal/server/github"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"go.yaml.in/yaml/v3"
)

type FileReader interface {
	Owner() string
	ReadFile(ctx context.Context, repo, path string) ([]byte, error)
}

type Loader struct {
	reader        FileReader
	orgPolicyRepo string
}

func NewLoader(reader FileReader, orgPolicyRepo string) *Loader {
	return &Loader{reader, orgPolicyRepo}
}

func (l *Loader) LoadRepositoryPolicy(ctx context.Context, repo, name string) (*Policy, error) {
	path := fmt.Sprintf(".github/sts/%s.yaml", name)

	policyContents, err := l.reader.ReadFile(ctx, repo, path)

	if err != nil {
		var ghNotFound *github.FileNotFoundError

		if errors.As(err, &ghNotFound) {
			return nil, &NotFoundError{err}
		}

		return nil, fmt.Errorf("loading policy file: %w", err)
	}

	var rp struct {
		TargetApp  string            `yaml:"target_app"`
		Identities []IdentityConfig    `yaml:"identities"`
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
		rp.TargetApp,
		rp.Identities,
		rp.Permissions,
		[]string{repo},
		l.reader.Owner(),
		l.reader.Owner()+"/"+repo,
	)
}

func (l *Loader) LoadOrganizationPolicy(ctx context.Context, name string) (*Policy, error) {
	path := fmt.Sprintf(".github/sts/%s.yaml", name)

	policyContents, err := l.reader.ReadFile(ctx, l.orgPolicyRepo, path)

	if err != nil {
		var ghNotFound *github.FileNotFoundError

		if errors.As(err, &ghNotFound) {
			return nil, &NotFoundError{err}
		}

		return nil, fmt.Errorf("loading policy file: %w", err)
	}

	var op struct {
		TargetApp    string            `yaml:"target_app"`
		Identities   []IdentityConfig    `yaml:"identities"`
		Permissions  map[string]string `yaml:"permissions"`
		Repositories []string          `yaml:"repositories"`
	}

	if err := yaml.Unmarshal(policyContents, &op); err != nil {
		return nil, fmt.Errorf("could not parse organization policy: %w", err)
	}

	return NewPolicy(
		op.TargetApp,
		op.Identities,
		op.Permissions,
		op.Repositories,
		l.reader.Owner(),
		l.reader.Owner()+"/"+l.orgPolicyRepo,
	)
}

type NotFoundError struct {
	Err error
}

func (e *NotFoundError) Error() string { return "policy not found" }
func (e *NotFoundError) Unwrap() error { return e.Err }

type IdentityConfig struct {
	Issuer    string `yaml:"issuer"`
	Subject   string `yaml:"subject"`
	Condition string `yaml:"condition,omitempty"`
}

type Identity struct {
	Issuer    string
	Subject   *regexp.Regexp
	Condition cel.Program
}

func newIdentity(issuer, subject, condition, owner, repository string) (*Identity, error) {
	subjectRegex, err := regexp.Compile("^" + subject + "$")

	if err != nil {
		return nil, fmt.Errorf("could not compile subject pattern: %w", err)
	}

	id := &Identity{
		Issuer:  issuer,
		Subject: subjectRegex,
	}

	if condition == "" {
		return id, nil
	}

	env, err := cel.NewEnv(
		cel.Variable("claims", cel.MapType(cel.StringType, cel.DynType)),
		cel.Constant("owner", cel.StringType, types.String(owner)),
		cel.Constant("repository", cel.StringType, types.String(repository)),
	)

	if err != nil {
		return nil, fmt.Errorf("could not create CEL environment: %w", err)
	}

	ast, iss := env.Compile(condition)

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

	id.Condition = program

	return id, nil
}

func (id *Identity) EvaluateCondition(claims map[string]any) (bool, error) {
	if id.Condition == nil {
		return true, nil
	}

	out, _, err := id.Condition.Eval(map[string]any{
		"claims": claims,
	})

	if err != nil {
		return false, fmt.Errorf("could not evaluate 'condition' expression: %w", err)
	}

	// SAFETY: we've enforced that this must be a bool in NewIdentity.
	return out.Value().(bool), nil
}

type Policy struct {
	TargetApp    string
	Identities   []Identity
	Permissions  map[string]string
	Repositories []string
}

func NewPolicy(
	targetApp string,
	identities []IdentityConfig,
	permissions map[string]string,
	repositories []string,
	owner string,
	repository string,
) (*Policy, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("policy must have at least one identity")
	}

	ids := make([]Identity, 0, len(identities))

	for i, iy := range identities {
		id, err := newIdentity(iy.Issuer, iy.Subject, iy.Condition, owner, repository)

		if err != nil {
			return nil, fmt.Errorf("identity %d: %w", i, err)
		}

		ids = append(ids, *id)
	}

	return &Policy{
		TargetApp:    targetApp,
		Identities:   ids,
		Permissions:  permissions,
		Repositories: repositories,
	}, nil
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
