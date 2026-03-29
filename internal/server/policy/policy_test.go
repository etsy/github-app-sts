package policy

import (
	"context"
	"fmt"
	"testing"
)

type fakeFileReader struct {
	files map[string][]byte
}

func (f *fakeFileReader) ReadFile(_ context.Context, repo, path string) ([]byte, error) {
	key := fmt.Sprintf("%s/%s", repo, path)

	contents, ok := f.files[key]
	if !ok {
		return nil, fmt.Errorf("file not found: %s", key)
	}

	return contents, nil
}

func TestLoadRepositoryPolicy(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid policy",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  contents: read
  issues: write
`,
		},
		{
			name: "valid policy with CEL claims",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:.*
claims: claims.ref == "refs/heads/main"
permissions:
  contents: read
`,
		},
		{
			name: "rejects organization_ prefixed permission",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  organization_hooks: read
`,
			wantErr: true,
		},
		{
			name: "rejects members permission",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  members: read
`,
			wantErr: true,
		},
		{
			name: "rejects administration permission",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
permissions:
  administration: read
`,
			wantErr: true,
		},
		{
			name: "invalid subject regex",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: "repo:myorg/myrepo:ref:refs/heads/[invalid"
permissions:
  contents: read
`,
			wantErr: true,
		},
		{
			name: "invalid CEL expression",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:.*
claims: not a valid expression !!!
permissions:
  contents: read
`,
			wantErr: true,
		},
		{
			name: "CEL expression must return bool",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:.*
claims: claims.ref
permissions:
  contents: read
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &fakeFileReader{
				files: map[string][]byte{
					"myrepo/.github/sts/test.yaml": []byte(tt.yaml),
				},
			}

			loader := NewLoader(reader, "")

			policy, err := loader.LoadRepositoryPolicy(context.Background(), "myrepo", "test")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if policy.TargetApp != "deploy-bot" {
				t.Errorf("TargetApp = %s, want 'deploy-bot'", policy.TargetApp)
			}

			if policy.Issuer != "https://token.actions.githubusercontent.com" {
				t.Errorf("Issuer = %q, want %q", policy.Issuer, "https://token.actions.githubusercontent.com")
			}

			if len(policy.Repositories) != 1 || policy.Repositories[0] != "myrepo" {
				t.Errorf("Repositories = %v, want [myrepo]", policy.Repositories)
			}
		})
	}
}

func TestLoadOrganizationPolicy(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid org policy with org permissions",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/.*:ref:refs/heads/main
permissions:
  contents: read
  members: read
  organization_hooks: read
repositories:
  - myorg/repo-a
  - myorg/repo-b
`,
		},
		{
			name: "valid org policy without repositories",
			yaml: `
target_app: deploy-bot
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/.*:ref:refs/heads/main
permissions:
  contents: read
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &fakeFileReader{
				files: map[string][]byte{
					"org-policies/.github/sts/test.yaml": []byte(tt.yaml),
				},
			}

			loader := NewLoader(reader, "org-policies")

			policy, err := loader.LoadOrganizationPolicy(context.Background(), "test")

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if policy.TargetApp != "deploy-bot" {
				t.Errorf("TargetApp = %s, want 'deploy-bot'", policy.TargetApp)
			}
		})
	}
}

func TestIsOrganizationPermission(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"contents", false},
		{"issues", false},
		{"pull_requests", false},
		{"members", true},
		{"administration", true},
		{"plan", true},
		{"custom_properties_for_organizations", true},
		{"enterprise_custom_properties_for_organizations", true},
		{"organization_hooks", true},
		{"organization_administration", true},
		{"organization_projects", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOrganizationPermission(tt.name); got != tt.want {
				t.Errorf("isOrganizationPermission(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
