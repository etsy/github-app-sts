# Policy Reference

Policies are YAML files that control which OIDC identities can exchange tokens and what permissions those tokens receive. There are two types: **repository policies** and **organization policies**.

## Repository Policies

Repository policies live in the target repository at `.github/sts/<name>.yaml`. They grant access to that repository only.

### Example

```yaml
target_app: deploy-bot

identities:
  - issuer: "https://token.actions.githubusercontent.com"
    subject: "^repo:my-org/my-repo:ref:refs/heads/main$"

permissions:
  contents: read
  pull_requests: write
```

### Restrictions

Repository policies **cannot** grant organization-level permissions. The following permissions are rejected:

- Any permission prefixed with `organization_` (e.g., `organization_hooks`, `organization_administration`)
- `members`
- `administration`
- `plan`
- `custom_properties_for_organizations`
- `enterprise_custom_properties_for_organizations`

This prevents repositories from escalating their access to organization-level operations via a GitHub App.

## Organization Policies

Organization policies live in a dedicated policy repository (configured via `org_policy_repos` in the [server config](server-config.md)). They can grant access across multiple repositories and can include organization-level permissions.

### Example

```yaml
target_app: deploy-bot

identities:
  - issuer: "https://token.actions.githubusercontent.com"
    subject: "^repo:my-org/deploy-service:.*$"
    condition: claims.ref == "refs/heads/main"

permissions:
  contents: write

repositories:
  - my-org/app-frontend
  - my-org/app-backend
```

### `repositories` (optional)

A list of repositories the minted token will have access to. This field is only available in organization policies. If omitted, the token will have access to all repositories where the target app is installed.

## Fields

### `target_app` (required)

The name of the GitHub App to mint a token for. Must match a key in `sts_target_apps` from the server config.

```yaml
target_app: deploy-bot
```

### `identities` (required)

A list of OIDC identities allowed to use this policy. At least one identity is required. If any identity matches, the token exchange is permitted.

Each identity has the following fields:

#### `issuer` (required)

The expected OIDC issuer URL. Must exactly match the `iss` claim in the token.

```yaml
issuer: "https://token.actions.githubusercontent.com"
```

#### `subject` (required)

A regular expression matched against the token's `sub` claim. The pattern is automatically anchored with `^` and `$`, so `repo:my-org/.*` is equivalent to `^repo:my-org/.*$`.

```yaml
subject: "repo:my-org/my-repo:ref:refs/heads/main"
```

For more advanced use-cases, you can match all subjects with `.*` and use a `condition` to restrict access instead:

```yaml
subject: ".*"
condition: claims.sub.matches("^repo:" + repository + ":.*$")
```

#### `condition` (optional)

A [CEL](https://cel.dev/) expression for additional claim validation. Must evaluate to a boolean. The following variables are available:

- `claims` (`map[string]any`) — all claims from the OIDC token
- `owner` (`string`) — the organization or owner name
- `repository` (`string`) — the full repository path (e.g., `my-org/my-repo`)

Examples:

```yaml
# Only allow the main branch
condition: claims.ref == "refs/heads/main"

# Ensure the subject claim contains the target repository
condition: claims.sub.matches("^repo:" + repository + ":.*$")

# Restrict to a specific workflow (use workflow_ref, not workflow — the workflow
# claim contains the workflow's name: field, not the filename)
condition: claims.workflow_ref == "my-org/my-repo/.github/workflows/deploy.yml@refs/heads/main"
```

### `permissions` (required)

A map of GitHub App permissions to grant on the minted token. Keys are permission names and values are access levels (typically `read` or `write`).

```yaml
permissions:
  contents: read
  issues: write
  pull_requests: write
```
