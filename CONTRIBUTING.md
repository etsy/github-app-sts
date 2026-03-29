# Contributing

## Building

```bash
go build ./...
```

### GitHub Action

```bash
cd action && npm install && npm run build
```

## Testing

### Unit tests

```bash
go test ./...                     # all Go unit tests
go test ./internal/server/policy/ # single package
cd action && npm test             # GitHub Action tests
```

### Integration tests

Integration tests use the GitHub API, and must have a functioning GitHub App configured.

#### GitHub App setup

You must create a GitHub app with at least the `contents: read` permission, and install it in the repository containing this code, e.g. your fork. Write down the **client ID** and **installation ID** (visible on the app's settings page after installation), and generate a **private key** (PEM format).

#### Running locally

```bash
TEST_APP_CLIENT_ID=Iv1.abc123 \
TEST_APP_INSTALLATION_ID=12345678 \
TEST_APP_OWNER=your-org-or-user \
TEST_APP_REPO=your-repo \
TEST_APP_PRIVATE_KEY="$(cat /path/to/private-key.pem)" \
INTEGRATION_TEST=all \
go test ./... -v
```

You can also run a subset of integration tests by setting `INTEGRATION_TEST` to a comma-separated list of test names (e.g., `INTEGRATION_TEST=server`).

#### Running in CI

The CI workflow (`.github/workflows/ci.yaml`) runs integration tests automatically. For forks, configure the following in your repository's **Settings > Secrets and variables > Actions**:

**Variables:**

| Name                       | Value                             |
| -------------------------- | --------------------------------- |
| `TEST_APP_CLIENT_ID`       | The GitHub App's client ID        |
| `TEST_APP_INSTALLATION_ID` | The installation ID for your fork |

**Secrets:**

| Name                   | Value                                     |
| ---------------------- | ----------------------------------------- |
| `TEST_APP_PRIVATE_KEY` | The GitHub App's private key (PEM format) |
