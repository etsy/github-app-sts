# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

GitHub App STS — a Secure Token Service that exchanges OIDC tokens for GitHub App installation access tokens via RFC 8693 token exchange. Policies (YAML + CEL expressions) stored in GitHub repositories control authorization.

## Build & Test Commands

### Go (server)

```bash
go build ./...                          # Build all packages
go test ./...                           # Run unit tests
go test ./... -v                        # Run unit tests (verbose)
go test ./internal/server/policy/ -v    # Run tests for a single package
go test -run TestName ./internal/...    # Run a specific test
INTEGRATION_TEST=all go test ./... -v   # Run all tests including integration (requires GitHub API access)
```

### TypeScript (GitHub Action, in `action/` directory)

```bash
cd action && npm install                # Install dependencies
cd action && npm run build              # Bundle with esbuild to dist/index.js
cd action && npm test                   # Run vitest tests
```

### Release

Uses GoReleaser (`.goreleaser.yaml`) for cross-platform builds and Docker images.

## Architecture

**Token exchange flow** (`POST /token`):
1. Extract OIDC issuer from JWT → validate against allowed issuers in server config
2. Parse resource URL (`https://github.com/{org}` or `https://github.com/{org}/{repo}`)
3. Load policy YAML from target repo (`.github/sts/{scope}.yaml`) or org policy repo
4. Verify OIDC token claims against policy (issuer, subject regex, CEL expressions)
5. Mint GitHub App installation token with policy-specified permissions
6. Return token per RFC 8693

**Key packages:**
- `cmd/github-app-sts-server/` — CLI entry point, accepts `--config` flag
- `internal/server/sts/` — Core token exchange orchestration
- `internal/server/policy/` — Policy loading and CEL-based evaluation
- `internal/server/oidc/` — OIDC token verification via `coreos/go-oidc/v3`
- `internal/server/github/` — GitHub API: app JWTs, installation tokens, file reading (all with LRU caching)
- `internal/server/github/appkey/` — Signing key abstraction (RSA file/env var, Google Cloud KMS)
- `internal/server/config/` — YAML server configuration with validation
- `internal/observability/` — OpenTelemetry tracing/metrics with auto-protocol detection
- `action/` — GitHub Action (TypeScript) that wraps the STS HTTP API

**Server config** (`docs/server-config.md`) defines: audience, port, allowed OIDC issuers, policy reader app, target apps (each with a signing key source), and org policy repos.

**Policy files** (`docs/policies.md`) define: `target_app` (alias matching a server config entry), `identities` (array of identity matchers, each with `issuer`, `subject` regex, and optional `condition` CEL expression using `claims`, `owner`, and `repository` variables), `permissions`, and `repositories` (org-level only).
