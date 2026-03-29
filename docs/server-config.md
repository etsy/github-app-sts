# Server Configuration Reference

The server is configured with a YAML file, passed via `--config`:

```shell
github-app-sts-server --config config.yaml
```

## Full Example

```yaml
audience: "https://sts.example.com"
port: 8080

allowed_issuers:
  - "https://token.actions.githubusercontent.com"

policy_reader_app:
  client_id: "123456"
  private_key:
    google_kms: "projects/my-project/locations/us-central1/keyRings/github/cryptoKeys/sts-reader/cryptoKeyVersions/1"
  installations:
    my-org: 22222

sts_target_apps:
  deploy-bot:
    client_id: "789012"
    private_key:
      env_var: "DEPLOY_BOT_PRIVATE_KEY"
    installations:
      my-org: 33333
  ci-bot:
    client_id: "345678"
    private_key:
      file: "/etc/sts/ci-bot.pem"
    installations:
      my-org: 44444

org_policy_repos:
  my-org: ".github-sts"
```

## Fields

### `audience` (required)

The expected OIDC `aud` claim value. OIDC tokens must contain this value in their audience claim. This should be the public URL of your STS server.

```yaml
audience: "https://sts.example.com"
```

### `port` (required)

The HTTP port the server listens on.

```yaml
port: 8080
```

### `allowed_issuers` (required)

A list of OIDC issuer URLs the server will accept tokens from. Tokens from unlisted issuers are rejected immediately, before any outbound requests are made.

Must contain at least one entry.

```yaml
allowed_issuers:
  - "https://token.actions.githubusercontent.com"
```

### `policy_reader_app` (required)

The GitHub App used to read policy files from repositories. This app only needs `contents: read` permission.

See [App Configuration](#app-configuration) below.

### `sts_target_apps` (required)

A map of named GitHub Apps that policies can mint tokens for. Each key is an alias referenced by the `target_app` field in policy files.

Must contain at least one entry.

```yaml
sts_target_apps:
  deploy-bot:
    client_id: "789012"
    private_key:
      file: "/etc/sts/deploy-bot.pem"
    installations:
      my-org: 33333
```

### `org_policy_repos` (optional)

Maps organization names to the repository that holds their organization-level policies. If not set, only repository-level policies are supported.

```yaml
org_policy_repos:
  my-org: ".github-sts"
```

## App Configuration

Both `policy_reader_app` and each entry in `sts_target_apps` share the same structure.

### `client_id` (required)

The GitHub App's client ID.

### `installations` (required)

A map of organization names to their installation IDs for this app. Must contain at least one entry.

```yaml
installations:
  my-org: 12345
  other-org: 67890
```

### `private_key` (required)

Specifies how to obtain the app's private key for signing JWTs. Exactly one of the following must be set:

#### `google_kms`

A full Google Cloud KMS CryptoKeyVersion resource name.

```yaml
private_key:
  google_kms: "projects/my-project/locations/us-central1/keyRings/github/cryptoKeys/my-key/cryptoKeyVersions/1"
```

#### `env_var`

The name of an environment variable containing a PEM-encoded private key.

```yaml
private_key:
  env_var: "MY_APP_PRIVATE_KEY"
```

#### `file`

A path to a PEM-encoded private key file.

```yaml
private_key:
  file: "/etc/sts/my-app.pem"
```
