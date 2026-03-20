package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the STS server.
type Config struct {
	// Audience is the expected OIDC audience value (e.g., "https://sts.example.com"). OIDC tokens must have this value
	// in their "aud" claim to be accepted.
	Audience *string `yaml:"audience"`

	// Port is the HTTP port to listen on.
	Port *int `yaml:"port"`

	// AllowedIssuers is the list of OIDC issuer URLs that the STS will accept tokens from. Tokens from issuers not on
	// this list are rejected before any outbound requests are made.
	AllowedIssuers []string `yaml:"allowed_issuers"`

	// PolicyReaderApp is the GitHub App used by the STS for reading policy files and finding installations. This needs
	// `contents: "read"` permissions on any repository that is expected to contain a policy.
	PolicyReaderApp *AppConfig `yaml:"policy_reader_app"`

	// STSTargetApps are the GitHub Apps that policies can mint tokens for. Each policy specifies an app_id that must
	// match one of these.
	STSTargetApps []AppConfig `yaml:"sts_target_apps"`

	// OrgPolicyRepos maps organization names to their policy repository.
	OrgPolicyRepos map[string]string `yaml:"org_policy_repos"`
}

// AppConfig configures a single GitHub App.
type AppConfig struct {
	// ClientID is the numeric GitHub App ClientID.
	ClientID *string `yaml:"client_id"`

	// PrivateKey specifies how to obtain the App's private key for JWT signing.
	PrivateKey PrivateKeyConfig `yaml:"private_key"`

	// Installations maps organization names to their installation IDs.
	Installations map[string]int64 `yaml:"installations"`
}

// PrivateKeyConfig specifies the source for a GitHub App's private key.
// Exactly one field must be set.
type PrivateKeyConfig struct {
	// GoogleKMS is the full GCP KMS CryptoKeyVersion resource name. For example:
	//   projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<key>/cryptoKeyVersions/<version>
	GoogleKMS string `yaml:"google_kms,omitempty"`

	// EnvVar is the name of an environment variable containing the PEM-encoded private key.
	EnvVar string `yaml:"env_var,omitempty"`

	// File is the path to a PEM-encoded private key file.
	File string `yaml:"file,omitempty"`
}

// Load reads and parses a configuration file at the given path,
// applies environment variable overrides, and validates the result.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// validate checks that the configuration is well-formed.
func (c *Config) validate() error {
	var errs []error

	if c.Audience == nil {
		errs = append(errs, errors.New("'audience' is required"))
	} else if *c.Audience == "" {
		errs = append(errs, errors.New("'audience' must not be empty"))
	}

	if c.Port == nil {
		errs = append(errs, errors.New("'port' is required"))
	}

	if err := c.validateAllowedIssuers(); err != nil {
		errs = append(errs, err)
	}

	if innerErrs := c.PolicyReaderApp.validate("policy_reader_app"); len(innerErrs) != 0 {
		errs = append(errs, innerErrs...)
	}

	if innerErrs := c.validateSTSTargetApps(); len(innerErrs) != 0 {
		errs = append(errs, innerErrs...)
	}

	for org, repo := range c.OrgPolicyRepos {
		if repo == "" {
			errs = append(errs, fmt.Errorf("org_policy_repos[%s]: must not be empty", org))
		}
	}

	return errors.Join(errs...)
}

func (c *Config) validateAllowedIssuers() error {
	if c.AllowedIssuers == nil {
		return errors.New("'allowed_issuers' is required")
	}

	if len(c.AllowedIssuers) == 0 {
		return errors.New("'allowed_issuers' must contain at least one issuer")
	}

	for i, iss := range c.AllowedIssuers {
		if iss == "" {
			return fmt.Errorf("'allowed_issuers[%d]': must not be empty", i)
		}
	}

	return nil
}

func (c *Config) validateSTSTargetApps() []error {
	errs := []error{}

	if len(c.STSTargetApps) == 0 {
		return append(errs, errors.New("at least one sts_target_app must be configured"))
	}

	for i, app := range c.STSTargetApps {
		errs = append(errs, app.validate(fmt.Sprintf("'sts_target_apps[%d]'", i))...)
	}

	return errs
}

func (c *AppConfig) validate(fieldName string) []error {
	errs := []error{}

	if c == nil {
		return append(errs, fmt.Errorf("'%s' is required", fieldName))
	}

	if c.ClientID == nil {
		errs = append(errs, fmt.Errorf("'%s.client_id' is required", fieldName))
	}

	if err := c.PrivateKey.validate(fieldName + ".private_key"); err != nil {
		errs = append(errs, err)
	}

	if len(c.Installations) == 0 {
		errs = append(errs, fmt.Errorf("'%s.installations': at least one installation is required", fieldName))
	}

	return errs
}

func (pk *PrivateKeyConfig) validate(fieldName string) error {
	count := 0

	if pk.GoogleKMS != "" {
		count++
	}

	if pk.EnvVar != "" {
		count++
	}

	if pk.File != "" {
		count++
	}

	switch count {
	case 0:
		return fmt.Errorf("'%s': exactly one of google_kms, env_var, or file must be set", fieldName)

	case 1:
		return nil

	default:
		return fmt.Errorf("'%s': only one of google_kms, env_var, or file may be set", fieldName)
	}
}
