package config

import (
	"os"
	"path/filepath"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func validConfig() *Config {
	return &Config{
		Audience:       ptr("https://sts.example.com"),
		Port:           ptr(8080),
		AllowedIssuers: []string{"https://token.actions.githubusercontent.com"},
		PolicyReaderApp: &AppConfig{
			ClientID:   ptr("1"),
			PrivateKey: PrivateKeyConfig{File: "/path/to/key.pem"},
			Installations: map[string]int64{
				"myorg": 12345,
			},
		},
		STSTargetApps: []AppConfig{
			{
				ClientID:   ptr("2"),
				PrivateKey: PrivateKeyConfig{File: "/path/to/key2.pem"},
				Installations: map[string]int64{
					"myorg": 67890,
				},
			},
		},
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		if err := validConfig().validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	invalid := []struct {
		name   string
		mutate func(*Config)
	}{
		{"missing audience", func(c *Config) { c.Audience = nil }},
		{"empty audience", func(c *Config) { c.Audience = ptr("") }},
		{"missing port", func(c *Config) { c.Port = nil }},
		{"missing allowed_issuers", func(c *Config) { c.AllowedIssuers = nil }},
		{"empty allowed_issuers", func(c *Config) { c.AllowedIssuers = []string{} }},
		{"empty issuer entry", func(c *Config) { c.AllowedIssuers = []string{""} }},
		{"missing policy_reader_app", func(c *Config) { c.PolicyReaderApp = nil }},
		{"missing policy_reader_app id", func(c *Config) { c.PolicyReaderApp.ClientID = nil }},
		{"missing policy_reader_app installations", func(c *Config) { c.PolicyReaderApp.Installations = nil }},
		{"no private key source", func(c *Config) { c.PolicyReaderApp.PrivateKey = PrivateKeyConfig{} }},
		{"multiple private key sources", func(c *Config) {
			c.PolicyReaderApp.PrivateKey = PrivateKeyConfig{File: "a", EnvVar: "B"}
		}},
		{"empty sts_target_apps", func(c *Config) { c.STSTargetApps = []AppConfig{} }},
		{"missing sts_target_app id", func(c *Config) { c.STSTargetApps[0].ClientID = nil }},
		{"empty org_policy_repo value", func(c *Config) { c.OrgPolicyRepos = map[string]string{"org": ""} }},
	}

	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(cfg)

			if err := cfg.validate(); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestValidatePrivateKeyVariants(t *testing.T) {
	variants := []struct {
		name string
		pk   PrivateKeyConfig
	}{
		{"file", PrivateKeyConfig{File: "/path/to/key.pem"}},
		{"env_var", PrivateKeyConfig{EnvVar: "MY_KEY"}},
		{"google_kms", PrivateKeyConfig{GoogleKMS: "projects/p/locations/l/keyRings/kr/cryptoKeys/k/cryptoKeyVersions/1"}},
	}

	for _, tt := range variants {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.PolicyReaderApp.PrivateKey = tt.pk

			if err := cfg.validate(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	t.Run("valid file", func(t *testing.T) {
		content := `
audience: "https://sts.example.com"
port: 8080
allowed_issuers:
  - "https://token.actions.githubusercontent.com"
policy_reader_app:
  client_id: 1
  private_key:
    file: "/path/to/key.pem"
  installations:
    myorg: 12345
sts_target_apps:
  - client_id: 2
    private_key:
      file: "/path/to/key2.pem"
    installations:
      myorg: 67890
`
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte(content), 0644)

		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if *cfg.Audience != "https://sts.example.com" {
			t.Errorf("audience = %q, want %q", *cfg.Audience, "https://sts.example.com")
		}

		if *cfg.Port != 8080 {
			t.Errorf("port = %d, want %d", *cfg.Port, 8080)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := Load("/nonexistent/config.yaml"); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("invalid yaml", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte(":::"), 0644)

		if _, err := Load(path); err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("validation failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		os.WriteFile(path, []byte("port: 8080\n"), 0644)

		if _, err := Load(path); err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
