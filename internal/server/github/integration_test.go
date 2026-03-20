package github_test

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/ericnorris/github-app-sts/internal/server/github"
	"github.com/ericnorris/github-app-sts/internal/server/github/appkey"
)

const (
	FileReaderTestPath    = ".github/this-file-is-used-in-an-integration-test"
	FileReaderTestContent = "this-is-a-well-known-string\n"
)

func mustGetenv(t *testing.T, key string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}

	t.Fatalf("missing or empty environment variable '%s'", key)

	return ""
}

func TestFileReaderIntegration(t *testing.T) {
	if _, ok := os.LookupEnv("GITHUB_INTEGRATION_TEST"); !ok {
		t.Skip("set GITHUB_INTEGRATION_TEST to run")
	}

	clientID := mustGetenv(t, "GITHUB_APP_CLIENT_ID")
	privateKey := mustGetenv(t, "GITHUB_APP_PRIVATE_KEY")
	installationID := mustGetenv(t, "GITHUB_APP_INSTALLATION_ID")
	owner := mustGetenv(t, "GITHUB_INTEGRATION_TEST_OWNER")
	repo := mustGetenv(t, "GITHUB_INTEGRATION_TEST_REPO")

	key, err := appkey.NewRSA(clientID, []byte(privateKey))

	if err != nil {
		t.Fatalf("creating RSA key: %v", err)
	}

	reader := github.NewFileReader(
		github.NewInstallationTokenSource(
			github.NewAppTokenSource(key),
			owner,
			installationID,
			nil,
		),
		nil,
	)

	content, err := reader.ReadFile(context.Background(), repo, FileReaderTestPath)

	if err != nil {
		t.Fatalf("reading file: %v", err)
	}

	if !bytes.Equal(content, []byte(FileReaderTestContent)) {
		t.Errorf("got %q, want %q", content, FileReaderTestContent)
	}
}
