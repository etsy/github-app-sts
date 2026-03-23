package github_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/etsy/github-app-sts/internal/server/github"
	"github.com/etsy/github-app-sts/internal/testutil"
)

const (
	FileReaderTestPath    = ".github/this-file-is-used-in-an-integration-test"
	FileReaderTestContent = "this-is-a-well-known-string\n"
)

type staticTokenSource struct {
	owner string
	token string
}

func (s *staticTokenSource) Owner() string { return s.owner }

func (s *staticTokenSource) Token(_ context.Context, _ []string, _ github.Permissions) (*github.InstallationToken, error) {
	return &github.InstallationToken{
		AccessToken: s.token,
		ExpiresAt:   time.Now().Add(time.Hour),
	}, nil
}

func TestFileReaderIntegration(t *testing.T) {
	testutil.SkipUnlessIntegrationTest(t, "file_reader")

	token := testutil.MustGetenv(t, "GITHUB_TOKEN")
	owner := testutil.MustGetenv(t, "GITHUB_INTEGRATION_TEST_OWNER")
	repo := testutil.MustGetenv(t, "GITHUB_INTEGRATION_TEST_REPO")

	reader := github.NewFileReader(
		&staticTokenSource{owner: owner, token: token},
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
