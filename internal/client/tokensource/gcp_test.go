package tokensource

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/oauth2"
	"google.golang.org/api/idtoken"
)

func TestFromGCPFallsBackToMetadataForAuthorizedUserCredentials(t *testing.T) {
	tests := []struct {
		name string
		err  string
	}{
		{"unquoted", "idtoken: unsupported credentials type: authorized_user"},
		{"quoted", "idtoken: unsupported credentials type: \"authorized_user\""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGCPTestHooks(t)

			newIDTokenSource = func(_ context.Context, _ string, _ ...idtoken.ClientOption) (oauth2.TokenSource, error) {
				return nil, errors.New(tt.err)
			}

			var gotSuffix string
			metadataGet = func(_ context.Context, suffix string) (string, error) {
				gotSuffix = suffix
				return "metadata-token", nil
			}

			token, err := FromGCP(context.Background(), "https://sts.example/token")

			if err != nil {
				t.Fatalf("FromGCP returned error: %v", err)
			}

			if token != "metadata-token" {
				t.Fatalf("FromGCP token = %q, want %q", token, "metadata-token")
			}

			wantSuffix := "instance/service-accounts/default/identity?audience=https%3A%2F%2Fsts.example%2Ftoken&format=full"
			if gotSuffix != wantSuffix {
				t.Fatalf("metadata suffix = %q, want %q", gotSuffix, wantSuffix)
			}
		})
	}
}

func TestFromGCPDoesNotFallBackForOtherTokenSourceErrors(t *testing.T) {
	resetGCPTestHooks(t)

	newIDTokenSource = func(_ context.Context, _ string, _ ...idtoken.ClientOption) (oauth2.TokenSource, error) {
		return nil, errors.New("boom")
	}

	metadataGet = func(_ context.Context, _ string) (string, error) {
		t.Fatal("metadataGet should not be called")
		return "", nil
	}

	_, err := FromGCP(context.Background(), "https://sts.example/token")

	if err == nil {
		t.Fatal("FromGCP returned nil error")
	}
}

func resetGCPTestHooks(t *testing.T) {
	t.Helper()

	originalNewIDTokenSource := newIDTokenSource
	originalMetadataGet := metadataGet

	t.Cleanup(func() {
		newIDTokenSource = originalNewIDTokenSource
		metadataGet = originalMetadataGet
	})
}
