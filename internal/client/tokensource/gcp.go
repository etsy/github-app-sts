package tokensource

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"google.golang.org/api/idtoken"
)

var (
	newIDTokenSource = idtoken.NewTokenSource
	metadataGet      = metadata.GetWithContext
)

// FromGCP fetches an OIDC identity token using GCP Application Default
// Credentials. This works on GCE, Cloud Run, GKE, and anywhere a service
// account key or workload identity federation is configured.
func FromGCP(ctx context.Context, audience string) (string, error) {
	ts, err := newIDTokenSource(ctx, audience)

	if err != nil {
		if isUnsupportedAuthorizedUser(err) {
			return fromGCPMetadata(ctx, audience)
		}

		return "", fmt.Errorf("creating GCP token source: %w", err)
	}

	token, err := ts.Token()

	if err != nil {
		return "", fmt.Errorf("fetching GCP identity token: %w", err)
	}

	// it's a little weird, but the ID token is set as the access token field
	if token.AccessToken == "" {
		return "", fmt.Errorf("GCP token source returned an empty token")
	}

	return token.AccessToken, nil
}

func isUnsupportedAuthorizedUser(err error) bool {
	errString := err.Error()
	return strings.Contains(errString, "unsupported credentials type") && strings.Contains(errString, "authorized_user")
}

func fromGCPMetadata(ctx context.Context, audience string) (string, error) {
	v := url.Values{}
	v.Set("audience", audience)
	v.Set("format", "full")

	token, err := metadataGet(ctx, "instance/service-accounts/default/identity?"+v.Encode())

	if err != nil {
		return "", fmt.Errorf("fetching GCP identity token from metadata server: %w", err)
	}

	if token == "" {
		return "", fmt.Errorf("GCP metadata server returned an empty token")
	}

	return token, nil
}
