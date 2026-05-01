package tokensource

import (
	"context"
	"fmt"

	"google.golang.org/api/idtoken"
)

// FromGCP fetches an OIDC identity token using GCP Application Default
// Credentials. This works on GCE, Cloud Run, GKE, and anywhere a service
// account key or workload identity federation is configured.
func FromGCP(ctx context.Context, audience string) (string, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience)

	if err != nil {
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
