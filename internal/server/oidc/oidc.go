package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"go.opentelemetry.io/otel"

	"github.com/etsy/github-app-sts/internal/server/policy"
)

var tracer = otel.Tracer("github-app-sts/oidc")

type Verifier struct {
	verifiers map[string]*oidc.IDTokenVerifier
}

func NewVerifier(ctx context.Context, issuers []string, audience string, client *http.Client) (*Verifier, error) {
	verifiers := make(map[string]*oidc.IDTokenVerifier)

	if client != nil {
		ctx = oidc.ClientContext(ctx, client)
	}

	for _, issuer := range issuers {
		provider, err := oidc.NewProvider(ctx, issuer)

		if err != nil {
			return nil, fmt.Errorf("could not construct OIDC provider for '%s': %w", issuer, err)
		}

		// Note: the context is apparently only used for extracting the http client from the context, set above.
		verifiers[issuer] = provider.VerifierContext(ctx, &oidc.Config{
			// It's a little weird that this is passed in as the ClientID, but it is the expected audience of the
			// token.
			ClientID: audience,
		})
	}

	return &Verifier{verifiers}, nil
}

func (v *Verifier) ExtractIssuer(token string) (string, error) {
	parts := strings.SplitN(token, ".", 3)

	if len(parts) != 3 {
		return "", errors.New("could not extract issuer from OIDC token: incorrect number of parts")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])

	if err != nil {
		return "", fmt.Errorf("could not extract issuer from OIDC token: %w", err)
	}

	var claims struct {
		Issuer string `json:"iss"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("could not extract issuer from OIDC token: %w", err)
	}

	if claims.Issuer == "" {
		return "", errors.New("could not extract issuer from OIDC token: missing 'iss' claim")
	}

	return claims.Issuer, nil
}

func (v *Verifier) Verify(ctx context.Context, issuer, unverifiedToken string, policy *policy.Policy) error {
	ctx, span := tracer.Start(ctx, "oidc.verify")
	defer span.End()

	verifier, ok := v.verifiers[issuer]

	if !ok {
		return fmt.Errorf("could not verify OIDC token: issuer '%s' not in allowed issuers", issuer)
	}

	token, err := verifier.Verify(ctx, unverifiedToken)

	if err != nil {
		return fmt.Errorf("could not verify OIDC token: %w", err)
	}

	if policy.Issuer != token.Issuer {
		return fmt.Errorf("could not verify OIDC token: policy does not allow the given issuer '%s'", token.Issuer)
	}

	if !policy.Subject.Match([]byte(token.Subject)) {
		return fmt.Errorf("could not verify OIDC token: policy does not allow the given subject '%s'", token.Subject)
	}

	var claims map[string]any

	if err := token.Claims(&claims); err != nil {
		return fmt.Errorf("could not verify OIDC token: %w", err)
	}

	if ok, err := policy.EvaluateCondition(claims); err != nil {
		return fmt.Errorf("could not verify OIDC token: %w", err)
	} else if !ok {
		return errors.New("could not verify OIDC token: token is not allowed by the 'condition' expression in the policy")
	}

	return nil
}
