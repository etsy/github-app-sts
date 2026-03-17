package github

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ericnorris/github-app-sts/internal/server/github/appkey"
)

type AppTokenSource struct {
	key appkey.AppKey

	mutex sync.Mutex
	token *AppToken
}

func NewAppTokenSource(key appkey.AppKey) *AppTokenSource {
	return &AppTokenSource{key: key}
}

func (a *AppTokenSource) Token(ctx context.Context) (*AppToken, error) {
	now := time.Now()

	a.mutex.Lock()
	defer a.mutex.Unlock()

	if !a.token.Expired(now) {
		return a.token, nil
	}

	token, err := a.generateToken(ctx, now)

	if err != nil {
		return nil, err
	}

	a.token = token

	return a.token, nil
}

func (a *AppTokenSource) generateToken(ctx context.Context, now time.Time) (*AppToken, error) {
	// "To protect against clock drift, we recommend that you set this 60 seconds in the past [...]"
	iat := now.Add(-60 * time.Second)

	// "The time must be no more than 10 minutes into the future."
	exp := now.Add(540 * time.Second)

	// NOTE: this is infallible
	headerJSON, _ := json.Marshal(struct {
		Type      string `json:"typ"`
		Algorithm string `json:"alg"`
	}{
		"JWT",
		"RS256",
	})

	// NOTE: this is infallible
	claimsJSON, _ := json.Marshal(struct {
		IssuedAt       int64  `json:"iat"`
		ExpirationTime int64  `json:"exp"`
		Issuer         string `json:"iss"`
	}{
		iat.Unix(),
		exp.Unix(),
		a.key.ClientID(),
	})

	signingInput := fmt.Appendf(
		[]byte{},
		"%s.%s",
		base64.RawURLEncoding.EncodeToString(headerJSON),
		base64.RawURLEncoding.EncodeToString(claimsJSON),
	)

	signature, err := a.key.SignRS256(ctx, sha256.Sum256([]byte(signingInput)))

	if err != nil {
		return nil, fmt.Errorf("could not sign GitHub App token: %w", err)
	}

	return &AppToken{
		jwt: string(signingInput) + "." + base64.RawURLEncoding.EncodeToString(signature),
		exp: exp,
	}, nil
}

type AppToken struct {
	jwt string
	exp time.Time
}

func (t *AppToken) Expired(now time.Time) bool {
	if t == nil {
		return true
	}

	return t.exp.Sub(now) > (60 * time.Second)
}
