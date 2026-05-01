package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/etsy/github-app-sts/internal/protocol"
)

func TestExchangeToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected Content-Type application/x-www-form-urlencoded, got %s", ct)
		}

		if err := r.ParseForm(); err != nil {
			t.Fatalf("parsing form: %v", err)
		}

		assertFormValue(t, r.PostForm, "grant_type", protocol.GrantType)
		assertFormValue(t, r.PostForm, "subject_token_type", protocol.SubjectTokenType)
		assertFormValue(t, r.PostForm, "subject_token", "my-jwt-token")
		assertFormValue(t, r.PostForm, "resource", "https://github.com/myorg/myrepo")
		assertFormValue(t, r.PostForm, "scope", "my-policy")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(protocol.SuccessResponse{
			AccessToken:     "ghs_test123",
			IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
			TokenType:       "Bearer",
			ExpiresIn:       3600,
		})
	}))
	defer server.Close()

	resp, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       server.URL,
		SubjectToken: "my-jwt-token",
		Resource:     "https://github.com/myorg/myrepo",
		Scope:        "my-policy",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AccessToken != "ghs_test123" {
		t.Errorf("expected access_token ghs_test123, got %s", resp.AccessToken)
	}

	if resp.ExpiresIn != 3600 {
		t.Errorf("expected expires_in 3600, got %d", resp.ExpiresIn)
	}
}

func TestExchangeToken_TrailingSlashNormalized(t *testing.T) {
	var requestPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(protocol.SuccessResponse{
			AccessToken: "ghs_test",
			TokenType:   "Bearer",
		})
	}))

	defer server.Close()

	_, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       server.URL + "///",
		SubjectToken: "token",
		Resource:     "https://github.com/org",
		Scope:        "policy",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if requestPath != "/token" {
		t.Errorf("expected path /token, got %s", requestPath)
	}
}

func TestExchangeToken_JSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "token expired",
		})
	}))

	defer server.Close()

	_, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       server.URL,
		SubjectToken: "bad-token",
		Resource:     "https://github.com/org",
		Scope:        "policy",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var stsErr *protocol.ErrorResponse

	if !errors.As(err, &stsErr) {
		t.Fatalf("expected *protocol.ErrorResponse, got %T: %v", err, err)
	}

	if stsErr.StatusCode != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", stsErr.StatusCode)
	}

	if stsErr.ErrorResponseBody.Error != "invalid_grant" {
		t.Errorf("expected error code invalid_grant, got %s", stsErr.ErrorResponseBody.Error)
	}

	if stsErr.Description != "token expired" {
		t.Errorf("expected description 'token expired', got %s", stsErr.Description)
	}
}

func TestExchangeToken_NonJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("Bad Gateway"))
	}))

	defer server.Close()

	_, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       server.URL,
		SubjectToken: "token",
		Resource:     "https://github.com/org",
		Scope:        "policy",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var stsErr *protocol.ErrorResponse

	if errors.As(err, &stsErr) {
		t.Fatalf("expected non-STS error, got ErrorResponse: %v", stsErr)
	}
}

func TestExchangeToken_MissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token_type": "Bearer",
		})
	}))

	defer server.Close()

	_, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       server.URL,
		SubjectToken: "token",
		Resource:     "https://github.com/org",
		Scope:        "policy",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var stsErr *protocol.ErrorResponse

	if errors.As(err, &stsErr) {
		t.Fatalf("expected non-STS error, got ErrorResponse: %v", stsErr)
	}
}

func TestExchangeToken_NetworkError(t *testing.T) {
	_, err := ExchangeToken(context.Background(), ExchangeRequest{
		STSUrl:       "http://localhost:1",
		SubjectToken: "token",
		Resource:     "https://github.com/org",
		Scope:        "policy",
	})

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var stsErr *protocol.ErrorResponse

	if errors.As(err, &stsErr) {
		t.Fatalf("expected non-STS error, got ErrorResponse: %v", stsErr)
	}
}

func assertFormValue(t *testing.T, values url.Values, key, expected string) {
	t.Helper()

	if got := values.Get(key); got != expected {
		t.Errorf("form value %s: expected %q, got %q", key, expected, got)
	}
}
