package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ericnorris/github-app-sts/internal/server/github"
	"github.com/ericnorris/github-app-sts/internal/server/sts"
)

type fakeExchanger struct {
	result *sts.Result
	err    error
}

func (f *fakeExchanger) ExchangeToken(_ context.Context, _, _, _ string) (*sts.Result, error) {
	return f.result, f.err
}

func validFormValues() url.Values {
	return url.Values{
		"grant_type":         {expectedGrantType},
		"subject_token_type": {expectedSubjectTokenType},
		"subject_token":      {"fake.jwt.token"},
		"resource":           {"https://github.com/myorg/myrepo"},
		"scope":              {"my-policy"},
	}
}

func validResult() *sts.Result {
	return &sts.Result{
		Token: &github.InstallationToken{
			AccessToken: "ghs_test123",
			ExpiresAt:   time.Now().Add(time.Hour),
		},
		Details: &sts.ExchangeDetails{},
	}
}

func TestTokenHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))

	tests := []struct {
		name           string
		method         string
		form           url.Values
		exchanger      *fakeExchanger
		wantStatus     int
		wantOAuthError string
	}{
		{
			name:       "successful exchange",
			method:     http.MethodPost,
			form:       validFormValues(),
			exchanger:  &fakeExchanger{result: validResult()},
			wantStatus: http.StatusOK,
		},
		{
			name:           "rejects GET",
			method:         http.MethodGet,
			form:           validFormValues(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusMethodNotAllowed,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "missing grant_type",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Del("grant_type")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "wrong grant_type",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Set("grant_type", "authorization_code")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "unsupported_grant_type",
		},
		{
			name:   "missing subject_token_type",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Del("subject_token_type")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "wrong subject_token_type",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "missing subject_token",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Del("subject_token")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "missing resource",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Del("resource")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "missing scope",
			method: http.MethodPost,
			form: func() url.Values {
				v := validFormValues()
				v.Del("scope")
				return v
			}(),
			exchanger:      &fakeExchanger{},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_request",
		},
		{
			name:   "service returns invalid token error",
			method: http.MethodPost,
			form:   validFormValues(),
			exchanger: &fakeExchanger{
				err: &sts.Error{
					Kind:    sts.ErrKindInvalidToken,
					Details: &sts.ExchangeDetails{},
					Err:     fmt.Errorf("bad token"),
				},
			},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_grant",
		},
		{
			name:   "service returns invalid resource error",
			method: http.MethodPost,
			form:   validFormValues(),
			exchanger: &fakeExchanger{
				err: &sts.Error{
					Kind:    sts.ErrKindInvalidResource,
					Details: &sts.ExchangeDetails{},
					Err:     fmt.Errorf("bad resource"),
				},
			},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_target",
		},
		{
			name:   "service returns invalid scope error",
			method: http.MethodPost,
			form:   validFormValues(),
			exchanger: &fakeExchanger{
				err: &sts.Error{
					Kind:    sts.ErrKindInvalidScope,
					Details: &sts.ExchangeDetails{},
					Err:     fmt.Errorf("bad scope"),
				},
			},
			wantStatus:     http.StatusBadRequest,
			wantOAuthError: "invalid_scope",
		},
		{
			name:   "service returns internal error",
			method: http.MethodPost,
			form:   validFormValues(),
			exchanger: &fakeExchanger{
				err: &sts.Error{
					Kind:    sts.ErrKindInternal,
					Details: &sts.ExchangeDetails{},
					Err:     fmt.Errorf("github api error"),
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantOAuthError: "server_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &tokenHandler{sts: tt.exchanger, logger: logger}

			body := strings.NewReader(tt.form.Encode())
			req := httptest.NewRequest(tt.method, "/token", body)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if rec.Header().Get("Content-Type") != "application/json" {
				t.Errorf("Content-Type = %q, want %q", rec.Header().Get("Content-Type"), "application/json")
			}

			var resp map[string]any

			if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
				t.Fatalf("could not decode response body: %v", err)
			}

			if tt.wantOAuthError != "" {
				if resp["error"] != tt.wantOAuthError {
					t.Errorf("error = %q, want %q", resp["error"], tt.wantOAuthError)
				}

				if _, ok := resp["error_description"]; !ok {
					t.Error("expected error_description in response")
				}
			} else {
				if _, ok := resp["access_token"]; !ok {
					t.Error("expected access_token in response")
				}

				if resp["token_type"] != "Bearer" {
					t.Errorf("token_type = %q, want %q", resp["token_type"], "Bearer")
				}

				if resp["issued_token_type"] != issuedTokenType {
					t.Errorf("issued_token_type = %q, want %q", resp["issued_token_type"], issuedTokenType)
				}

				if _, ok := resp["expires_in"]; !ok {
					t.Error("expected expires_in in response")
				}
			}
		})
	}
}
