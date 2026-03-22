package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ericnorris/github-app-sts/internal/server/sts"
)

const (
	expectedGrantType        = "urn:ietf:params:oauth:grant-type:token-exchange"
	expectedSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

	issuedTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

type service interface {
	ExchangeToken(ctx context.Context, subjectToken, resource, scope string) (*sts.Result, error)
}

type tokenHandler struct {
	sts    service
	logger *slog.Logger
}

func (h *tokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, &errorResponse{http.StatusMethodNotAllowed, "invalid_request", "method not allowed"})
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "could not parse form body"})
		return
	}

	grantType := r.FormValue("grant_type")

	if grantType == "" {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "missing grant_type parameter"})
		return
	}

	if grantType != expectedGrantType {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "unsupported_grant_type", "grant_type must be " + expectedGrantType})
		return
	}

	subjectTokenType := r.FormValue("subject_token_type")

	if subjectTokenType == "" {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "missing subject_token_type parameter"})
		return
	}

	if subjectTokenType != expectedSubjectTokenType {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "subject_token_type must be " + expectedSubjectTokenType})
		return
	}

	subjectToken := r.FormValue("subject_token")

	if subjectToken == "" {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "missing subject_token parameter"})
		return
	}

	resource := r.FormValue("resource")

	if resource == "" {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "missing resource parameter"})
		return
	}

	scope := r.FormValue("scope")

	if scope == "" {
		h.writeError(w, &errorResponse{http.StatusBadRequest, "invalid_request", "missing scope parameter"})
		return
	}

	result, err := h.sts.ExchangeToken(r.Context(), subjectToken, resource, scope)

	if err != nil {
		response := &errorResponse{http.StatusInternalServerError, "server_error", "internal server error"}

		var stsError *sts.Error

		if errors.As(err, &stsError) {
			logLevel := slog.LevelError

			switch stsError.Kind {
			case sts.ErrKindInvalidToken:
				response = &errorResponse{http.StatusBadRequest, "invalid_grant", "invalid subject token"}
				logLevel = slog.LevelWarn

			case sts.ErrKindInvalidResource:
				response = &errorResponse{http.StatusBadRequest, "invalid_target", "invalid resource"}
				logLevel = slog.LevelInfo

			case sts.ErrKindInvalidScope:
				response = &errorResponse{http.StatusBadRequest, "invalid_scope", "invalid scope"}
				logLevel = slog.LevelInfo

			}

			h.logExchange(logLevel, stsError.Details, stsError.Unwrap())
		} else {
			h.logger.Error("unexpected error type from exchange", "error", err)
		}

		h.writeError(w, response)
		return
	}

	h.logExchange(slog.LevelInfo, result.Details, nil)

	h.writeSuccess(w, &successResponse{
		AccessToken:     result.Token.AccessToken,
		IssuedTokenType: issuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       int(time.Until(result.Token.ExpiresAt).Seconds()),
	})
}

func (h *tokenHandler) logExchange(level slog.Level, d *sts.ExchangeDetails, err error) {
	attrs := []slog.Attr{
		slog.Group(
			"exchange_details",
			slog.String("subject_token_hash", d.SubjectTokenHash),
			slog.String("resource", d.ResourceParameter),
			slog.String("scope", d.ScopeParameter),
			slog.String("issuer", d.SubjectTokenIssuer),
			slog.String("target_org", d.TargetOrganization),
			slog.String("target_repo", d.TargetRepository),
			slog.String("policy_app_client_id", d.PolicyAppClientID),
			slog.Bool("allowed_by_policy", d.AllowedByPolicy),
		),
	}

	if err != nil {
		attrs = append(attrs,
			slog.String("error", err.Error()),
		)

		h.logger.LogAttrs(context.Background(), level, "token exchange failed", attrs...)
		return
	}

	h.logger.LogAttrs(context.Background(), level, "token exchange succeeded", attrs...)
}

type errorResponse struct {
	Status      int
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (h *tokenHandler) writeError(w http.ResponseWriter, response *errorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.Status)

	// SAFETY: this is infallible.
	json.NewEncoder(w).Encode(response)
}

type successResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

func (h *tokenHandler) writeSuccess(w http.ResponseWriter, response *successResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// SAFETY: this is infallible.
	json.NewEncoder(w).Encode(response)
}
