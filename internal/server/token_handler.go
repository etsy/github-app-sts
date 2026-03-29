package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/etsy/github-app-sts/internal/server/sts"
)

var meter = otel.Meter("github-app-sts/token-handler")

var exchangeCounter, _ = meter.Int64Counter(
	"sts.token_exchange.total",
	metric.WithDescription("Total token exchange attempts"),
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
	ctx := r.Context()

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

	result, err := h.sts.ExchangeToken(ctx, subjectToken, resource, scope)

	if err != nil {
		response := &errorResponse{http.StatusInternalServerError, "server_error", "internal server error"}

		attrs := []attribute.KeyValue{
			attribute.String("error.type", fmt.Sprintf("%T", err)),
		}

		var stsError *sts.Error

		if errors.As(err, &stsError) {
			logLevel := slog.LevelError

			switch stsError.Kind {
			case sts.ErrKindInvalidToken:
				response = &errorResponse{http.StatusBadRequest, "invalid_grant", stsError.Message}
				logLevel = slog.LevelWarn

			case sts.ErrKindInvalidResource:
				response = &errorResponse{http.StatusBadRequest, "invalid_target", stsError.Message}
				logLevel = slog.LevelInfo

			case sts.ErrKindInvalidScope:
				response = &errorResponse{http.StatusBadRequest, "invalid_scope", stsError.Message}
				logLevel = slog.LevelInfo

			case sts.ErrKindInternal:
				logLevel = slog.LevelError
			}

			attrs = append(
				attrs,
				attribute.String("sts.error", response.Error),
				attribute.String("sts.target_org", stsError.Details.TargetOrganization),
				attribute.String("sts.target_repo", stsError.Details.TargetRepository),
			)

			h.logExchange(ctx, logLevel, stsError.Details, stsError.Unwrap())
		} else {
			h.logger.Error("unexpected error type from exchange", "error", err)
		}

		exchangeCounter.Add(ctx, 1, metric.WithAttributes(attrs...))

		h.writeError(w, response)
		return
	}

	exchangeCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("sts.target_org", result.Details.TargetOrganization),
		attribute.String("sts.target_repo", result.Details.TargetRepository),
	))

	h.logExchange(ctx, slog.LevelInfo, result.Details, nil)

	h.writeSuccess(w, &successResponse{
		AccessToken:     result.Token.AccessToken,
		IssuedTokenType: issuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       int(time.Until(result.Token.ExpiresAt).Seconds()),
	})
}

func (h *tokenHandler) logExchange(ctx context.Context, level slog.Level, d *sts.ExchangeDetails, err error) {
	attrs := []slog.Attr{
		slog.Group(
			"exchange_details",
			slog.String("subject_token_hash", d.SubjectTokenHash),
			slog.String("resource", d.ResourceParameter),
			slog.String("scope", d.ScopeParameter),
			slog.String("issuer", d.SubjectTokenIssuer),
			slog.String("target_org", d.TargetOrganization),
			slog.String("target_repo", d.TargetRepository),
			slog.String("policy_target_app", d.PolicyTargetApp),
			slog.Bool("allowed_by_policy", d.AllowedByPolicy),
		),
	}

	if err != nil {
		attrs = append(attrs,
			slog.String("error", err.Error()),
		)

		h.logger.LogAttrs(ctx, level, "token exchange failed", attrs...)
		return
	}

	h.logger.LogAttrs(ctx, level, "token exchange succeeded", attrs...)
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
