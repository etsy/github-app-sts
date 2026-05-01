// Package protocol defines the RFC 8693 token exchange wire format shared
// between the STS client and server.
package protocol

import "fmt"

const (
	GrantType        = "urn:ietf:params:oauth:grant-type:token-exchange"
	SubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"
	IssuedTokenType  = "urn:ietf:params:oauth:token-type:access_token"
)

// SuccessResponse is the JSON body for a successful token exchange.
type SuccessResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}

// ErrorResponseBody is the JSON body for an OAuth 2.0 error response.
type ErrorResponseBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// ErrorResponse pairs the wire format with the HTTP status code.
type ErrorResponse struct {
	StatusCode int
	ErrorResponseBody
}

func (e *ErrorResponse) Error() string {
	return fmt.Sprintf("STS error (%s): %s", e.ErrorResponseBody.Error, e.Description)
}
