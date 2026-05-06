package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/etsy/github-app-sts/internal/protocol"
)

type ExchangeRequest struct {
	STSUrl       string
	SubjectToken string
	Resource     string
	Scope        string
}

func ExchangeToken(ctx context.Context, req ExchangeRequest) (*protocol.SuccessResponse, error) {
	tokenURL := strings.TrimRight(req.STSUrl, "/") + "/token"

	form := url.Values{
		"grant_type":         {protocol.GrantType},
		"subject_token_type": {protocol.SubjectTokenType},
		"subject_token":      {req.SubjectToken},
		"resource":           {req.Resource},
		"scope":              {req.Scope},
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))

	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(httpReq)

	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var parsed protocol.ErrorResponseBody

		if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
			return nil, &protocol.ErrorResponse{
				StatusCode:        resp.StatusCode,
				ErrorResponseBody: parsed,
			}
		}

		return nil, fmt.Errorf("STS returned %d: %s", resp.StatusCode, body)
	}

	var result protocol.SuccessResponse

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if result.AccessToken == "" {
		return nil, fmt.Errorf("missing access_token in response")
	}

	return &result, nil
}
