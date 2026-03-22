const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

export interface ExchangeTokenRequest {
  stsUrl: string;
  subjectToken: string;
  resource: string;
  scope: string;
}

export interface ExchangeTokenResponse {
  access_token: string;
  issued_token_type: string;
  token_type: string;
  expires_in: number;
}

export class STSError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly errorCode: string,
    public readonly errorDescription: string,
  ) {
    super(`STS error (${errorCode}): ${errorDescription}`);
    this.name = "STSError";
  }
}

export async function exchangeToken(
  request: ExchangeTokenRequest,
  fetchFn: typeof fetch = fetch,
): Promise<ExchangeTokenResponse> {
  const url = request.stsUrl.replace(/\/+$/, "") + "/token";

  const body = new URLSearchParams({
    grant_type: GRANT_TYPE,
    subject_token_type: SUBJECT_TOKEN_TYPE,
    subject_token: request.subjectToken,
    resource: request.resource,
    scope: request.scope,
  });

  const response = await fetchFn(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  const responseBody = await response.text();

  if (!response.ok) {
    let errorCode = "unknown_error";
    let errorDescription = responseBody;

    try {
      const parsed = JSON.parse(responseBody);
      if (parsed.error) errorCode = parsed.error;
      if (parsed.error_description) errorDescription = parsed.error_description;
    } catch {
      // non-JSON error body, use raw text as description
    }

    throw new STSError(response.status, errorCode, errorDescription);
  }

  const parsed = JSON.parse(responseBody) as ExchangeTokenResponse;

  if (!parsed.access_token) {
    throw new STSError(response.status, "invalid_response", "missing access_token in response");
  }

  return parsed;
}
