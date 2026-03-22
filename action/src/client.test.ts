import { describe, it, expect, vi } from "vitest";
import { exchangeToken, STSError, type ExchangeTokenRequest } from "./client.js";

function mockFetch(status: number, body: string): typeof fetch {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    text: async () => body,
  });
}

const baseRequest: ExchangeTokenRequest = {
  stsUrl: "https://sts.example.com",
  subjectToken: "oidc-jwt-token",
  resource: "https://github.com/myorg/myrepo",
  scope: "deploy",
};

describe("exchangeToken", () => {
  it("sends correct form params and parses success response", async () => {
    const fetchFn = mockFetch(
      200,
      JSON.stringify({
        access_token: "ghs_abc123",
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: 3600,
      }),
    );

    const result = await exchangeToken(baseRequest, fetchFn);

    expect(result.access_token).toBe("ghs_abc123");
    expect(result.token_type).toBe("Bearer");
    expect(result.expires_in).toBe(3600);

    expect(fetchFn).toHaveBeenCalledWith("https://sts.example.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: expect.any(URLSearchParams),
    });

    const body = (fetchFn as ReturnType<typeof vi.fn>).mock.calls[0][1].body as URLSearchParams;
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:token-exchange");
    expect(body.get("subject_token_type")).toBe("urn:ietf:params:oauth:token-type:jwt");
    expect(body.get("subject_token")).toBe("oidc-jwt-token");
    expect(body.get("resource")).toBe("https://github.com/myorg/myrepo");
    expect(body.get("scope")).toBe("deploy");
  });

  it("throws STSError on 400 with OAuth error body", async () => {
    const fetchFn = mockFetch(
      400,
      JSON.stringify({
        error: "invalid_request",
        error_description: "missing resource parameter",
      }),
    );

    try {
      await exchangeToken(baseRequest, fetchFn);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(STSError);
      const err = e as STSError;
      expect(err.statusCode).toBe(400);
      expect(err.errorCode).toBe("invalid_request");
      expect(err.errorDescription).toBe("missing resource parameter");
    }
  });

  it("throws STSError on 500 server error", async () => {
    const fetchFn = mockFetch(
      500,
      JSON.stringify({
        error: "server_error",
        error_description: "internal server error",
      }),
    );

    try {
      await exchangeToken(baseRequest, fetchFn);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(STSError);
      const err = e as STSError;
      expect(err.statusCode).toBe(500);
      expect(err.errorCode).toBe("server_error");
    }
  });

  it("handles non-JSON error body gracefully", async () => {
    const fetchFn = mockFetch(502, "<html>Bad Gateway</html>");

    try {
      await exchangeToken(baseRequest, fetchFn);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(STSError);
      const err = e as STSError;
      expect(err.statusCode).toBe(502);
      expect(err.errorCode).toBe("unknown_error");
      expect(err.errorDescription).toBe("<html>Bad Gateway</html>");
    }
  });

  it("throws on 200 response missing access_token", async () => {
    const fetchFn = mockFetch(
      200,
      JSON.stringify({
        token_type: "Bearer",
        expires_in: 3600,
      }),
    );

    try {
      await exchangeToken(baseRequest, fetchFn);
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(STSError);
      const err = e as STSError;
      expect(err.errorCode).toBe("invalid_response");
    }
  });

  it("strips trailing slash from stsUrl", async () => {
    const fetchFn = mockFetch(
      200,
      JSON.stringify({
        access_token: "ghs_abc123",
        issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
        token_type: "Bearer",
        expires_in: 3600,
      }),
    );

    await exchangeToken({ ...baseRequest, stsUrl: "https://sts.example.com/" }, fetchFn);

    expect(fetchFn).toHaveBeenCalledWith(
      "https://sts.example.com/token",
      expect.any(Object),
    );
  });
});
