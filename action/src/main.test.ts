import { describe, it, expect, vi, beforeEach } from "vitest";

const { coreMock, exchangeTokenMock } = vi.hoisted(() => ({
  coreMock: {
    getInput: vi.fn(),
    getIDToken: vi.fn(),
    setSecret: vi.fn(),
    setOutput: vi.fn(),
    exportVariable: vi.fn(),
    setFailed: vi.fn(),
    error: vi.fn(),
  },
  exchangeTokenMock: vi.fn(),
}));

vi.mock("@actions/core", () => coreMock);

vi.mock("./client.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("./client.js")>();
  return {
    ...original,
    exchangeToken: exchangeTokenMock,
  };
});

// Import STSError after mocks are set up (the mock preserves the original)
const { STSError } = await import("./client.js");

function setupInputs(inputs: Record<string, string>) {
  coreMock.getInput.mockImplementation((name: string, opts?: { required?: boolean }) => {
    const value = inputs[name] ?? "";
    if (opts?.required && !value) {
      throw new Error(`Input required and not supplied: ${name}`);
    }
    return value;
  });
}

async function runMain() {
  vi.resetModules();
  vi.mock("@actions/core", () => coreMock);
  vi.mock("./client.js", async (importOriginal) => {
    const original = await importOriginal<typeof import("./client.js")>();
    return {
      ...original,
      exchangeToken: exchangeTokenMock,
    };
  });
  await import("./main.js");
  await new Promise((r) => setTimeout(r, 0));
}

describe("main", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("happy path: exchanges token and sets output", async () => {
    setupInputs({
      "sts-url": "https://sts.example.com",
      policy: "deploy",
      target: "https://github.com/myorg/myrepo",
    });

    coreMock.getIDToken.mockResolvedValue("oidc-jwt");
    exchangeTokenMock.mockResolvedValue({
      access_token: "ghs_abc123",
      token_type: "Bearer",
      expires_in: 3600,
    });

    await runMain();

    expect(coreMock.getIDToken).toHaveBeenCalledWith("https://sts.example.com");
    expect(exchangeTokenMock).toHaveBeenCalledWith({
      stsUrl: "https://sts.example.com",
      subjectToken: "oidc-jwt",
      resource: "https://github.com/myorg/myrepo",
      scope: "deploy",
    });
    expect(coreMock.setSecret).toHaveBeenCalledWith("ghs_abc123");
    expect(coreMock.setOutput).toHaveBeenCalledWith("token", "ghs_abc123");
    expect(coreMock.exportVariable).not.toHaveBeenCalled();
    expect(coreMock.setFailed).not.toHaveBeenCalled();
  });

  it("exports token as env var when token-variable is set", async () => {
    setupInputs({
      "sts-url": "https://sts.example.com",
      policy: "deploy",
      target: "https://github.com/myorg/myrepo",
      "token-variable": "GH_TOKEN",
    });

    coreMock.getIDToken.mockResolvedValue("oidc-jwt");
    exchangeTokenMock.mockResolvedValue({
      access_token: "ghs_abc123",
      token_type: "Bearer",
      expires_in: 3600,
    });

    await runMain();

    expect(coreMock.exportVariable).toHaveBeenCalledWith("GH_TOKEN", "ghs_abc123");
  });

  it("calls setFailed when getIDToken fails", async () => {
    setupInputs({
      "sts-url": "https://sts.example.com",
      policy: "deploy",
      target: "https://github.com/myorg/myrepo",
    });

    coreMock.getIDToken.mockRejectedValue(new Error("OIDC token request failed"));

    await runMain();

    expect(coreMock.setFailed).toHaveBeenCalledWith("OIDC token request failed");
  });

  it("logs error code and calls setFailed on STSError", async () => {
    setupInputs({
      "sts-url": "https://sts.example.com",
      policy: "deploy",
      target: "https://github.com/myorg/myrepo",
    });

    coreMock.getIDToken.mockResolvedValue("oidc-jwt");
    exchangeTokenMock.mockRejectedValue(
      new STSError(400, "invalid_scope", "invalid scope"),
    );

    await runMain();

    expect(coreMock.error).toHaveBeenCalledWith("STS error code: invalid_scope");
    expect(coreMock.setFailed).toHaveBeenCalledWith("STS error (invalid_scope): invalid scope");
  });
});
