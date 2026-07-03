import { describe, it, expect } from "vitest";

import { maskSensitiveHeaders } from "../../open-sse/utils/requestLogger.js";

describe("request logger header redaction", () => {
  it("redacts credential-bearing headers", () => {
    const masked = maskSensitiveHeaders({
      authorization: "Bearer sk-live-secret",
      "x-api-key": "sk-live-secret",
      cookie: "auth_token=secret",
      "content-type": "application/json",
      "x-trace-id": "trace-123",
    });

    expect(masked.authorization).toBe("[REDACTED]");
    expect(masked["x-api-key"]).toBe("[REDACTED]");
    expect(masked.cookie).toBe("[REDACTED]");
    expect(masked["content-type"]).toBe("application/json");
    expect(masked["x-trace-id"]).toBe("trace-123");
  });

  it("redacts Headers instances without mutating safe headers", () => {
    const headers = new Headers({
      Authorization: "Bearer sk-live-secret",
      Accept: "application/json",
    });

    const masked = maskSensitiveHeaders(headers);

    expect(masked.authorization).toBe("[REDACTED]");
    expect(masked.accept).toBe("application/json");
  });
});
