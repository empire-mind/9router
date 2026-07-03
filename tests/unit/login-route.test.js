import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const mocks = vi.hoisted(() => ({
  jsonResponse: vi.fn((body, init = {}) => ({
    status: init.status || 200,
    headers: init.headers || {},
    body,
  })),
  getSettings: vi.fn(),
  bcryptCompare: vi.fn(),
  cookies: vi.fn(),
  setDashboardAuthCookie: vi.fn(),
  isOidcConfigured: vi.fn(),
}));

vi.mock("next/server", () => ({
  NextResponse: {
    json: mocks.jsonResponse,
  },
}));

vi.mock("@/lib/localDb", () => ({
  getSettings: mocks.getSettings,
}));

vi.mock("bcryptjs", () => ({
  default: { compare: mocks.bcryptCompare },
}));

vi.mock("next/headers", () => ({
  cookies: mocks.cookies,
}));

vi.mock("@/lib/auth/dashboardSession", () => ({
  setDashboardAuthCookie: mocks.setDashboardAuthCookie,
}));

vi.mock("@/lib/auth/oidc", () => ({
  isOidcConfigured: mocks.isOidcConfigured,
}));

const { POST, __test__ } = await import("../../src/app/api/auth/login/route.js");

function request(password, headers = {}) {
  return {
    json: vi.fn(async () => ({ password })),
    headers: new Headers({ host: "localhost:20128", ...headers }),
  };
}

describe("password login route", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    __test__.loginAttempts.clear();
    delete process.env.INITIAL_PASSWORD;
    mocks.getSettings.mockResolvedValue({
      password: null,
      authMode: "password",
      tunnelDashboardAccess: false,
    });
    mocks.bcryptCompare.mockResolvedValue(false);
    mocks.cookies.mockResolvedValue({});
    mocks.isOidcConfigured.mockReturnValue(false);
  });

  afterEach(() => {
    delete process.env.INITIAL_PASSWORD;
  });

  it("does not fall back to the historical default password", async () => {
    const response = await POST(request("123456"));

    expect(response.status).toBe(503);
    expect(response.body.error).toBe("Dashboard password is not configured");
  });

  it("allows explicit initial password from environment", async () => {
    process.env.INITIAL_PASSWORD = "configured-once";

    const response = await POST(request("configured-once"));

    expect(response.status).toBe(200);
    expect(response.body.success).toBe(true);
    expect(mocks.setDashboardAuthCookie).toHaveBeenCalled();
  });

  it("throttles repeated invalid password attempts", async () => {
    mocks.getSettings.mockResolvedValue({
      password: "$2a$10$hash",
      authMode: "password",
      tunnelDashboardAccess: false,
    });
    mocks.bcryptCompare.mockResolvedValue(false);

    let response;
    for (let i = 0; i < 5; i += 1) {
      response = await POST(request("wrong", { "x-forwarded-for": "203.0.113.9" }));
    }

    expect(response.status).toBe(429);
    expect(response.headers["Retry-After"]).toBeDefined();

    const stillThrottled = await POST(request("wrong", { "x-forwarded-for": "203.0.113.9" }));
    expect(stillThrottled.status).toBe(429);
  });
});
