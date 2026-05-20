import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("secret references", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.doUnmock("node:child_process");
    vi.doUnmock("node:fs");
    vi.resetModules();
  });

  it("detects supported reference schemes", async () => {
    const refs = await import("@/lib/secrets/onePassword.js");

    expect(refs.isOnePasswordReference("op://Shared/App/key")).toBe(true);
    expect(refs.isGcpSecretReference("gcp://openrouter-api-key")).toBe(true);
    expect(refs.isKeychainSecretReference("keychain://halvo-shared/OPENROUTER_API_KEY")).toBe(true);
    expect(refs.isSecretReference("plain-secret")).toBe(false);
  });

  it("resolves gcp:// references through gcloud without exposing values", async () => {
    const execFileSync = vi.fn((cmd, args) => {
      if (args?.includes("--version")) return "Google Cloud SDK 999.0.0";
      expect(cmd).toBe("gcloud");
      expect(args).toEqual([
        "secrets",
        "versions",
        "access",
        "latest",
        "--secret",
        "openrouter-api-key",
      ]);
      return "resolved-gcp-secret\n";
    });

    vi.doMock("node:child_process", () => ({ execFileSync }));
    vi.doMock("node:fs", async () => {
      const actual = await vi.importActual("node:fs");
      return { ...actual, default: { ...actual.default, existsSync: vi.fn(() => false) } };
    });

    const { resolveSecretValue } = await import("@/lib/secrets/onePassword.js");

    expect(resolveSecretValue("gcp://openrouter-api-key")).toBe("resolved-gcp-secret");
  });

  it("resolves keychain:// references through macOS security", async () => {
    const execFileSync = vi.fn((cmd, args) => {
      expect(cmd).toBe("/usr/bin/security");
      expect(args).toEqual([
        "find-generic-password",
        "-s",
        "halvo-shared",
        "-a",
        "OPENROUTER_API_KEY",
        "-w",
        "/Library/Keychains/System.keychain",
      ]);
      return "resolved-keychain-secret\n";
    });

    vi.doMock("node:child_process", () => ({ execFileSync }));

    const { resolveSecretValue } = await import("@/lib/secrets/onePassword.js");

    expect(resolveSecretValue("keychain://halvo-shared/OPENROUTER_API_KEY")).toBe("resolved-keychain-secret");
  });
});
