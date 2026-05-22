import { afterEach, describe, expect, it, vi } from "vitest";

describe("configuration validation", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it("rejects placeholder PII encryption keys in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PII_ENCRYPTION_KEY", "replace-with-32-byte-secret");

    await expect(import("../src/config.js")).rejects.toThrow("PII_ENCRYPTION_KEY must be configured");
  });

  it("allows local demo PII encryption keys outside production", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PII_ENCRYPTION_KEY", "local-demo-pii-encryption-key-32b");

    await expect(import("../src/config.js")).resolves.toHaveProperty("config");
  });
});
