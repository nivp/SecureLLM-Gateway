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

  it("accepts llm_canary as the provider-backed injection detection mode", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("INJECTION_DETECTION_MODE", "llm_canary");

    const loaded = await import("../src/config.js");
    expect(loaded.config.INJECTION_DETECTION_MODE).toBe("llm_canary");
  });

  it("defaults to llm_canary mode with debug canary logs disabled", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PII_ENCRYPTION_KEY", "local-demo-pii-encryption-key-32b");
    vi.stubEnv("INJECTION_DETECTION_MODE", undefined);
    vi.stubEnv("LLM_CANARY_DEBUG_LOGS", undefined);

    const loaded = await import("../src/config.js");
    expect(loaded.config.INJECTION_DETECTION_MODE).toBe("llm_canary");
    expect(loaded.config.LLM_CANARY_DEBUG_LOGS).toBe(false);
  });
});
