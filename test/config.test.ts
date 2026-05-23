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

  it("rejects short PII encryption keys in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PII_ENCRYPTION_KEY", "short-secret");

    await expect(import("../src/config.js")).rejects.toThrow("at least 32 bytes");
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

  it("defaults to classic mode with debug canary logs disabled", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PII_ENCRYPTION_KEY", "local-demo-pii-encryption-key-32b");
    vi.stubEnv("INJECTION_DETECTION_MODE", undefined);
    vi.stubEnv("LLM_CANARY_DEBUG_LOGS", undefined);

    const loaded = await import("../src/config.js");
    expect(loaded.config.INJECTION_DETECTION_MODE).toBe("classic");
    expect(loaded.config.LLM_CANARY_DEBUG_LOGS).toBe(false);
    expect(loaded.config.OPENAI_CANARY_MODEL).toBeUndefined();
  });

  it("accepts combined mode for regex-first provider-backed detection", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("INJECTION_DETECTION_MODE", "combined");

    const loaded = await import("../src/config.js");
    expect(loaded.config.INJECTION_DETECTION_MODE).toBe("combined");
  });

  it("accepts a dedicated canary model separate from chat model aliases", async () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PII_ENCRYPTION_KEY", "local-demo-pii-encryption-key-32b");
    vi.stubEnv("OPENAI_CANARY_MODEL", "small-canary-model");
    vi.stubEnv("OPENAI_MODEL_ALIASES", '{"gpt-4o":"larger-chat-model"}');

    const loaded = await import("../src/config.js");
    expect(loaded.config.OPENAI_CANARY_MODEL).toBe("small-canary-model");
    expect(loaded.config.modelAliases).toEqual({ "gpt-4o": "larger-chat-model" });
  });
});
