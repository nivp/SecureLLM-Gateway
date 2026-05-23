import "dotenv/config";
import { z } from "zod";

const PLACEHOLDER_PII_KEYS = new Set(["replace-with-32-byte-secret", "local-demo-pii-encryption-key-32b"]);

const envSchema = z.object({
  NODE_ENV: z.string().default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  MONGODB_URI: z.string().default("mongodb://localhost:27017/securellm"),
  REDIS_URL: z.string().default("redis://localhost:6379"),
  INJECTION_DETECTION_MODE: z.enum(["classic", "llm_canary"]).default("llm_canary"),
  LLM_CANARY_DEBUG_LOGS: z.coerce.boolean().default(false),
  OPENAI_API_KEY: z.string().optional(),
  OPENAI_BASE_URL: z.string().url().optional(),
  OPENAI_CANARY_MODEL: z.string().min(1).optional(),
  OPENAI_MODEL_ALIASES: z.string().optional(),
  PII_ENCRYPTION_KEY: z.string().optional()
});

export type AppConfig = z.infer<typeof envSchema> & {
  modelAliases: Record<string, string>;
  allowedModels: Set<string>;
};

function parseAliases(raw: string | undefined): Record<string, string> {
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("OPENAI_MODEL_ALIASES must be a JSON object");
    }
    return Object.fromEntries(
      Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string")
    );
  } catch (error) {
    throw new Error(`Invalid OPENAI_MODEL_ALIASES: ${(error as Error).message}`);
  }
}

const parsed = envSchema.parse(process.env);
if (parsed.NODE_ENV === "production" && (!parsed.PII_ENCRYPTION_KEY || PLACEHOLDER_PII_KEYS.has(parsed.PII_ENCRYPTION_KEY))) {
  throw new Error("PII_ENCRYPTION_KEY must be configured with a strong production secret");
}

const modelAliases = parseAliases(parsed.OPENAI_MODEL_ALIASES);
const baseModels = ["gpt-4o", "claude-3-5-sonnet"];

export const config: AppConfig = {
  ...parsed,
  modelAliases,
  allowedModels: new Set([...baseModels, ...Object.keys(modelAliases), ...Object.values(modelAliases)])
};

export function providerReady(appConfig: Pick<AppConfig, "OPENAI_API_KEY"> = config): boolean {
  return Boolean(appConfig.OPENAI_API_KEY);
}
