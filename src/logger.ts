import pino from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? "info",
  redact: {
    paths: ["req.headers.x-api-key", "*.apiKey", "*.OPENAI_API_KEY", "*.CLIENT_API_KEY", "*.ADMIN_API_KEY"],
    censor: "[REDACTED]"
  }
});
