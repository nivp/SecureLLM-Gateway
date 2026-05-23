import pino from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL ?? (process.env.NODE_ENV === "test" ? "silent" : "info"),
  redact: {
    paths: ["req.headers.x-api-key", "*.apiKey", "*.OPENAI_API_KEY", "*.CLIENT_API_KEY", "*.ADMIN_API_KEY"],
    censor: "[REDACTED]"
  }
});
