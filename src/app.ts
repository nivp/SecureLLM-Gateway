import cors from "cors";
import express from "express";
import type { Redis } from "ioredis";
import { pinoHttp } from "pino-http";
import { logger } from "./logger.js";
import { errorHandler } from "./middleware/errors.js";
import { requestContext } from "./middleware/requestContext.js";
import { requireAuth } from "./middleware/auth.js";
import { rateLimitMiddleware } from "./middleware/rateLimit.js";
import { validateChatBody } from "./middleware/chatValidation.js";
import { promptInjectionMiddleware } from "./middleware/promptInjection.js";
import { piiRedactionMiddleware } from "./middleware/piiRedaction.js";
import { auditRouter } from "./routes/audit.js";
import { chatRouter } from "./routes/chat.js";
import { healthRouter } from "./routes/health.js";

export function createApp(redis: Redis): express.Express {
  const app = express();

  app.use(cors());
  app.use(express.json({ limit: "1mb" }));
  app.use(requestContext);
  app.use((req, res, next) => {
    res.locals.startedAt = Date.now();
    next();
  });
  app.use(pinoHttp({ logger, genReqId: (req) => (req as express.Request).id }));

  app.use(healthRouter(redis));
  app.use("/v1/chat", requireAuth(), rateLimitMiddleware(redis), validateChatBody, promptInjectionMiddleware(), piiRedactionMiddleware);
  app.use(chatRouter());
  app.use("/v1/audit", requireAuth("admin"));
  app.use(auditRouter());

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found" });
  });
  app.use(errorHandler);

  return app;
}
