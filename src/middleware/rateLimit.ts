import type { Redis } from "ioredis";
import type { NextFunction, Request, Response } from "express";
import { sha256Json, writeAuditSafe } from "../audit.js";
import { asyncHandler } from "./errors.js";

export function rateLimitMiddleware(redis: Redis) {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    if (!req.auth) {
      res.status(401).json({ error: "missing_auth_context" });
      return;
    }

    const now = Date.now();
    const windowMs = 60_000;
    const key = `rate:${req.auth.keyId}`;
    const member = `${now}:${req.id}`;

    const pipeline = redis.pipeline();
    pipeline.zremrangebyscore(key, 0, now - windowMs);
    pipeline.zadd(key, now, member);
    pipeline.zcard(key);
    pipeline.expire(key, 90);
    const results = await pipeline.exec();
    const count = Number(results?.[2]?.[1] ?? 0);

    res.setHeader("x-ratelimit-limit", String(req.auth.rateLimitPerMinute));
    res.setHeader("x-ratelimit-remaining", String(Math.max(req.auth.rateLimitPerMinute - count, 0)));

    if (count > req.auth.rateLimitPerMinute) {
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 429,
        requestHash: sha256Json({ path: req.path, method: req.method, body: req.body }),
        threats: [{ type: "rate_limit", ruleId: "rate-limit-exceeded", message: "API key rate limit exceeded" }]
      });
      res.status(429).json({ error: "rate_limit_exceeded" });
      return;
    }

    next();
  });
}
