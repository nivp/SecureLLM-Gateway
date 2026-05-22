import type { Redis } from "ioredis";
import type { Router } from "express";
import { Router as createRouter } from "express";
import mongoose from "mongoose";
import { providerReady } from "../config.js";
import { asyncHandler } from "../middleware/errors.js";

export function healthRouter(redis: Redis): Router {
  const router = createRouter();
  router.get("/healthz", asyncHandler(async (_req, res) => {
    let redisOk = false;
    try {
      redisOk = (await redis.ping()) === "PONG";
    } catch {
      redisOk = false;
    }
    const mongoOk = mongoose.connection.readyState === 1;
    const providerOk = providerReady();
    res.status(mongoOk && redisOk ? 200 : 503).json({
      status: mongoOk && redisOk && providerOk ? "ok" : "degraded",
      mongo: mongoOk,
      redis: redisOk,
      provider: providerOk
    });
  }));
  return router;
}
