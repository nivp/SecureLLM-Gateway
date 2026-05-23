import type { NextFunction, Request, Response } from "express";
import { sha256Json, writeAuditSafe } from "../audit.js";
import { ApiKeyModel } from "../models/ApiKey.js";
import { keyIdFor, verifyApiKey } from "../security/hash.js";
import type { Role } from "../types.js";
import { asyncHandler } from "./errors.js";

export function requireAuth(requiredRole?: Role) {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const apiKey = req.header("x-api-key");
    if (!apiKey) {
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 401,
        requestHash: sha256Json({ path: req.path, method: req.method, body: req.body, query: req.query }),
        threats: [{ type: "auth", ruleId: "missing-api-key", message: "Missing x-api-key header" }]
      });
      res.status(401).json({ error: "missing_api_key" });
      return;
    }

    const keyRecord = await ApiKeyModel.findOne({ keyId: keyIdFor(apiKey), enabled: true }).lean();
    if (!keyRecord || !verifyApiKey(apiKey, keyRecord.salt, keyRecord.hash)) {
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 401,
        requestHash: sha256Json({ path: req.path, method: req.method, body: req.body, query: req.query }),
        threats: [{ type: "auth", ruleId: "invalid-api-key", message: "Invalid API key" }]
      });
      res.status(401).json({ error: "invalid_api_key" });
      return;
    }

    if (requiredRole === "admin" && keyRecord.role !== "admin") {
      req.auth = {
        keyId: keyRecord.keyId,
        role: keyRecord.role,
        rateLimitPerMinute: keyRecord.rateLimitPerMinute
      };
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 403,
        requestHash: sha256Json({ path: req.path, method: req.method, body: req.body, query: req.query }),
        threats: [{ type: "auth", ruleId: "admin-required", message: "Admin role required" }]
      });
      res.status(403).json({ error: "admin_required" });
      return;
    }

    req.auth = {
      keyId: keyRecord.keyId,
      role: keyRecord.role,
      rateLimitPerMinute: keyRecord.rateLimitPerMinute
    };
    next();
  });
}
