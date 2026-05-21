import type { NextFunction, Request, Response } from "express";
import { ApiKeyModel } from "../models/ApiKey.js";
import { keyIdFor, verifyApiKey } from "../security/hash.js";
import type { Role } from "../types.js";

export function requireAuth(requiredRole?: Role) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const apiKey = req.header("x-api-key");
    if (!apiKey) {
      res.status(401).json({ error: "missing_api_key" });
      return;
    }

    const keyRecord = await ApiKeyModel.findOne({ keyId: keyIdFor(apiKey), enabled: true }).lean();
    if (!keyRecord || !verifyApiKey(apiKey, keyRecord.salt, keyRecord.hash)) {
      res.status(401).json({ error: "invalid_api_key" });
      return;
    }

    if (requiredRole === "admin" && keyRecord.role !== "admin") {
      res.status(403).json({ error: "admin_required" });
      return;
    }

    req.auth = {
      keyId: keyRecord.keyId,
      role: keyRecord.role,
      rateLimitPerMinute: keyRecord.rateLimitPerMinute
    };
    next();
  };
}
