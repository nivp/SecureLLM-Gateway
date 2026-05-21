import type { Router } from "express";
import { Router as createRouter } from "express";
import { z } from "zod";
import { config } from "../config.js";
import { AuditLogModel } from "../models/AuditLog.js";
import { decryptValue } from "../security/piiCrypto.js";

const querySchema = z.object({
  since: z.string().datetime().optional(),
  limit: z.coerce.number().int().positive().max(500).default(100),
  reveal_pii: z.enum(["true", "false"]).default("false")
});

export function auditRouter(): Router {
  const router = createRouter();
  router.get("/v1/audit", async (req, res) => {
    const parsed = querySchema.safeParse(req.query);
    if (!parsed.success) {
      res.status(400).json({ error: "invalid_query", details: parsed.error.flatten() });
      return;
    }

    const query = parsed.data.since ? { timestamp: { $gte: new Date(parsed.data.since) } } : {};
    const records = await AuditLogModel.find(query).sort({ timestamp: -1 }).limit(parsed.data.limit).lean();
    const reveal = parsed.data.reveal_pii === "true" && Boolean(config.PII_ENCRYPTION_KEY);

    res.json({
      entries: records.map((record) => ({
        ...record,
        piiTokens: record.piiTokens?.map((token) => ({
          token: token.token,
          category: token.category,
          value: reveal && token.encryptedValue ? decryptValue(token.encryptedValue, config.PII_ENCRYPTION_KEY!) : undefined
        }))
      }))
    });
  });
  return router;
}
