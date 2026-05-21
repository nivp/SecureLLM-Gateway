import { createHash } from "node:crypto";
import type { Request } from "express";
import { config } from "./config.js";
import { AuditLogModel, type AuditStatus } from "./models/AuditLog.js";
import { encryptValue } from "./security/piiCrypto.js";
import type { RedactionToken, Threat } from "./types.js";

export function sha256Json(value: unknown): string {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function encryptedPiiTokens(tokens: RedactionToken[] | undefined) {
  if (!tokens?.length) {
    return undefined;
  }
  return tokens.map((entry) => ({
    token: entry.token,
    category: entry.category,
    encryptedValue: config.PII_ENCRYPTION_KEY ? encryptValue(entry.value, config.PII_ENCRYPTION_KEY) : undefined
  }));
}

export async function writeAudit(params: {
  req: Request;
  startedAt: number;
  status: AuditStatus;
  statusCode: number;
  requestHash?: string;
  responseHash?: string;
  threats?: Threat[];
  piiTokens?: RedactionToken[];
  error?: string;
}): Promise<void> {
  await AuditLogModel.create({
    timestamp: new Date(),
    correlationId: params.req.id,
    apiKeyId: params.req.auth?.keyId,
    model: params.req.validatedChat?.model,
    requestHash: params.requestHash,
    responseHash: params.responseHash,
    detectedThreats: (params.threats ?? params.req.detectedThreats ?? []).map((threat) => threat.ruleId),
    latencyMs: Date.now() - params.startedAt,
    status: params.status,
    statusCode: params.statusCode,
    piiTokens: encryptedPiiTokens(params.piiTokens),
    error: params.error
  });
}
