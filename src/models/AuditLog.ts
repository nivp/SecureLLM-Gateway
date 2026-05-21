import mongoose, { Schema } from "mongoose";

export type AuditStatus = "allowed" | "blocked" | "error";

export type AuditLogDocument = {
  timestamp: Date;
  correlationId: string;
  apiKeyId?: string;
  model?: string;
  requestHash?: string;
  responseHash?: string;
  detectedThreats: string[];
  latencyMs: number;
  status: AuditStatus;
  statusCode: number;
  piiTokens?: Array<{ token: string; category: string; encryptedValue?: string }>;
  error?: string;
};

const auditLogSchema = new Schema<AuditLogDocument>(
  {
    timestamp: { type: Date, required: true, index: true },
    correlationId: { type: String, required: true, index: true },
    apiKeyId: { type: String, index: true },
    model: { type: String },
    requestHash: { type: String },
    responseHash: { type: String },
    detectedThreats: [{ type: String }],
    latencyMs: { type: Number, required: true },
    status: { type: String, enum: ["allowed", "blocked", "error"], required: true },
    statusCode: { type: Number, required: true },
    piiTokens: [{ token: String, category: String, encryptedValue: String }],
    error: { type: String }
  },
  { versionKey: false }
);

export const AuditLogModel = mongoose.model<AuditLogDocument>("AuditLog", auditLogSchema);
