import mongoose, { Schema } from "mongoose";
import type { Role } from "../types.js";

export type ApiKeyDocument = {
  keyId: string;
  hash: string;
  salt: string;
  role: Role;
  rateLimitPerMinute: number;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
};

const apiKeySchema = new Schema<ApiKeyDocument>(
  {
    keyId: { type: String, required: true, unique: true, index: true },
    hash: { type: String, required: true },
    salt: { type: String, required: true },
    role: { type: String, enum: ["client", "admin"], required: true },
    rateLimitPerMinute: { type: Number, default: 30, min: 1 },
    enabled: { type: Boolean, default: true }
  },
  { timestamps: true }
);

export const ApiKeyModel = mongoose.model<ApiKeyDocument>("ApiKey", apiKeySchema);
