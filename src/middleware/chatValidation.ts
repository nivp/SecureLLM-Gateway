import type { NextFunction, Request, Response } from "express";
import { z } from "zod";
import { sha256Json, writeAuditSafe } from "../audit.js";
import { config } from "../config.js";

const chatSchema = z.object({
  model: z.string().min(1),
  messages: z
    .array(
      z.object({
        role: z.enum(["system", "user", "assistant"]),
        content: z.string().min(1)
      })
    )
    .min(1),
  max_tokens: z.number().int().positive().max(8192).default(1024)
});

export function validateChatBody(req: Request, res: Response, next: NextFunction): void {
  const parsed = chatSchema.safeParse(req.body);
  if (!parsed.success) {
    void writeAuditSafe({
      req,
      startedAt: res.locals.startedAt as number,
      status: "blocked",
      statusCode: 400,
      requestHash: sha256Json({ path: req.path, method: req.method, body: req.body }),
      threats: [{ type: "validation", ruleId: "invalid-chat-request", message: "Invalid chat request body" }]
    }).finally(() => {
      res.status(400).json({ error: "invalid_request", details: parsed.error.flatten() });
    });
    return;
  }

  if (!config.allowedModels.has(parsed.data.model)) {
    req.validatedChat = {
      ...parsed.data,
      providerModel: parsed.data.model
    };
    void writeAuditSafe({
      req,
      startedAt: res.locals.startedAt as number,
      status: "blocked",
      statusCode: 400,
      requestHash: sha256Json({ path: req.path, method: req.method, body: req.body }),
      threats: [{ type: "validation", ruleId: "unsupported-model", message: "Unsupported model" }]
    }).finally(() => {
      res.status(400).json({ error: "unsupported_model" });
    });
    return;
  }

  req.validatedChat = {
    ...parsed.data,
    providerModel: config.modelAliases[parsed.data.model] ?? parsed.data.model
  };
  next();
}
