import type { NextFunction, Request, Response } from "express";
import { redactMessages } from "../security/piiRedactor.js";

export function piiRedactionMiddleware(req: Request, _res: Response, next: NextFunction): void {
  const redacted = redactMessages(req.validatedChat?.messages ?? []);
  req.redactedMessages = redacted.messages;
  req.redactions = redacted.tokens;
  next();
}
