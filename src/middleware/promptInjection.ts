import type { NextFunction, Request, Response } from "express";
import { sha256Json, writeAudit } from "../audit.js";
import { detectPromptInjection } from "../security/injectionDetector.js";
import { asyncHandler } from "./errors.js";

export function promptInjectionMiddleware() {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const threats = detectPromptInjection(req.validatedChat?.messages ?? []);
    req.detectedThreats = threats;
    if (threats.length > 0) {
      await writeAudit({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 400,
        requestHash: sha256Json(req.validatedChat),
        threats
      });
      res.status(400).json({ error: "prompt_injection_detected", threats: threats.map((threat) => threat.ruleId) });
      return;
    }
    next();
  });
}
