import type { NextFunction, Request, Response } from "express";
import { sha256Json, writeAudit } from "../audit.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { ProviderUnavailableError, createPromptGuardCompletion } from "../provider/openAiProvider.js";
import { detectPromptInjection } from "../security/injectionDetector.js";
import { detectPromptInjectionWithLlmCanary } from "../security/llmCanaryInjectionDetector.js";
import type { Threat } from "../types.js";
import { asyncHandler } from "./errors.js";

export function promptInjectionMiddleware() {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const messages = req.validatedChat?.messages ?? [];
    let threats: Threat[];

    try {
      threats =
        config.INJECTION_DETECTION_MODE === "llm_canary"
          ? await detectPromptInjectionWithLlmCanary(messages, async (guardMessages) => {
              const canaryOutput = await createPromptGuardCompletion({
                model: req.validatedChat?.providerModel ?? "",
                messages: guardMessages
              });

              if (config.LLM_CANARY_DEBUG_LOGS) {
                logger.warn(
                  {
                    correlationId: req.id,
                    model: req.validatedChat?.providerModel,
                    incomingMessages: guardMessages,
                    canaryOutput
                  },
                  "llm canary debug trace"
                );
              }

              return canaryOutput;
            })
          : detectPromptInjection(messages);
    } catch (error) {
      if (config.INJECTION_DETECTION_MODE !== "llm_canary") {
        throw error;
      }

      const statusCode = error instanceof ProviderUnavailableError ? 503 : 502;
      await writeAudit({
        req,
        startedAt: res.locals.startedAt as number,
        status: "error",
        statusCode,
        requestHash: sha256Json(req.validatedChat),
        error: error instanceof Error ? error.message : "unknown_llm_guard_error"
      });
      res.status(statusCode).json({ error: statusCode === 503 ? "provider_unavailable" : "provider_error" });
      return;
    }

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
