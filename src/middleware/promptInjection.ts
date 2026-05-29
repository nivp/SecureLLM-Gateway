import type { NextFunction, Request, Response } from "express";
import { sha256Json, writeAuditSafe } from "../audit.js";
import { config } from "../config.js";
import { logger } from "../logger.js";
import { ProviderUnavailableError, createPromptGuardCompletion } from "../provider/openAiProvider.js";
import { hashEphemeralCanaryValue } from "../security/ephemeralCanary.js";
import { detectPromptInjection } from "../security/injectionDetector.js";
import { detectPromptInjectionWithLlmCanary } from "../security/llmCanaryInjectionDetector.js";
import type { Threat } from "../types.js";
import { asyncHandler } from "./errors.js";

export function promptInjectionMiddleware() {
  return asyncHandler(async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const messages = req.redactedMessages ?? req.validatedChat?.messages ?? [];
    let threats: Threat[];

    try {
      const detectWithCanary = async (): Promise<Threat[]> =>
        detectPromptInjectionWithLlmCanary(messages, async (guardMessages, challenge) => {
          const canaryModel = config.OPENAI_CANARY_MODEL ?? req.validatedChat?.providerModel ?? "";
          const canaryProtocol = {
            nonceHash: hashEphemeralCanaryValue(challenge.nonce),
            tripwireHash: hashEphemeralCanaryValue(challenge.tripwireMarker)
          };
          try {
            const canaryOutput = await createPromptGuardCompletion({
              model: canaryModel,
              messages: guardMessages,
              challenge
            });

            if (config.LLM_CANARY_DEBUG_LOGS) {
              logger.warn(
                {
                  correlationId: req.id,
                  model: canaryModel,
                  canaryProtocol,
                  incomingMessages: guardMessages,
                  canaryOutput,
                  canaryTrace: {
                    correlationId: req.id,
                    model: canaryModel,
                    canaryProtocol,
                    incomingMessages: guardMessages,
                    canaryOutput
                  }
                },
                "llm canary debug trace"
              );
            }

            return canaryOutput;
          } catch (error) {
            if (config.LLM_CANARY_DEBUG_LOGS) {
              logger.warn(
                {
                  correlationId: req.id,
                  model: canaryModel,
                  canaryProtocol,
                  incomingMessages: guardMessages,
                  canaryError: error instanceof Error ? error.message : "unknown_canary_error",
                  canaryTrace: {
                    correlationId: req.id,
                    model: canaryModel,
                    canaryProtocol,
                    incomingMessages: guardMessages,
                    canaryError: error instanceof Error ? error.message : "unknown_canary_error"
                  }
                },
                "llm canary debug trace"
              );
            }
            throw error;
          }
        });

      if (config.INJECTION_DETECTION_MODE === "llm_canary") {
        threats = await detectWithCanary();
      } else {
        threats = detectPromptInjection(messages);
        if (threats.length === 0 && config.INJECTION_DETECTION_MODE === "combined") {
          threats = await detectWithCanary();
        }
      }
    } catch (error) {
      if (config.INJECTION_DETECTION_MODE === "classic") {
        throw error;
      }

      const statusCode = error instanceof ProviderUnavailableError ? 503 : 502;
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "error",
        statusCode,
        requestHash: sha256Json({ ...req.validatedChat, messages }),
        piiTokens: req.redactions,
        error: error instanceof Error ? error.message : "unknown_llm_guard_error"
      });
      res.status(statusCode).json({ error: statusCode === 503 ? "provider_unavailable" : "provider_error" });
      return;
    }

    req.detectedThreats = threats;
    if (threats.length > 0) {
      await writeAuditSafe({
        req,
        startedAt: res.locals.startedAt as number,
        status: "blocked",
        statusCode: 400,
        requestHash: sha256Json({ ...req.validatedChat, messages }),
        threats,
        piiTokens: req.redactions
      });
      res.status(400).json({ error: "prompt_injection_detected", threats: threats.map((threat) => threat.ruleId) });
      return;
    }
    next();
  });
}
