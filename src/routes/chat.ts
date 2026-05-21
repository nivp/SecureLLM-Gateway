import type { Router } from "express";
import { Router as createRouter } from "express";
import { sha256Json, writeAudit } from "../audit.js";
import { ProviderUnavailableError, createChatCompletion } from "../provider/openAiProvider.js";
import { validateOutput } from "../security/outputValidator.js";

export function chatRouter(): Router {
  const router = createRouter();
  router.post("/v1/chat", async (req, res) => {
    const startedAt = res.locals.startedAt as number;
    const requestHash = sha256Json({ ...req.validatedChat, messages: req.redactedMessages });

    try {
      const chat = req.validatedChat;
      if (!chat) {
        res.status(500).json({ error: "missing_chat_context" });
        return;
      }

      const content = await createChatCompletion({
        model: chat.providerModel,
        messages: req.redactedMessages ?? chat.messages,
        maxTokens: chat.max_tokens
      });

      const threats = validateOutput(content);
      if (threats.length > 0) {
        await writeAudit({
          req,
          startedAt,
          status: "blocked",
          statusCode: 400,
          requestHash,
          responseHash: sha256Json(content),
          threats,
          piiTokens: req.redactions
        });
        res.status(400).json({ error: "unsafe_model_output", threats: threats.map((threat) => threat.ruleId) });
        return;
      }

      await writeAudit({
        req,
        startedAt,
        status: "allowed",
        statusCode: 200,
        requestHash,
        responseHash: sha256Json(content),
        piiTokens: req.redactions
      });
      res.json({ model: chat.model, providerModel: chat.providerModel, message: { role: "assistant", content } });
    } catch (error) {
      const statusCode = error instanceof ProviderUnavailableError ? 503 : 502;
      await writeAudit({
        req,
        startedAt,
        status: "error",
        statusCode,
        requestHash,
        piiTokens: req.redactions,
        error: error instanceof Error ? error.message : "unknown_error"
      });
      res.status(statusCode).json({ error: statusCode === 503 ? "provider_unavailable" : "provider_error" });
    }
  });
  return router;
}
