import type { ErrorRequestHandler, RequestHandler } from "express";
import { sha256Json, writeAuditSafe } from "../audit.js";
import { logger } from "../logger.js";

export function asyncHandler(handler: RequestHandler): RequestHandler {
  return (req, res, next) => {
    Promise.resolve()
      .then(() => handler(req, res, next))
      .catch(next);
  };
}

export const errorHandler: ErrorRequestHandler = (error, req, res, next) => {
  if (res.headersSent) {
    next(error);
    return;
  }

  logger.error({ err: error, correlationId: req.id }, "request failed");
  void writeAuditSafe({
    req,
    startedAt: (res.locals.startedAt as number | undefined) ?? Date.now(),
    status: "error",
    statusCode: 500,
    requestHash: sha256Json({ path: req.path, method: req.method, body: req.body, query: req.query }),
    error: error instanceof Error ? error.message : "unknown_error"
  }).finally(() => {
    res.status(500).json({ error: "internal_error", correlationId: req.id });
  });
};
