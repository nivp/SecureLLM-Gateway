import type { ErrorRequestHandler, RequestHandler } from "express";
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
  res.status(500).json({ error: "internal_error", correlationId: req.id });
};
