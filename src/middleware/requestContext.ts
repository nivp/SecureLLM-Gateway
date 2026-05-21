import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

export function requestContext(req: Request, res: Response, next: NextFunction): void {
  req.id = req.header("x-correlation-id") ?? randomUUID();
  res.setHeader("x-correlation-id", req.id);
  next();
}
