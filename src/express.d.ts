import type { AuthenticatedKey, ChatMessage, RedactionToken, Threat } from "./types.js";

declare global {
  namespace Express {
    interface Request {
      id: string;
      auth?: AuthenticatedKey;
      validatedChat?: {
        model: string;
        providerModel: string;
        messages: ChatMessage[];
        max_tokens: number;
      };
      redactedMessages?: ChatMessage[];
      redactions?: RedactionToken[];
      detectedThreats?: Threat[];
    }
  }
}

export {};
