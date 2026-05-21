import OpenAI from "openai";
import { config, providerReady } from "../config.js";
import type { ChatMessage } from "../types.js";

export class ProviderUnavailableError extends Error {
  constructor(message = "provider_unavailable") {
    super(message);
    this.name = "ProviderUnavailableError";
  }
}

export async function createChatCompletion(params: {
  model: string;
  messages: ChatMessage[];
  maxTokens: number;
}): Promise<string> {
  if (!providerReady()) {
    throw new ProviderUnavailableError("OPENAI_API_KEY is not configured");
  }

  const client = new OpenAI({
    apiKey: config.OPENAI_API_KEY,
    baseURL: config.OPENAI_BASE_URL
  });

  const response = await client.chat.completions.create({
    model: params.model,
    messages: params.messages,
    max_tokens: params.maxTokens
  });

  return response.choices[0]?.message?.content ?? "";
}
