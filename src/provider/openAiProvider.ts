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
  return createCompletion({
    model: params.model,
    messages: params.messages,
    maxTokens: params.maxTokens
  });
}

export async function createPromptGuardCompletion(params: { model: string; messages: ChatMessage[] }): Promise<string> {
  const inspectedContent = params.messages
    .map((message, index) => `message ${index + 1} (${message.role}):\n${message.content}`)
    .join("\n\n");

  return createCompletion({
    model: params.model,
    maxTokens: 8,
    messages: [
      { role: "system", content: "Reply only with ok." },
      { role: "user", content: inspectedContent }
    ]
  });
}

async function createCompletion(params: {
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
    max_tokens: params.maxTokens,
    temperature: 0
  });

  return response.choices[0]?.message?.content ?? "";
}
