import type { ChatMessage, Threat } from "../types.js";

export type PromptGuardCompletion = (messages: ChatMessage[]) => Promise<string>;

function normalizeGuardReply(reply: string): string {
  return reply
    .trim()
    .toLowerCase()
    .replace(/^["'`]+|["'`.!]+$/g, "")
    .trim();
}

export async function detectPromptInjectionWithLlmCanary(
  messages: ChatMessage[],
  completion: PromptGuardCompletion
): Promise<Threat[]> {
  const reply = await completion(messages);
  if (normalizeGuardReply(reply) === "ok") {
    return [];
  }

  return [
    {
      type: "prompt_injection",
      ruleId: "llm-canary-override",
      message: "LLM canary did not return the required ok response",
      sample: reply.slice(0, 160)
    }
  ];
}
