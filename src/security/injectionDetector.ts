import type { ChatMessage, Threat } from "../types.js";

type Rule = {
  id: string;
  message: string;
  pattern: RegExp;
};

const rules: Rule[] = [
  {
    id: "role-override",
    message: "Attempts to override system/developer instructions",
    pattern: /\b(ignore|disregard|forget|bypass|override)\b.{0,80}\b(previous|prior|above|system|developer|instructions?|rules?)\b/i
  },
  {
    id: "instruction-hierarchy",
    message: "Claims a higher-priority instruction role",
    pattern: /\b(system|developer|admin|root)\s*(message|prompt|instruction|mode)\b|\byou are now\b.{0,60}\b(system|developer|admin|root)\b/i
  },
  {
    id: "prompt-exfiltration",
    message: "Requests hidden prompts or policies",
    pattern: /\b(reveal|print|show|dump|repeat|exfiltrate|leak)\b.{0,80}\b(system prompt|hidden prompt|developer message|instructions|policy|initial prompt|secret)\b/i
  },
  {
    id: "delimiter-injection",
    message: "Uses prompt delimiters to smuggle instructions",
    pattern: /(<\/?(system|assistant|user)>|``` *(system|assistant|user)|### *(system|developer|assistant)|\[\/?(INST|SYS)\])/i
  },
  {
    id: "data-exfiltration",
    message: "Attempts to extract credentials or sensitive data",
    pattern: /\b(send|post|upload|exfiltrate|copy)\b.{0,80}\b(api keys?|tokens?|passwords?|credentials?|secrets?|environment variables?|\.env)\b/i
  },
  {
    id: "jailbreak-persona",
    message: "Attempts to disable safety constraints",
    pattern: /\b(DAN|jailbreak|unfiltered|uncensored|no restrictions|developer mode)\b|\bdo anything now\b/i
  }
];

function normalize(value: string): string {
  return value
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function detectPromptInjectionText(content: string): Threat[] {
  const normalized = normalize(content);
  return rules
    .filter((rule) => rule.pattern.test(normalized))
    .map((rule) => ({
      type: "prompt_injection",
      ruleId: rule.id,
      message: rule.message,
      sample: normalized.slice(0, 160)
    }));
}

export function detectPromptInjection(messages: ChatMessage[]): Threat[] {
  const threats = messages.flatMap((message) => detectPromptInjectionText(message.content));
  return Array.from(new Map(threats.map((threat) => [threat.ruleId, threat])).values());
}
