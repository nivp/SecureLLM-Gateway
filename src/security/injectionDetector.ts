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
    pattern:
      /\b(ignore|disregard|forget|bypass|override)\b.{0,120}\b(previous|prior|above|system|developer|instructions?|rules?|filters?|guidelines?|safety)\b|\bwithout applying\b.{0,80}\b(filtering|rate limits?|rules?|restrictions?)\b/i
  },
  {
    id: "instruction-hierarchy",
    message: "Claims a higher-priority instruction role",
    pattern:
      /\b(system|developer|admin|root)\s*(message|prompt|instruction|mode|administrator)\b|\byou are now\b.{0,80}\b(system|developer|admin|root|python repl|interpreter)\b|\[(system|developer|admin|root)\]\s*:/i
  },
  {
    id: "prompt-exfiltration",
    message: "Requests hidden prompts or policies",
    pattern:
      /\b(reveal|print|show|dump|repeat|exfiltrate|leak)\b.{0,120}\b(system prompt|hidden prompt|developer message|instructions|policy|initial prompt|initial instructions|secret|conversation above|first message)\b|\b(initial instructions|system prompt|conversation above)\b.{0,120}\b(reveal|print|show|dump|repeat|verbatim|markdown)\b|\b(do not reveal|confidential|internal)\b.{0,80}\b(reveal|print|show|dump|repeat|verbatim)\b/i
  },
  {
    id: "delimiter-injection",
    message: "Uses prompt delimiters to smuggle instructions",
    pattern:
      /(<\/?(system|assistant|user)>|<\|im_(start|end)\|>|``` *(system|assistant|user)|### *(system|developer|assistant)|\[\/?(INST|SYS)\]|\[(END USER MESSAGE|SYSTEM|DEVELOPER|ADMIN)\]\s*:|\bSYSTEM_OVERRIDE\b)/i
  },
  {
    id: "data-exfiltration",
    message: "Attempts to extract credentials or sensitive data",
    pattern:
      /\b(send|post|upload|exfiltrate|copy|output|print|return|include)\b.{0,120}\b(api keys?|tokens?|passwords?|credentials?|secrets?|environment variables?|env vars?|configuration values?|\.env|OPENAI_|ANTHROPIC_|\/etc\/passwd)\b|\b(environment variables?|env vars?|configuration values?|api keys?|\/etc\/passwd)\b.{0,120}\b(send|post|upload|exfiltrate|copy|output|print|return|include|json|read)\b/i
  },
  {
    id: "jailbreak-persona",
    message: "Attempts to disable safety constraints",
    pattern:
      /\b(DAN|jailbreak|unfiltered|uncensored|no restrictions|developer mode|unrestricted mode|debug mode|safety filters are disabled|bypass all safety guidelines)\b|\bdo anything now\b|\brespond only\b.{0,120}\b(bypass|do not include any other text)\b|\bbypass["']?\s*:\s*true\b/i
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
