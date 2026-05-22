import type { Threat } from "../types.js";
import { detectPromptInjectionText } from "./injectionDetector.js";

const secretRules = [
  { id: "openai-key", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/, message: "OpenAI-style secret detected" },
  { id: "jwt", pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, message: "JWT-shaped token detected" },
  { id: "aws-access-key", pattern: /\bAKIA[0-9A-Z]{16}\b/, message: "AWS access key detected" }
];

export function validateOutput(content: string): Threat[] {
  const secretThreats: Threat[] = secretRules
    .filter((rule) => rule.pattern.test(content))
    .map((rule) => ({ type: "secret_leak", ruleId: rule.id, message: rule.message }));
  const echoedInjection = detectPromptInjectionText(content).map((threat) => ({
    ...threat,
    type: "echoed_prompt_injection"
  }));
  return [...secretThreats, ...echoedInjection];
}
