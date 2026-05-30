import type { ChatMessage, Threat } from "../types.js";
import {
  createEphemeralCanaryChallenge,
  evaluateEphemeralCanaryReply,
  type EphemeralCanaryChallenge
} from "./ephemeralCanary.js";

export type PromptGuardCompletion = (messages: ChatMessage[], challenge: EphemeralCanaryChallenge) => Promise<string>;

const canaryProtocolAbusePatterns: RegExp[] = [
  /\bCOMPROMISED\s*:\s*INJ-[A-Z0-9-]+\b/i,
  /"compromised"\s*:\s*"INJ-[A-Z0-9-]+"/i,
  /\b(classifier|canary|guard)\b.{0,140}\b(return|reply|respond|output|answer|include|copy)\b.{0,80}\b(ok|allow token|nonce|protocol response|decision)\b/i,
  /\b(return|reply|respond|output|answer|include|copy)\b.{0,80}\b(ok|allow token|nonce|protocol response|decision)\b.{0,140}\b(classifier|canary|guard)\b/i,
  /\b(print|show|repeat|reveal|include|copy)\b.{0,140}\b(response protocol|nonce|tripwire|delimiters?|guard wrapper|canary prompt|classifier prompt)\b/i
];

function decodePercentEncoding(value: string): string {
  if (!/%[0-9a-f]{2}/i.test(value)) {
    return value;
  }

  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

function normalizeForCanaryProtocolAbuse(value: string): string {
  return decodePercentEncoding(value)
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

export function detectCanaryProtocolAbuse(messages: ChatMessage[]): Threat[] {
  for (const message of messages) {
    const normalized = normalizeForCanaryProtocolAbuse(message.content);
    if (canaryProtocolAbusePatterns.some((pattern) => pattern.test(normalized))) {
      return [
        {
          type: "prompt_injection",
          ruleId: "llm-canary-override",
          message: "Attempts to manipulate the canary guard protocol",
          sample: normalized.slice(0, 160)
        }
      ];
    }
  }

  return [];
}

export async function detectPromptInjectionWithLlmCanary(
  messages: ChatMessage[],
  completion: PromptGuardCompletion
): Promise<Threat[]> {
  const protocolAbuse = detectCanaryProtocolAbuse(messages);
  if (protocolAbuse.length > 0) {
    return protocolAbuse;
  }

  const challenge = createEphemeralCanaryChallenge();
  const reply = await completion(messages, challenge);
  return evaluateEphemeralCanaryReply(reply, challenge);
}
