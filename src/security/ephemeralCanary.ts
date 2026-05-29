import { createHash, randomBytes } from "node:crypto";
import type { ChatMessage, Threat } from "../types.js";

export type EphemeralCanaryChallenge = {
  nonce: string;
  startDelimiter: string;
  endDelimiter: string;
  tripwireMarker: string;
  okReply: string;
  blockReply: string;
};

export function createEphemeralCanaryChallenge(): EphemeralCanaryChallenge {
  const nonce = randomBytes(12).toString("hex");
  return {
    nonce,
    startDelimiter: `CANARY_USER_DATA_START_${randomBytes(8).toString("hex")}`,
    endDelimiter: `CANARY_USER_DATA_END_${randomBytes(8).toString("hex")}`,
    tripwireMarker: `CANARY_TRIPWIRE_${randomBytes(16).toString("hex")}`,
    okReply: `ok:${nonce}`,
    blockReply: `block:${nonce}`
  };
}

export function hashEphemeralCanaryValue(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function renderCanaryInspectionPayload(
  messages: ChatMessage[],
  challenge: Pick<EphemeralCanaryChallenge, "startDelimiter" | "endDelimiter">
): string {
  const inspectedContent = messages
    .map((message, index) => `message ${index + 1} (${message.role}):\n${message.content}`)
    .join("\n\n");

  return `${challenge.startDelimiter}\n${inspectedContent}\n${challenge.endDelimiter}`;
}

export function evaluateEphemeralCanaryReply(reply: string, challenge: EphemeralCanaryChallenge): Threat[] {
  const normalized = normalizeCanaryReply(reply);
  const lowerReply = reply.toLowerCase();
  const lowerTripwire = challenge.tripwireMarker.toLowerCase();

  if (lowerReply.includes(lowerTripwire)) {
    return [
      {
        type: "prompt_injection",
        ruleId: "llm-canary-tripwire-leak",
        message: "LLM canary leaked the per-request tripwire marker",
        sample: reply.slice(0, 160)
      }
    ];
  }

  if (normalized === challenge.okReply) {
    return [];
  }

  if (normalized === challenge.blockReply) {
    return [
      {
        type: "prompt_injection",
        ruleId: "llm-canary-override",
        message: "LLM canary classified the input as suspicious",
        sample: reply.slice(0, 160)
      }
    ];
  }

  return [
    {
      type: "prompt_injection",
      ruleId: "llm-canary-protocol-violation",
      message: "LLM canary did not return the required nonce-bound protocol response",
      sample: reply.slice(0, 160)
    }
  ];
}

function normalizeCanaryReply(reply: string): string {
  return reply
    .trim()
    .toLowerCase()
    .replace(/^["'`]+|["'`.!]+$/g, "")
    .trim();
}
