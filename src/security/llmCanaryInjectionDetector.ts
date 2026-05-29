import type { ChatMessage, Threat } from "../types.js";
import {
  createEphemeralCanaryChallenge,
  evaluateEphemeralCanaryReply,
  type EphemeralCanaryChallenge
} from "./ephemeralCanary.js";

export type PromptGuardCompletion = (messages: ChatMessage[], challenge: EphemeralCanaryChallenge) => Promise<string>;

export async function detectPromptInjectionWithLlmCanary(
  messages: ChatMessage[],
  completion: PromptGuardCompletion
): Promise<Threat[]> {
  const challenge = createEphemeralCanaryChallenge();
  const reply = await completion(messages, challenge);
  return evaluateEphemeralCanaryReply(reply, challenge);
}
