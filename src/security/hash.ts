import { createHash, randomBytes, pbkdf2Sync, timingSafeEqual } from "node:crypto";

const ITERATIONS = 120_000;
const KEY_LENGTH = 32;
const DIGEST = "sha256";

export function keyIdFor(apiKey: string): string {
  return createHash("sha256").update(apiKey).digest("hex");
}

export function hashApiKey(apiKey: string, salt = randomBytes(16).toString("hex")): { salt: string; hash: string } {
  const hash = pbkdf2Sync(apiKey, salt, ITERATIONS, KEY_LENGTH, DIGEST).toString("hex");
  return { salt, hash };
}

export function verifyApiKey(apiKey: string, salt: string, expectedHash: string): boolean {
  const actual = Buffer.from(hashApiKey(apiKey, salt).hash, "hex");
  const expected = Buffer.from(expectedHash, "hex");
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}
