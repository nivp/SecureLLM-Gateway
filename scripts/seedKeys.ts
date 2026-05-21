import "dotenv/config";
import { connectMongo, disconnectMongo } from "../src/db.js";
import { ApiKeyModel } from "../src/models/ApiKey.js";
import { hashApiKey, keyIdFor } from "../src/security/hash.js";
import type { Role } from "../src/types.js";

async function upsertKey(name: string, value: string | undefined, role: Role, rateLimit: number): Promise<void> {
  if (!value) {
    console.warn(`Skipping ${name}; env var is not set`);
    return;
  }
  const { salt, hash } = hashApiKey(value);
  const keyId = keyIdFor(value);
  await ApiKeyModel.updateOne(
    { keyId },
    { $set: { keyId, salt, hash, role, rateLimitPerMinute: rateLimit, enabled: true } },
    { upsert: true }
  );
  console.log(`Seeded ${role} key ${keyId.slice(0, 12)}...`);
}

async function main(): Promise<void> {
  await connectMongo(process.env.MONGODB_URI);
  await upsertKey("CLIENT_API_KEY", process.env.CLIENT_API_KEY, "client", Number(process.env.CLIENT_RATE_LIMIT_PER_MINUTE ?? 30));
  await upsertKey("ADMIN_API_KEY", process.env.ADMIN_API_KEY, "admin", Number(process.env.ADMIN_RATE_LIMIT_PER_MINUTE ?? 120));
  await disconnectMongo();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
