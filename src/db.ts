import mongoose from "mongoose";
import { Redis } from "ioredis";
import { config } from "./config.js";
import { logger } from "./logger.js";

export async function connectMongo(uri = config.MONGODB_URI): Promise<typeof mongoose> {
  mongoose.set("strictQuery", true);
  await mongoose.connect(uri);
  logger.info("connected to MongoDB");
  return mongoose;
}

export function createRedis(url = config.REDIS_URL): Redis {
  return new Redis(url, { lazyConnect: true, maxRetriesPerRequest: 2 });
}

export async function disconnectMongo(): Promise<void> {
  await mongoose.disconnect();
}
