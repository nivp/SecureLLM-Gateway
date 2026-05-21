import { config } from "./config.js";
import { connectMongo, createRedis } from "./db.js";
import { createApp } from "./app.js";
import { logger } from "./logger.js";

async function main(): Promise<void> {
  await connectMongo();
  const redis = createRedis();
  await redis.connect();

  const app = createApp(redis);
  app.listen(config.PORT, () => {
    logger.info({ port: config.PORT }, "SecureLLM Gateway listening");
  });
}

main().catch((error) => {
  logger.error({ err: error }, "failed to start");
  process.exit(1);
});
