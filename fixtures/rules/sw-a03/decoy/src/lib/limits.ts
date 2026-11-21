import { Redis } from "@upstash/redis";

const redis = Redis.fromEnv();

/** Fixed-window counter: true when the key is still under its limit. */
export async function checkRateLimit(key: string, limit = 10, windowSeconds = 60): Promise<boolean> {
  const bucket = `rl:${key}:${Math.floor(Date.now() / 1000 / windowSeconds)}`;
  const count = await redis.incr(bucket);
  if (count === 1) await redis.expire(bucket, windowSeconds);
  return count <= limit;
}
