import Redis from "ioredis";

let redis = null;

function getClient() {
  if (!redis) {
    const url = process.env.REDIS_URL;
    if (!url) throw new Error("REDIS_URL is not set");
    const parsed = new URL(url);
    const useTls = parsed.protocol === "rediss:";
    redis = new Redis(url, {
      tls: useTls ? { rejectUnauthorized: false } : undefined,
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        return Math.min(times * 50, 2000);
      },
    });
  }
  return redis;
}

export async function checkRateLimit(apiKey, endpoint, limit, windowSeconds) {
  const client = getClient();
  const now = Math.floor(Date.now() / 1000);
  const windowKey = Math.floor(now / windowSeconds);
  const redisKey = `ratelimit:${apiKey}:${endpoint}:${windowKey}`;
  const current = await client.incr(redisKey);
  if (current === 1) {
    await client.expire(redisKey, windowSeconds + 1);
  }
  if (current > limit) {
    return { allowed: false, remaining: 0, reset: (windowKey + 1) * windowSeconds };
  }
  return { allowed: true, remaining: limit - current, reset: (windowKey + 1) * windowSeconds };
}