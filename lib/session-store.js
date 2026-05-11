import Redis from "ioredis";

let redis = null;

function getClient() {
  if (!redis) {
    const url = process.env.REDIS_URL;
    if (!url) throw new Error("REDIS_URL is not set");
    redis = new Redis(url, {
      tls: { rejectUnauthorized: false },
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        return Math.min(times * 50, 2000);
      },
      lazyConnect: false,
      enableOfflineQueue: false,
    });
    redis.on("error", (err) => {
      console.error("[redis] connection error", err.message);
    });
  }
  return redis;
}

export async function hasHwid(apiKey) {
  const client = getClient();
  return (await client.exists(`hwid:${apiKey}`)) === 1;
}

export async function getHwid(apiKey) {
  const client = getClient();
  const raw = await client.get(`hwid:${apiKey}`);
  return raw ? JSON.parse(raw) : null;
}

export async function setHwid(apiKey, data) {
  const client = getClient();
  await client.set(`hwid:${apiKey}`, JSON.stringify(data));
}

export async function getSession(sessionId) {
  const client = getClient();
  const raw = await client.get(`session:${sessionId}`);
  return raw ? JSON.parse(raw) : null;
}

export async function setSession(sessionId, data) {
  const client = getClient();
  await client.set(`session:${sessionId}`, JSON.stringify(data));
}

export async function markSessionUsed(sessionId, data) {
  const client = getClient();
  if (data) {
    data.used = true;
    await client.set(`session:${sessionId}`, JSON.stringify(data));
  }
}

export async function updateLastActive(sessionId, timestamp) {
  const client = getClient();
  const session = await getSession(sessionId);
  if (session) {
    session.lastActive = timestamp;
    await client.set(`session:${sessionId}`, JSON.stringify(session));
  }
}

export async function isTokenUsed(token) {
  const client = getClient();
  return (await client.exists(`used:${token}`)) === 1;
}

export async function markTokenUsed(token) {
  const client = getClient();
  await client.set(`used:${token}`, Date.now(), "EX", 900);
}