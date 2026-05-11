import { kv } from "@vercel/kv";

export async function getHwid(apiKey) {
  return kv.get(`hwid:${apiKey}`);
}

export async function setHwid(apiKey, data) {
  return kv.set(`hwid:${apiKey}`, JSON.stringify(data));
}

export async function hasHwid(apiKey) {
  const res = await kv.exists(`hwid:${apiKey}`);
  return res === 1;
}

export async function getSession(sessionId) {
  const raw = await kv.get(`session:${sessionId}`);
  return raw ? JSON.parse(raw) : null;
}

export async function setSession(sessionId, data) {
  return kv.set(`session:${sessionId}`, JSON.stringify(data));
}

export async function markSessionUsed(sessionId, data) {
  if (data) {
    data.used = true;
    await kv.set(`session:${sessionId}`, JSON.stringify(data));
  }
}

export async function updateLastActive(sessionId, timestamp) {
  const session = await getSession(sessionId);
  if (session) {
    session.lastActive = timestamp;
    await kv.set(`session:${sessionId}`, JSON.stringify(session));
  }
}

export async function isTokenUsed(token) {
  const res = await kv.exists(`used:${token}`);
  return res === 1;
}

export async function markTokenUsed(token) {
  await kv.set(`used:${token}`, Date.now(), { ex: 900 }); // auto‑expire after 15 min
}
