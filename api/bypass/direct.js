export const config = { runtime: "nodejs" };

import jwt from "jsonwebtoken";
import {
  getHwid,
  getSession,
  markSessionUsed,
  isTokenUsed,
  markTokenUsed,
} from "../../lib/session-store.js";

const JWT_SECRET = process.env.JWT_SECRET;
const BT_API_KEY = process.env.BT_API_KEY;
const LOOTLINK_BASE_URL = process.env.LOOTLINK_BASE_URL; // e.g. https://lootlinkcom.vercel.app
const HEARTBEAT_WINDOW_MS = 20000;

const ALLOWED_TARGET_HOSTS = new Set([
  "linkvertise.com","mboost.me","cuty.io","rekonise.com","ouo.io","work.ink",
  "hydrogen.lat","auth.platorelay.com","fast-links.org","rapid-links.com",
  "rapid-links.net","lockr.so","link-unlocker.com","pandadevelopment.net",
  "new.pandadevelopment.net","cuttlinks.com","trigonevo.com","rinku.pro",
  "7mb.io","link-hub.net","direct-links.net","direct-links.org","link-to.net",
  "direct-link.net","link-center.net","link-target.net","link-target.org"
]);

function verifyAccess(req) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return null;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.typ !== "access") return null;
    return { token, sessionId: decoded.sub };
  } catch {
    return null;
  }
}

async function validateApiKey(apiKey) {
  if (!apiKey) return false;
  try {
    const res = await fetch(
      `https://apikey-nine.vercel.app/api/key/info/${apiKey}`
    );
    const data = await res.json();
    return data.valid === true;
  } catch {
    return false;
  }
}

function parseBody(req) {
  try {
    return typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return null;
  }
}

function validateUrl(raw) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, error: "INVALID_URL" };
  }
  if (!["http:", "https:"].includes(parsed.protocol))
    return { ok: false, error: "INVALID_URL" };
  const host = parsed.hostname.toLowerCase();
  const matchesAllowed = [...ALLOWED_TARGET_HOSTS].some(
    (allowed) => host === allowed || host.endsWith(`.${allowed}`)
  );
  if (!matchesAllowed) return { ok: false, error: "HOST_NOT_ALLOWED" };
  return { ok: true, url: parsed.toString() };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-VW-API-Key"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")
    return res.status(405).json({ status: "error", message: "Method not allowed" });

  if (!JWT_SECRET || !BT_API_KEY || !LOOTLINK_BASE_URL)
    return res.status(500).json({ status: "error", message: "Server misconfigured" });

  const auth = verifyAccess(req);
  if (!auth)
    return res.status(401).json({ status: "error", message: "Unauthorized" });

  const { token, sessionId } = auth;

  const alreadyUsed = await isTokenUsed(token);
  if (alreadyUsed)
    return res.status(401).json({ status: "error", message: "Token already used" });

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey)
    return res.status(400).json({ status: "error", message: "Missing VW API key" });

  const isKeyValid = await validateApiKey(apiKey);
  if (!isKeyValid)
    return res.status(401).json({ status: "error", message: "Invalid API key" });

  const storedHwid = await getHwid(apiKey);
  if (!storedHwid)
    return res.status(400).json({ status: "error", message: "HWID not registered" });

  const userAgent = req.headers["user-agent"] || "";
  if (storedHwid.userAgent !== userAgent)
    return res.status(403).json({ status: "error", message: "User-Agent mismatch" });

  const session = await getSession(sessionId);
  if (!session)
    return res.status(401).json({ status: "error", message: "Session not found" });

  if (session.used)
    return res.status(401).json({ status: "error", message: "Session already used" });

  const now = Date.now();
  if (now - session.lastActive > HEARTBEAT_WINDOW_MS)
    return res.status(401).json({
      status: "error",
      message: "Heartbeat expired, please heartbeat again",
    });

  const body = parseBody(req);
  if (!body)
    return res.status(400).json({ status: "error", message: "Invalid JSON body" });

  const { url } = body;
  if (!url || typeof url !== "string")
    return res.status(400).json({ status: "error", message: "Missing url parameter" });

  const check = validateUrl(url);
  if (!check.ok)
    return res.status(400).json({ status: "error", message: check.error });

  try {
    const upstream = await fetch(
      `${LOOTLINK_BASE_URL}/api/bypass?url=${encodeURIComponent(check.url)}`
    );
    const text = await upstream.text();

    await markSessionUsed(sessionId, session);
    await markTokenUsed(token);

    res.status(upstream.status);
    res.setHeader("Content-Type", "application/json");
    return res.send(text);
  } catch {
    await markSessionUsed(sessionId, session);
    await markTokenUsed(token);

    return res.status(500).json({ status: "error", message: "Proxy failed" });
  }
}
