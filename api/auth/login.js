export const config = { runtime: "nodejs" };

import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { getHwid, setSession } from "../../lib/session-store.js";

const JWT_SECRET = process.env.JWT_SECRET;
const REFRESH_SECRET = process.env.REFRESH_SECRET;

function signAccess(sessionId) {
  return jwt.sign({ sub: sessionId, typ: "access" }, JWT_SECRET);
}

function signRefresh(sessionId) {
  return jwt.sign({ sub: sessionId, typ: "refresh" }, REFRESH_SECRET, {
    expiresIn: "14d",
  });
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

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-VW-API-Key"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")
    return res.status(405).json({ status: "error", message: "Method not allowed" });

  if (!JWT_SECRET || !REFRESH_SECRET)
    return res.status(500).json({ status: "error", message: "Server misconfigured" });

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey)
    return res.status(400).json({ status: "error", message: "Missing API key" });

  const isValid = await validateApiKey(apiKey);
  if (!isValid)
    return res.status(401).json({ status: "error", message: "Invalid API key" });

  const stored = await getHwid(apiKey);
  if (!stored)
    return res.status(400).json({ status: "error", message: "HWID not registered" });

  const userAgent = req.headers["user-agent"] || "";
  if (stored.userAgent !== userAgent)
    return res.status(403).json({ status: "error", message: "User-Agent mismatch" });

  const sessionId = randomUUID();
  const accessToken = signAccess(sessionId);
  const refreshToken = signRefresh(sessionId);

  const now = Date.now();
  await setSession(sessionId, {
    createdAt: now,
    lastActive: now,
    used: false,
    hwidHash: stored.hwidHash,
    apiKey,
  });

  res.setHeader("Set-Cookie", [
    `refresh_token=${refreshToken}; HttpOnly; Path=/api/auth/refresh; Max-Age=1209600; SameSite=None; Secure`,
  ]);

  return res.status(200).json({ status: "success", accessToken, expiresIn: "never" });
}
