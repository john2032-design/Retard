export const config = { runtime: "nodejs" };

import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { getHwid, setSession } from "../../lib/session-store.js";
import { checkRateLimit } from "../../lib/rate-limiter.js";

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
    "Content-Type, Authorization, X-VW-API-Key, X-Client-Token"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  console.log(`[LOGIN] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[LOGIN] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const clientToken = (req.headers["x-client-token"] || "").trim();
  if (!clientToken) {
    console.log("[LOGIN] Missing X-Client-Token");
    return res.status(400).json({ status: "error", message: "Missing X-Client-Token" });
  }

  if (!JWT_SECRET || !REFRESH_SECRET) {
    console.log("[LOGIN] JWT secrets missing");
    return res.status(500).json({ status: "error", message: "Server misconfigured" });
  }

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey) {
    console.log("[LOGIN] Missing API key");
    return res.status(400).json({ status: "error", message: "Missing API key" });
  }

  const isValid = await validateApiKey(apiKey);
  if (!isValid) {
    console.log("[LOGIN] Invalid API key");
    return res.status(401).json({ status: "error", message: "Invalid API key" });
  }

  const rateLimit = await checkRateLimit(apiKey, "login", 10, 60);
  if (!rateLimit.allowed) {
    console.log("[LOGIN] Rate limited");
    return res.status(429).json({ status: "error", message: "Too many requests" });
  }

  const stored = await getHwid(apiKey);
  if (!stored) {
    console.log("[LOGIN] HWID not registered");
    return res.status(400).json({ status: "error", message: "HWID not registered" });
  }

  const userAgent = req.headers["user-agent"] || "";
  if (stored.userAgent !== userAgent) {
    console.log("[LOGIN] User-Agent mismatch");
    return res.status(403).json({ status: "error", message: "User-Agent mismatch" });
  }

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

  console.log("[LOGIN] Session created successfully");
  return res.status(200).json({ status: "success", accessToken, expiresIn: "never" });
}