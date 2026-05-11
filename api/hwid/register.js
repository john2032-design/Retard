export const config = { runtime: "nodejs" };

import crypto from "crypto";
import { hasHwid, setHwid, setPublicKey } from "../../lib/session-store.js";
import { checkRateLimit } from "../../lib/rate-limiter.js";

function hashFingerprint(fingerprint, salt) {
  return crypto
    .createHash("sha256")
    .update(salt + fingerprint)
    .digest("hex");
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

  console.log(`[HWID-REGISTER] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[HWID-REGISTER] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const clientToken = (req.headers["x-client-token"] || "").trim();
  if (!clientToken) {
    console.log("[HWID-REGISTER] Missing X-Client-Token");
    return res.status(400).json({ status: "error", message: "Missing X-Client-Token" });
  }

  const HWID_SALT = process.env.HWID_SALT;
  if (!HWID_SALT) {
    console.log("[HWID-REGISTER] Missing HWID salt");
    return res.status(500).json({ status: "error", message: "Server misconfigured" });
  }

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey) {
    console.log("[HWID-REGISTER] Missing API key");
    return res.status(400).json({ status: "error", message: "Missing API key" });
  }

  const isValid = await validateApiKey(apiKey);
  if (!isValid) {
    console.log("[HWID-REGISTER] Invalid API key");
    return res.status(401).json({ status: "error", message: "Invalid API key" });
  }

  const rateLimit = await checkRateLimit(apiKey, "hwid_register", 3, 300);
  if (!rateLimit.allowed) {
    console.log("[HWID-REGISTER] Rate limited");
    return res.status(429).json({ status: "error", message: "Too many requests" });
  }

  const alreadyExists = await hasHwid(apiKey);
  if (alreadyExists) {
    console.log("[HWID-REGISTER] HWID already registered");
    return res.status(409).json({ status: "error", message: "HWID already registered" });
  }

  const { fingerprint, publicKey } = req.body || {};
  if (!fingerprint || !publicKey) {
    console.log("[HWID-REGISTER] Missing fingerprint or publicKey");
    return res.status(400).json({ status: "error", message: "Missing fingerprint or publicKey" });
  }

  const hashed = hashFingerprint(fingerprint, HWID_SALT);
  const userAgent = req.headers["user-agent"] || "";
  await setHwid(apiKey, {
    hwidHash: hashed,
    userAgent,
    createdAt: Date.now(),
  });
  await setPublicKey(apiKey, publicKey);

  console.log("[HWID-REGISTER] HWID registered successfully");
  return res.status(200).json({ status: "success", message: "HWID registered" });
}