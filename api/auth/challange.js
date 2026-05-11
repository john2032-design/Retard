export const config = { runtime: "nodejs" };

import crypto from "crypto";
import { storeNonce } from "../../lib/session-store.js";

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

  console.log(`[CHALLENGE] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[CHALLENGE] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey) {
    console.log("[CHALLENGE] Missing API key");
    return res.status(400).json({ status: "error", message: "Missing API key" });
  }

  const isValid = await validateApiKey(apiKey);
  if (!isValid) {
    console.log("[CHALLENGE] Invalid API key");
    return res.status(401).json({ status: "error", message: "Invalid API key" });
  }

  const nonce = crypto.randomBytes(32).toString("hex");
  await storeNonce(nonce, apiKey);

  console.log("[CHALLENGE] Nonce issued");
  return res.status(200).json({ status: "success", nonce, expiresIn: 30 });
}