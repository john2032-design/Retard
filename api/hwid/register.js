export const config = { runtime: "nodejs" };

import crypto from "crypto";
import { hasHwid, setHwid } from "../../lib/session-store.js";

function decrypt(encryptedData, iv, authTag, keyHex) {
  const keyBuffer = Buffer.from(keyHex, "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    keyBuffer,
    Buffer.from(iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function hashHwid(plainHwid, salt) {
  return crypto
    .createHash("sha256")
    .update(salt + plainHwid)
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
    "Content-Type, Authorization, X-VW-API-Key"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  console.log(`[HWID-REGISTER] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[HWID-REGISTER] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const HWID_ENCRYPTION_KEY = process.env.HWID_ENCRYPTION_KEY;
  const HWID_SALT = process.env.HWID_SALT;

  if (!HWID_ENCRYPTION_KEY || !HWID_SALT) {
    console.log("[HWID-REGISTER] Missing encryption key or salt");
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

  const alreadyExists = await hasHwid(apiKey);
  if (alreadyExists) {
    console.log("[HWID-REGISTER] HWID already registered");
    return res.status(409).json({ status: "error", message: "HWID already registered" });
  }

  const { encryptedData, iv, authTag } = req.body || {};
  if (!encryptedData || !iv || !authTag) {
    console.log("[HWID-REGISTER] Missing encryption fields");
    return res.status(400).json({ status: "error", message: "Missing encryption fields" });
  }

  let hwid;
  try {
    hwid = decrypt(encryptedData, iv, authTag, HWID_ENCRYPTION_KEY);
  } catch {
    console.log("[HWID-REGISTER] Decryption failed");
    return res.status(400).json({ status: "error", message: "Decryption failed" });
  }

  const hashed = hashHwid(hwid, HWID_SALT);
  const userAgent = req.headers["user-agent"] || "";
  await setHwid(apiKey, {
    hwidHash: hashed,
    userAgent,
    createdAt: Date.now(),
  });

  console.log("[HWID-REGISTER] HWID registered successfully");
  return res.status(200).json({ status: "success", message: "HWID registered" });
}