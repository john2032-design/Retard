export const config = { runtime: "nodejs" };

import crypto from "crypto";
import { hasHwid, setHwid } from "../../lib/session-store.js";

const HWID_ENCRYPTION_KEY = process.env.HWID_ENCRYPTION_KEY;
const HWID_SALT = process.env.HWID_SALT;
const HWID_KEY_BUFFER = Buffer.from(HWID_ENCRYPTION_KEY, "hex");

function decrypt(encryptedData, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    HWID_KEY_BUFFER,
    Buffer.from(iv, "hex")
  );
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  let decrypted = decipher.update(encryptedData, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function hashHwid(plainHwid) {
  return crypto
    .createHash("sha256")
    .update(HWID_SALT + plainHwid)
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

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")
    return res.status(405).json({ status: "error", message: "Method not allowed" });

  const apiKey = (req.headers["x-vw-api-key"] || "").trim();
  if (!apiKey)
    return res.status(400).json({ status: "error", message: "Missing API key" });

  const isValid = await validateApiKey(apiKey);
  if (!isValid)
    return res.status(401).json({ status: "error", message: "Invalid API key" });

  const alreadyExists = await hasHwid(apiKey);
  if (alreadyExists)
    return res.status(409).json({ status: "error", message: "HWID already registered" });

  const { encryptedData, iv, authTag } = req.body || {};
  if (!encryptedData || !iv || !authTag)
    return res.status(400).json({ status: "error", message: "Missing encryption fields" });

  let hwid;
  try {
    hwid = decrypt(encryptedData, iv, authTag);
  } catch {
    return res.status(400).json({ status: "error", message: "Decryption failed" });
  }

  const hashed = hashHwid(hwid);
  const userAgent = req.headers["user-agent"] || "";
  await setHwid(apiKey, {
    hwidHash: hashed,
    userAgent,
    createdAt: Date.now(),
  });

  return res.status(200).json({ status: "success", message: "HWID registered" });
}
