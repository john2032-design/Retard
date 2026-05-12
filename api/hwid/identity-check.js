export const config = { runtime: "nodejs" };

import crypto from "crypto";
import { getHwid } from "../../lib/session-store.js";

const INTERNAL_SECRET = process.env.HWID_RESET_SECRET || "";
const HWID_SALT = process.env.HWID_SALT || "";

function hashDeviceFingerprint(fingerprintData, hwidSalt) {
  if (!fingerprintData || typeof fingerprintData !== "object") return "";
  const normalized = Object.keys(fingerprintData)
    .sort()
    .map(k => `${k}:${(fingerprintData[k] || "").toString().slice(0, 256)}`)
    .join("|");
  return crypto.createHash("sha256").update(hwidSalt + normalized).digest("hex");
}

function normalizeUserAgent(ua) {
  return (ua || "")
    .replace(/Chrome\/[\d.]+|Firefox\/[\d.]+|Edge\/[\d.]+|Edg\/[\d.]+|Version\/[\d.]+|Safari\/[\d.]+|Mobile\/\w+|OPR\/[\d.]+|CriOS\/[\d.]+/gi, "")
    .replace(/\s{2,}/g, " ")
    .trim();
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  console.log(`[HWID-IDENTITY-CHECK] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[HWID-IDENTITY-CHECK] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const authHeader = req.headers.authorization || "";
  if (!authHeader || authHeader !== `Bearer ${INTERNAL_SECRET}`) {
    console.log("[HWID-IDENTITY-CHECK] Unauthorized");
    return res.status(401).json({ status: "error", message: "Unauthorized" });
  }

  const { apiKey, hwidHash, deviceHash, userAgent, ip, fingerprint } = req.body || {};
  if (!apiKey) {
    return res.status(400).json({ valid: false, reason: "Missing apiKey" });
  }

  const record = await getHwid(apiKey);
  if (!record) {
    return res.status(200).json({ valid: true, reason: "no_hwid_bound" });
  }

  if (record.hwidHash === hwidHash) {
    return res.status(200).json({ valid: true, reason: "exact_hwid_match" });
  }

  const uaMatch = record.userAgent && userAgent
    ? normalizeUserAgent(record.userAgent) === normalizeUserAgent(userAgent)
    : false;

  let fingerprintMatch = false;
  const currentFingerprint = fingerprint || {};
  const storedFingerprint = record.fingerprint || {};
  if (Object.keys(currentFingerprint).length > 0 && Object.keys(storedFingerprint).length > 0) {
    const currentDeviceHash = hashDeviceFingerprint(currentFingerprint, HWID_SALT);
    const storedDeviceHash = hashDeviceFingerprint(storedFingerprint, HWID_SALT);
    fingerprintMatch = currentDeviceHash === storedDeviceHash;
  }

  if (uaMatch || fingerprintMatch) {
    console.log(`[HWID-IDENTITY-CHECK] Device identity confirmed (UA=${uaMatch}, FP=${fingerprintMatch})`);
    return res.status(200).json({ valid: true, reason: "identity_match", uaMatch, fingerprintMatch });
  }

  console.log(`[HWID-IDENTITY-CHECK] Identity mismatch – rejecting`);
  return res.status(200).json({
    valid: false,
    reason: "device_mismatch",
    uaMatch: false,
    fingerprintMatch: false,
    message: "Device identity does not match the registered HWID"
  });
}