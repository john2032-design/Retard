export const config = { runtime: "nodejs" };

import { hasHwid } from "../../lib/session-store.js";

const RESET_SECRET = process.env.HWID_RESET_SECRET || "";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  console.log(`[HWID-RESET] ${req.method} ${req.url}`);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") {
    console.log("[HWID-RESET] Method not allowed");
    return res.status(405).json({ status: "error", message: "Method not allowed" });
  }

  const authHeader = req.headers.authorization || "";
  if (!authHeader || authHeader !== `Bearer ${RESET_SECRET}`) {
    console.log("[HWID-RESET] Unauthorized");
    return res.status(401).json({ status: "error", message: "Unauthorized" });
  }

  const { apiKey } = req.body || {};
  if (!apiKey) {
    console.log("[HWID-RESET] Missing apiKey");
    return res.status(400).json({ status: "error", message: "Missing apiKey" });
  }

  const exists = await hasHwid(apiKey);
  if (!exists) {
    console.log("[HWID-RESET] No HWID binding found");
    return res.status(404).json({ status: "error", message: "No HWID binding found for this key" });
  }

  const { kv } = await import("@vercel/kv");
  await kv.del(`hwid:${apiKey}`);
  console.log("[HWID-RESET] HWID binding cleared");

  return res.status(200).json({ status: "success", message: "HWID binding cleared" });
}