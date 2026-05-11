export const config = { runtime: "nodejs" };

import jwt from "jsonwebtoken";
import { getSession, updateLastActive } from "../../lib/session-store.js";

const JWT_SECRET = process.env.JWT_SECRET;

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization"
  );
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Cache-Control", "no-store");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")
    return res.status(405).json({ status: "error", message: "Method not allowed" });

  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token)
    return res.status(401).json({ status: "error", message: "Missing token" });

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ status: "error", message: "Invalid token" });
  }
  if (decoded.typ !== "access")
    return res.status(401).json({ status: "error", message: "Invalid token type" });

  const session = await getSession(decoded.sub);
  if (!session)
    return res.status(401).json({ status: "error", message: "Session not found" });
  if (session.used)
    return res.status(401).json({ status: "error", message: "Session already used" });

  await updateLastActive(decoded.sub, Date.now());
  return res.status(200).json({ status: "success" });
}
