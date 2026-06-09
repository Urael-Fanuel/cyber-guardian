const crypto = require("crypto");

const ADMIN_USERNAME = process.env.CG_ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.CG_ADMIN_PASSWORD || process.env.CG_ADMIN_BYPASS_SECRET || "";
const TOKEN_SECRET = process.env.CG_ADMIN_TOKEN_SECRET || process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ADMIN_TOKEN_VERSION = String(process.env.CG_ADMIN_TOKEN_VERSION || "1");
const ADMIN_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
  .split(",").map(s => s.trim()).filter(Boolean);

function setCors(req, res) {
  const origin = req.headers.origin || "";
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

function isAllowedOrigin(req) {
  const origin = req.headers.origin || "";
  return !origin || ALLOWED_ORIGINS.includes(origin);
}

function b64url(input) {
  return Buffer.from(input).toString("base64url");
}

function sign(payload) {
  return crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("base64url");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function createToken(username) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(JSON.stringify({
    sub: username,
    role: "admin",
    ver: ADMIN_TOKEN_VERSION,
    iat: now,
    exp: now + ADMIN_TOKEN_TTL_SECONDS,
  }));
  return `${payload}.${sign(payload)}`;
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: "Origin not allowed" });
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  if (!ADMIN_PASSWORD || !TOKEN_SECRET) return res.status(500).json({ error: "Admin login is not configured" });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request format" }); }
  }

  const username = String(body?.username || "").trim();
  const password = String(body?.password || "");

  if (!safeEqual(username, ADMIN_USERNAME) || !safeEqual(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: "Invalid username or password" });
  }

  return res.status(200).json({
    ok: true,
    token: createToken(username),
    expires_in: ADMIN_TOKEN_TTL_SECONDS,
  });
};
