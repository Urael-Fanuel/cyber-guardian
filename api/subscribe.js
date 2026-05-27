const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",").map(s => s.trim()).filter(Boolean);

const state = { ipBuckets: new Map() };

function getOrigin(req) {
  return req.headers.origin || "";
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function setCors(req, res) {
  const origin = getOrigin(req);
  if (origin && isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
}

function rejectDisallowedOrigin(req, res) {
  if (isAllowedOrigin(getOrigin(req))) return false;
  res.status(403).json({ error: "Origin not allowed" });
  return true;
}

function checkRateLimit(ip) {
  const now = Date.now();
  const hourAgo = now - 3_600_000;
  const bucket = (state.ipBuckets.get(ip) || []).filter(t => t > hourAgo);
  if (bucket.length >= 10) return false;
  bucket.push(now);
  state.ipBuckets.set(ip, bucket);
  return true;
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(200).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (!checkRateLimit(ip)) return res.status(429).json({ error: "Too many requests." });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request" }); }
  }

  const email = (body?.email || "").trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email) || email.length > 200) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }

  console.log("[SUBSCRIBE]", new Date().toISOString(), "accepted");

  return res.status(200).json({ success: true, message: "Thanks! We'll keep you posted on new threats." });
};
