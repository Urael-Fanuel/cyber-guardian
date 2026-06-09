const { createClient } = require("@supabase/supabase-js");

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",").map(s => s.trim()).filter(Boolean);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const SUBSCRIBE_NOTIFY_TO = process.env.SUBSCRIBE_NOTIFY_TO || "sales@cyberguardianscan.com";
const EMAIL_FROM = process.env.EMAIL_FROM || "Cyber-Guardian <notifications@cyberguardianscan.com>";

const state = { ipBuckets: new Map() };
let supabaseClient = null;

function getSupabase() {
  if (!SUPABASE_URL || !SUPABASE_KEY) return null;
  if (!supabaseClient) supabaseClient = createClient(SUPABASE_URL, SUPABASE_KEY);
  return supabaseClient;
}

function getOrigin(req) {
  return req.headers.origin || "";
}

function clientIp(req) {
  const real = req.headers["x-real-ip"];
  if (real) return String(real).trim();
  const xff = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : "unknown";
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

async function saveSubscriber(email, ip, origin) {
  const sb = getSupabase();
  if (!sb) return;

  const { error } = await sb
    .from("email_subscribers")
    .upsert({
      email,
      source: "threat_alert_signup",
      ip_hint: ip === "unknown" ? null : ip.slice(0, 64),
      origin: origin || null,
      updated_at: new Date().toISOString(),
    }, { onConflict: "email" });

  if (error) console.error("[subscribe-save]", error.message);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function notifySales(email, ip, origin) {
  if (!RESEND_API_KEY) {
    console.warn("[subscribe-notify] RESEND_API_KEY is not configured");
    return false;
  }

  const html = `
    <h2>New Cyber-Guardian lead</h2>
    <p>A visitor asked to get Cyber-Guardian security updates for AI tools and code threats.</p>
    <table>
      <tr><td><strong>Email</strong></td><td>${escapeHtml(email)}</td></tr>
      <tr><td><strong>Source</strong></td><td>Threat alert signup</td></tr>
      <tr><td><strong>Origin</strong></td><td>${escapeHtml(origin || "unknown")}</td></tr>
      <tr><td><strong>IP hint</strong></td><td>${escapeHtml(ip)}</td></tr>
      <tr><td><strong>Time</strong></td><td>${escapeHtml(new Date().toISOString())}</td></tr>
    </table>
  `;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: EMAIL_FROM,
      to: [SUBSCRIBE_NOTIFY_TO],
      reply_to: email,
      subject: `New Cyber-Guardian lead: ${email}`,
      html,
    }),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    console.error("[subscribe-notify]", response.status, detail.slice(0, 300));
    return false;
  }

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

  const ip = clientIp(req);
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

  await saveSubscriber(email, ip, getOrigin(req));
  const notificationSent = await notifySales(email, ip, getOrigin(req));
  console.log("[SUBSCRIBE]", new Date().toISOString(), "accepted", { notificationSent });

  return res.status(200).json({ success: true, message: "Thanks! We'll keep you posted on new threats." });
};
