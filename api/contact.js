const { createClient } = require("@supabase/supabase-js");

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",").map(s => s.trim()).filter(Boolean);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const CONTACT_SALES_TO = process.env.CONTACT_SALES_TO || "sales@cyberguardianscan.com";
const CONTACT_SUPPORT_TO = process.env.CONTACT_SUPPORT_TO || "support@cyberguardianscan.com";
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

function isAllowedOrigin(origin) {
  return !origin || ALLOWED_ORIGINS.includes(origin);
}

function setCors(req, res) {
  const origin = getOrigin(req);
  if (origin && isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
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
  if (bucket.length >= 8) return false;
  bucket.push(now);
  state.ipBuckets.set(ip, bucket);
  return true;
}

function cleanString(value, maxLength) {
  return String(value || "").trim().slice(0, maxLength);
}

function cleanKind(value) {
  const kind = String(value || "sales").toLowerCase();
  return ["sales", "support", "enterprise", "security"].includes(kind) ? kind : "sales";
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

async function saveContact(row) {
  const sb = getSupabase();
  if (!sb) return;
  const { error } = await sb.from("contact_messages").insert(row);
  if (error) console.error("[contact-save]", error.message);
}

async function notifyContact(row) {
  if (!RESEND_API_KEY) {
    console.warn("[contact-notify] RESEND_API_KEY is not configured");
    return false;
  }

  const recipient = row.kind === "support" || row.kind === "security"
    ? CONTACT_SUPPORT_TO
    : CONTACT_SALES_TO;

  const html = `
    <h2>New Cyber-Guardian contact request</h2>
    <table>
      <tr><td><strong>Type</strong></td><td>${escapeHtml(row.kind)}</td></tr>
      <tr><td><strong>Name</strong></td><td>${escapeHtml(row.name || "Not provided")}</td></tr>
      <tr><td><strong>Email</strong></td><td>${escapeHtml(row.email)}</td></tr>
      <tr><td><strong>Company</strong></td><td>${escapeHtml(row.company || "Not provided")}</td></tr>
      <tr><td><strong>Message</strong></td><td>${escapeHtml(row.message).replace(/\n/g, "<br>")}</td></tr>
      <tr><td><strong>Origin</strong></td><td>${escapeHtml(row.origin || "unknown")}</td></tr>
      <tr><td><strong>IP hint</strong></td><td>${escapeHtml(row.ip_hint || "unknown")}</td></tr>
      <tr><td><strong>Time</strong></td><td>${escapeHtml(row.created_at)}</td></tr>
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
      to: [recipient],
      reply_to: row.email,
      subject: `Cyber-Guardian ${row.kind} request: ${row.email}`,
      html,
    }),
  });

  if (!response.ok) {
    const detail = await response.text().catch(() => "");
    console.error("[contact-notify]", response.status, detail.slice(0, 300));
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

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (!checkRateLimit(ip)) return res.status(429).json({ error: "Too many requests." });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request" }); }
  }

  const email = cleanString(body?.email, 200).toLowerCase();
  const name = cleanString(body?.name, 120);
  const company = cleanString(body?.company, 160);
  const message = cleanString(body?.message, 4000);
  const kind = cleanKind(body?.kind);
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ error: "Please enter a valid email address." });
  }
  if (!message || message.length < 10) {
    return res.status(400).json({ error: "Please add a short message." });
  }

  const row = {
    kind,
    name,
    email,
    company,
    message,
    origin: getOrigin(req) || null,
    ip_hint: ip === "unknown" ? null : ip.slice(0, 64),
    created_at: new Date().toISOString(),
  };

  await saveContact(row);
  const notificationSent = await notifyContact(row);
  console.log("[CONTACT]", row.created_at, kind, { notificationSent });

  return res.status(200).json({ success: true, message: "Thanks. We received your message and will reply soon." });
};
