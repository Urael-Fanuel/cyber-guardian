const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const TOKEN_SECRET = process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

let supabaseClient = null;

function getSupabase() {
  if (!SUPABASE_URL || !SUPABASE_KEY) return null;
  if (!supabaseClient) supabaseClient = createClient(SUPABASE_URL, SUPABASE_KEY);
  return supabaseClient;
}

function setCors(req, res) {
  const origin = req.headers.origin || "";
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CG-Admin-Token");
  res.setHeader("Content-Type", "application/json");
}

function isAllowedOrigin(req) {
  const origin = req.headers.origin || "";
  return !origin || ALLOWED_ORIGINS.includes(origin);
}

function getHeader(req, name) {
  const value = req.headers?.[name] || req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function isAdminToken(req) {
  const token = String(getHeader(req, "x-cg-admin-token") || "").trim();
  if (!token || !TOKEN_SECRET) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;
  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(payload).digest("base64url");
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return false;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return parsed.role === "admin" && Number(parsed.exp || 0) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function tableMissing(error) {
  return /relation .* does not exist|schema cache|Could not find/i.test(error?.message || "");
}

async function getContactMessages(sb) {
  const { data, error } = await sb
    .from("contact_messages")
    .select("id,kind,name,email,company,message,origin,created_at")
    .order("created_at", { ascending: false })
    .limit(50);
  if (error) {
    if (tableMissing(error)) return { configured: false, rows: [] };
    throw error;
  }
  return { configured: true, rows: data || [] };
}

async function getEmailSubscribers(sb) {
  const { data, error } = await sb
    .from("email_subscribers")
    .select("email,source,origin,created_at,updated_at")
    .order("updated_at", { ascending: false })
    .limit(100);
  if (error) {
    if (tableMissing(error)) return { configured: false, rows: [] };
    throw error;
  }
  return { configured: true, rows: data || [] };
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: "Origin not allowed" });
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  if (!isAdminToken(req)) return res.status(401).json({ error: "Admin token required" });

  const sb = getSupabase();
  if (!sb) return res.status(500).json({ error: "Supabase is not configured" });

  try {
    const [contacts, subscribers] = await Promise.all([
      getContactMessages(sb),
      getEmailSubscribers(sb),
    ]);

    return res.status(200).json({
      ok: true,
      contacts,
      subscribers,
      generated_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error("[admin-leads]", err.message);
    return res.status(500).json({ error: "Leads unavailable" });
  }
};
