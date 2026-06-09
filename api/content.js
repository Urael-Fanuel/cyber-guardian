const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_BYPASS_SECRET = process.env.CG_ADMIN_BYPASS_SECRET || "";
const ADMIN_TOKEN_SECRET = process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
  .split(",").map(s => s.trim()).filter(Boolean);

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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CG-Admin-Secret, X-CG-Admin-Token");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Content-Type", "application/json");
}

function getHeader(req, name) {
  const value = req.headers?.[name] || req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function isAllowedOrigin(req) {
  const origin = req.headers.origin || "";
  return !origin || ALLOWED_ORIGINS.includes(origin);
}

function isAdmin(req) {
  const provided = String(getHeader(req, "x-cg-admin-secret") || "").trim();
  if (ADMIN_BYPASS_SECRET.trim() && provided && provided === ADMIN_BYPASS_SECRET.trim()) return true;
  return isAdminToken(req);
}

function isAdminToken(req) {
  const token = String(getHeader(req, "x-cg-admin-token") || "").trim();
  if (!token || !ADMIN_TOKEN_SECRET) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;
  const expected = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(payload).digest("base64url");
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

function cleanSurface(surface) {
  return ["site", "dashboard"].includes(surface) ? surface : "site";
}

function cleanLang(lang) {
  return String(lang || "en").toLowerCase().replace(/[^a-z-]/g, "").slice(0, 12) || "en";
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: "Origin not allowed" });

  const sb = getSupabase();
  if (!sb) return res.status(500).json({ error: "Server configuration error" });

  if (req.method === "GET") {
    const url = new URL(req.url || "/api/content", `https://${req.headers.host || "cyberguardianscan.com"}`);
    const surface = cleanSurface(url.searchParams.get("surface"));
    const lang = cleanLang(url.searchParams.get("lang"));

    const { data, error } = await sb
      .from("site_content_overrides")
      .select("content_key,content_value")
      .eq("surface", surface)
      .eq("lang", lang);

    if (error) {
      console.error("[content-get]", error.message);
      return res.status(200).json({ surface, lang, entries: {}, warning: "content overrides unavailable" });
    }
    const entries = {};
    for (const row of data || []) entries[row.content_key] = row.content_value;
    return res.status(200).json({ surface, lang, entries });
  }

  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  if (!isAdmin(req)) return res.status(401).json({ error: "Admin secret required" });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request format" }); }
  }

  const surface = cleanSurface(body?.surface);
  const lang = cleanLang(body?.lang);
  const entries = body?.entries || {};
  const rows = Object.entries(entries)
    .filter(([key, value]) => typeof key === "string" && key.trim() && typeof value === "string")
    .map(([key, value]) => ({
      surface,
      lang,
      content_key: key.trim().slice(0, 160),
      content_value: value,
      updated_at: new Date().toISOString(),
    }));

  if (!rows.length) return res.status(400).json({ error: "No content entries supplied" });

  const { error } = await sb
    .from("site_content_overrides")
    .upsert(rows, { onConflict: "surface,lang,content_key" });

  if (error) return res.status(500).json({ error: "Content save failed" });
  return res.status(200).json({ ok: true, saved: rows.length });
};
