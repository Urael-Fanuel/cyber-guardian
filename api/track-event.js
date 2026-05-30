const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
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
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Content-Type", "application/json");
}

function rejectDisallowedOrigin(req, res) {
  if (isAllowedOrigin(getOrigin(req))) return false;
  res.status(403).json({ error: "Origin not allowed" });
  return true;
}

function cleanText(value, maxLen = 300) {
  return String(value || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
}

function cleanScope(value) {
  const scope = cleanText(value, 40).toLowerCase();
  if (scope.includes("mcp")) return "mcp";
  if (scope.includes("skill")) return "skill";
  if (scope.includes("extension") || scope.includes("ide") || scope === "ext") return "extension";
  if (scope.includes("action") || scope.includes("workflow")) return "github_action";
  if (scope.includes("package") || scope.includes("npm") || scope.includes("pypi")) return "package";
  if (scope.includes("depend")) return "dependency";
  return scope || null;
}

function cleanMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const out = {};
  for (const [key, raw] of Object.entries(value).slice(0, 20)) {
    const cleanKey = cleanText(key, 40).replace(/[^a-zA-Z0-9_.-]/g, "_");
    if (!cleanKey) continue;
    if (typeof raw === "number" || typeof raw === "boolean") out[cleanKey] = raw;
    else if (raw == null) out[cleanKey] = null;
    else out[cleanKey] = cleanText(raw, 240);
  }
  return out;
}

function header(req, name) {
  return req.headers[name.toLowerCase()] || req.headers[name] || "";
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(200).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const sb = getSupabase();
  if (!sb) return res.status(202).json({ ok: false, stored: false, reason: "analytics_not_configured" });

  let body = req.body;
  if (Buffer.isBuffer(body)) body = body.toString("utf8");
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request format" }); }
  }

  const eventName = cleanText(body?.event_name || body?.event, 80).toLowerCase().replace(/[^a-z0-9_.:-]/g, "_");
  if (!eventName) return res.status(400).json({ error: "event_name is required" });

  const row = {
    event_name: eventName,
    page_path: cleanText(body?.page_path || body?.path || "", 300),
    referrer: cleanText(body?.referrer || "", 500),
    scan_scope: cleanScope(body?.scan_scope || body?.scope || body?.metadata?.scope),
    country: cleanText(header(req, "x-vercel-ip-country"), 2).toUpperCase() || null,
    region: cleanText(header(req, "x-vercel-ip-country-region"), 80) || null,
    city: cleanText(header(req, "x-vercel-ip-city"), 120) || null,
    user_agent: cleanText(header(req, "user-agent"), 500),
    visitor_id: cleanText(body?.visitor_id || body?.session_id || "", 80) || null,
    metadata: cleanMetadata(body?.metadata),
  };

  const { error } = await sb.from("site_events").insert(row);
  if (error) {
    console.error("[track-event]", error.message);
    return res.status(202).json({ ok: false, stored: false });
  }

  return res.status(200).json({ ok: true, stored: true });
};
