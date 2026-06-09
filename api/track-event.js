const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_TOKEN_SECRET = process.env.CG_ADMIN_TOKEN_SECRET || process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ADMIN_TOKEN_VERSION = String(process.env.CG_ADMIN_TOKEN_VERSION || "1");
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
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
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CG-Admin-Token, Authorization");
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

function tableMissing(error) {
  return /relation .* does not exist|schema cache|Could not find/i.test(error?.message || "");
}

function hashValue(value) {
  const raw = cleanText(value, 1000);
  if (!raw) return null;
  return crypto.createHash("sha256").update(raw, "utf8").digest("hex");
}

function cleanSeverity(value) {
  const severity = cleanText(value, 20).toLowerCase();
  if (["low", "medium", "high", "critical"].includes(severity)) return severity;
  return "medium";
}

function cleanUrl(value) {
  const raw = cleanText(value, 500);
  if (!raw) return "";
  try {
    const url = new URL(raw);
    if (!["https:", "http:"].includes(url.protocol)) return "";
    url.hash = "";
    return url.toString().slice(0, 500);
  } catch {
    return raw.slice(0, 500);
  }
}

function header(req, name) {
  return req.headers[name.toLowerCase()] || req.headers[name] || "";
}

function adminToken(req) {
  const direct = String(header(req, "x-cg-admin-token") || "").trim();
  if (direct) return direct;
  const auth = String(header(req, "authorization") || "").trim();
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

function isAdminToken(req) {
  const token = adminToken(req);
  if (!token || !ADMIN_TOKEN_SECRET) return false;
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;
  const expected = crypto.createHmac("sha256", ADMIN_TOKEN_SECRET).update(payload).digest("base64url");
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) return false;
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    return parsed.role === "admin" && String(parsed.ver || "1") === ADMIN_TOKEN_VERSION && Number(parsed.exp || 0) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function insertEventWithFallback(sb, row) {
  const { error } = await sb.from("site_events").insert(row);
  if (!error) return true;
  if (/column .* does not exist|schema cache|Could not find/i.test(error.message || "") && Object.prototype.hasOwnProperty.call(row, "actor")) {
    const legacy = { ...row };
    delete legacy.actor;
    const retry = await sb.from("site_events").insert(legacy);
    if (!retry.error) return true;
    console.error("[track-event]", retry.error.message);
    return false;
  }
  console.error("[track-event]", error.message);
  return false;
}

async function insertThreatIntelReport(sb, body, req, actor) {
  const metadata = cleanMetadata(body?.metadata);
  const sourceUrl = cleanUrl(body?.source_url || metadata.source_url || "");
  const row = {
    report_source: cleanText(body?.report_source || metadata.report_source || (actor === "owner" ? "admin" : "web"), 80) || "web",
    scope: cleanScope(body?.scan_scope || body?.scope || metadata.scope),
    source_name: cleanText(body?.source_name || metadata.source_name || "", 180),
    source_url: sourceUrl,
    source_hash: hashValue(body?.source_hash || sourceUrl || body?.source_name || metadata.source_name || ""),
    event_type: cleanText(body?.event_type || metadata.event_type || body?.event_name || "runtime_anomaly", 80).toLowerCase(),
    severity: cleanSeverity(body?.severity || metadata.severity),
    behavior: cleanText(body?.behavior || metadata.behavior || metadata.summary || "Runtime anomaly reported", 1000),
    indicators: metadata,
    country: cleanText(header(req, "x-vercel-ip-country"), 2).toUpperCase() || null,
    region: cleanText(header(req, "x-vercel-ip-country-region"), 80) || null,
    city: cleanText(header(req, "x-vercel-ip-city"), 120) || null,
    user_agent: cleanText(header(req, "user-agent"), 500),
    visitor_id: cleanText(body?.visitor_id || body?.session_id || "", 80) || null,
    status: "pending",
  };

  const { error } = await sb.from("cg_threat_intel_reports").insert(row);
  if (error) {
    if (!tableMissing(error)) console.error("[threat-intel-report]", error.message);
    return false;
  }
  return true;
}

function threatFamiliesFromMetadata(metadata) {
  const raw = metadata.threat_families || metadata.threats || metadata.threat_summary || "";
  if (Array.isArray(raw)) return raw.map(item => cleanText(item, 80)).filter(Boolean).slice(0, 12);
  return String(raw || "")
    .split(",")
    .map(item => cleanText(item, 80))
    .filter(Boolean)
    .slice(0, 12);
}

async function insertWrapperRequest(sb, body) {
  const metadata = cleanMetadata(body?.metadata);
  const requestedControls = String(metadata.requested_controls || "deny risky filesystem access, block unexpected network egress, limit shell execution")
    .split(",")
    .map(item => cleanText(item, 120))
    .filter(Boolean)
    .slice(0, 12);

  const row = {
    request_source: cleanText(body?.request_source || "web_scan_result", 80),
    scope: cleanScope(body?.scan_scope || body?.scope || metadata.scope),
    source_name: cleanText(body?.source_name || metadata.source_name || "", 180),
    source_url: cleanUrl(body?.source_url || metadata.source_url || ""),
    decision: cleanText(metadata.decision || body?.decision || "", 80),
    threat_score: Math.max(0, Math.min(100, parseInt(metadata.threat_score || body?.threat_score || "0", 10) || 0)),
    threat_families: threatFamiliesFromMetadata(metadata),
    code_purpose: cleanText(metadata.code_purpose || body?.code_purpose || "", 500),
    requested_controls: requestedControls,
    wrapper_status: "requested",
    contact_email: cleanText(body?.contact_email || metadata.contact_email || "", 240),
    visitor_id: cleanText(body?.visitor_id || body?.session_id || "", 80) || null,
    notes: cleanText(metadata.notes || body?.notes || "", 1000),
  };

  const { error } = await sb.from("cg_wrapper_requests").insert(row);
  if (error) {
    if (!tableMissing(error)) console.error("[wrapper-request]", error.message);
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

  const sb = getSupabase();
  if (!sb) return res.status(202).json({ ok: false, stored: false, reason: "analytics_not_configured" });

  let body = req.body;
  if (Buffer.isBuffer(body)) body = body.toString("utf8");
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request format" }); }
  }

  const eventName = cleanText(body?.event_name || body?.event, 80).toLowerCase().replace(/[^a-z0-9_.:-]/g, "_");
  if (!eventName) return res.status(400).json({ error: "event_name is required" });
  const actor = isAdminToken(req) ? "owner" : "public";

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
    actor,
    metadata: cleanMetadata(body?.metadata),
  };

  const stored = await insertEventWithFallback(sb, row);
  let threat_intel_stored = false;
  let wrapper_request_stored = false;
  if (["threat_intel_report", "runtime_anomaly_report", "runtime_permission_blocked"].includes(eventName)) {
    threat_intel_stored = await insertThreatIntelReport(sb, body, req, actor);
  }
  if (["secure_wrapper_requested", "wrapper_request"].includes(eventName)) {
    wrapper_request_stored = await insertWrapperRequest(sb, body);
  }
  if (!stored) return res.status(202).json({ ok: false, stored: false });

  return res.status(200).json({ ok: true, stored: true, actor, threat_intel_stored, wrapper_request_stored });
};
