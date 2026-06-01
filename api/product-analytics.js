const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_TOKEN_SECRET = process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

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
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CG-Admin-Token");
  res.setHeader("Content-Type", "application/json");
}

function rejectDisallowedOrigin(req, res) {
  if (isAllowedOrigin(getOrigin(req))) return false;
  res.status(403).json({ error: "Origin not allowed" });
  return true;
}

function getHeader(req, name) {
  const value = req.headers?.[name] || req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
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

function countBy(rows, keyFn) {
  const counts = {};
  for (const row of rows) {
    const key = keyFn(row);
    if (!key) continue;
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function topCounts(counts, limit = 10) {
  return Object.entries(counts)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, limit);
}

function uniqueCount(rows, key) {
  return new Set(rows.map(row => row[key]).filter(Boolean)).size;
}

function eventRowsByActor(rows, actor) {
  return rows.filter(row => (row.actor || "public") === actor);
}

function since(days) {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000);
}

function byDay(rows) {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date(Date.now() - i * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    days.push({ date, events: 0, visitors: new Set(), scans: 0 });
  }
  const map = new Map(days.map(day => [day.date, day]));
  for (const row of rows) {
    const date = String(row.created_at || "").slice(0, 10);
    const day = map.get(date);
    if (!day) continue;
    day.events++;
    if (row.visitor_id) day.visitors.add(row.visitor_id);
    if (row.event_name === "scan_completed") day.scans++;
  }
  return days.map(day => ({ date: day.date, events: day.events, visitors: day.visitors.size, scans: day.scans }));
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(200).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
  if (!isAdminToken(req)) return res.status(401).json({ error: "Admin token required" });
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: "Not configured" });

  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_KEY);
    let { data: rows, error } = await sb
      .from("site_events")
      .select("event_name,page_path,scan_scope,country,visitor_id,metadata,actor,created_at")
      .gte("created_at", since(30).toISOString())
      .order("created_at", { ascending: false })
      .limit(5000);

    let actorFilterActive = true;
    if (error) {
      if (/relation .* does not exist|schema cache|Could not find/i.test(error.message || "")) {
        if (/actor/i.test(error.message || "")) {
          const legacy = await sb
            .from("site_events")
            .select("event_name,page_path,scan_scope,country,visitor_id,metadata,created_at")
            .gte("created_at", since(30).toISOString())
            .order("created_at", { ascending: false })
            .limit(5000);
          rows = legacy.data;
          error = legacy.error;
          actorFilterActive = false;
        } else {
          return res.status(200).json({ configured: false, events_30d: 0, visitors_30d: 0 });
        }
      }
      if (error) throw error;
    }

    const all = (rows || []).map(row => ({ ...row, actor: row.actor || "public" }));
    const publicRows = eventRowsByActor(all, "public");
    const ownerRows = eventRowsByActor(all, "owner");
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const weekStart = since(7);
    const today = publicRows.filter(row => new Date(row.created_at) >= todayStart);
    const week = publicRows.filter(row => new Date(row.created_at) >= weekStart);
    const scanEvents = publicRows.filter(row => ["scan_started", "scan_completed", "scan_failed"].includes(row.event_name));
    const ownerScanEvents = ownerRows.filter(row => ["scan_started", "scan_completed", "scan_failed"].includes(row.event_name));

    return res.status(200).json({
      configured: true,
      actor_filter_active: actorFilterActive,
      events_30d: publicRows.length,
      events_today: today.length,
      events_7d: week.length,
      visitors_30d: uniqueCount(publicRows, "visitor_id"),
      visitors_today: uniqueCount(today, "visitor_id"),
      visitors_7d: uniqueCount(week, "visitor_id"),
      scans_30d: publicRows.filter(row => row.event_name === "scan_completed").length,
      sales_clicks_30d: publicRows.filter(row => row.event_name === "contact_sales_clicked").length,
      email_submits_30d: publicRows.filter(row => row.event_name === "email_submitted").length,
      owner_events_30d: ownerRows.length,
      owner_scans_30d: ownerRows.filter(row => row.event_name === "scan_completed").length,
      owner_visitors_30d: uniqueCount(ownerRows, "visitor_id"),
      all_events_30d: all.length,
      all_visitors_30d: uniqueCount(all, "visitor_id"),
      all_scans_30d: all.filter(row => row.event_name === "scan_completed").length,
      by_country: topCounts(countBy(publicRows, row => row.country || "unknown"), 12),
      by_event: topCounts(countBy(publicRows, row => row.event_name), 12),
      by_scan_scope: topCounts(countBy(scanEvents, row => row.scan_scope || row.metadata?.scope || "unknown"), 10),
      owner_by_event: topCounts(countBy(ownerRows, row => row.event_name), 8),
      owner_by_scan_scope: topCounts(countBy(ownerScanEvents, row => row.scan_scope || row.metadata?.scope || "unknown"), 8),
      trend: byDay(publicRows),
      recent: publicRows.slice(0, 20).map(row => ({
        event_name: row.event_name,
        page_path: row.page_path,
        scan_scope: row.scan_scope,
        country: row.country,
        actor: row.actor,
        created_at: row.created_at,
      })),
    });
  } catch (err) {
    console.error("[product-analytics]", err.message);
    return res.status(500).json({ error: "Analytics unavailable" });
  }
};
