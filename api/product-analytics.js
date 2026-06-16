const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ADMIN_TOKEN_SECRET = process.env.CG_ADMIN_BYPASS_SECRET || process.env.CG_ADMIN_PASSWORD || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
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

function uniqueVisitors(rows) {
  return uniqueCount(rows, "visitor_id");
}

function pct(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
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

function metadata(row, key) {
  const value = row?.metadata && typeof row.metadata === "object" ? row.metadata[key] : "";
  return String(value ?? "").trim();
}

function scanScope(row) {
  return row.scan_scope || metadata(row, "scope") || "unknown";
}

function scanStatus(row) {
  const raw = metadata(row, "status").toUpperCase();
  if (raw.includes("CRITICAL")) return "do_not_install";
  if (raw.includes("MODERATE") || raw.includes("AMBIGUOUS")) return "security_review";
  if (raw.includes("SAFE")) return "ok_to_install";
  return "unknown";
}

function scoreBucket(row) {
  const score = Number(metadata(row, "threat_score") || 0);
  if (score >= 70) return "70_100_high_risk";
  if (score >= 20) return "20_69_review";
  return "0_19_low_risk";
}

function contactType(row) {
  const type = (metadata(row, "type") || row.event_name.replace(/^contact_/, "").replace(/_clicked$/, "")).toLowerCase();
  if (["sales", "enterprise", "support", "security"].includes(type)) return type;
  return row.event_name === "email_submitted" ? "email_signup" : "general";
}

function referrerDomain(row) {
  const referrer = String(row.referrer || "").trim();
  if (!referrer) return "direct";
  try {
    const url = new URL(referrer);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return "other";
  }
}

function deviceFromRow(row) {
  const explicit = metadata(row, "device").toLowerCase();
  if (["mobile", "tablet", "desktop"].includes(explicit)) return explicit;
  const ua = String(row.user_agent || "").toLowerCase();
  if (/mobile|iphone|android/.test(ua)) return "mobile";
  if (/ipad|tablet/.test(ua)) return "tablet";
  return ua ? "desktop" : "unknown";
}

function browserFromRow(row) {
  const ua = String(row.user_agent || "").toLowerCase();
  if (!ua) return "unknown";
  if (ua.includes("edg/")) return "edge";
  if (ua.includes("chrome/") && !ua.includes("chromium")) return "chrome";
  if (ua.includes("firefox/")) return "firefox";
  if (ua.includes("safari/") && !ua.includes("chrome/")) return "safari";
  return "other";
}

function compactPath(path) {
  const value = String(path || "/").trim() || "/";
  return value === "/" ? "home" : value.replace(/^\//, "") || "home";
}

function countryScopeKey(row) {
  return `${row.country || "unknown"} · ${scanScope(row)}`;
}

function contactIntentRows(rows) {
  return rows.filter(row =>
    row.event_name === "contact_sales_clicked" ||
    row.event_name === "contact_enterprise_clicked" ||
    row.event_name === "email_submitted" ||
    (row.event_name === "contact_form_submitted" && ["sales", "enterprise"].includes(contactType(row)))
  );
}

function isAccountEvent(row) {
  return String(row.event_name || "").startsWith("account_");
}

function isContactEvent(row) {
  return /^contact_.*_clicked$/.test(row.event_name) ||
    row.event_name === "contact_clicked" ||
    row.event_name === "contact_form_submitted";
}

function visitorCountsBy(rows, keyFn, limit = 12) {
  const map = new Map();
  for (const row of rows) {
    const key = keyFn(row) || "unknown";
    if (!map.has(key)) map.set(key, new Set());
    if (row.visitor_id) map.get(key).add(row.visitor_id);
  }
  return Array.from(map.entries())
    .map(([key, set]) => ({ key, count: set.size }))
    .sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
    .slice(0, limit);
}

function countryJourney(rows, limit = 16) {
  const map = new Map();
  function entry(country) {
    const key = country || "unknown";
    if (!map.has(key)) {
      map.set(key, {
        key,
        events: 0,
        visitors_set: new Set(),
        page_views: 0,
        scan_starts: 0,
        scan_completed: 0,
        scan_failed: 0,
        contact_actions: 0,
        email_signups: 0,
        account_signups: 0,
      });
    }
    return map.get(key);
  }

  for (const row of rows) {
    const item = entry(row.country || "unknown");
    item.events++;
    if (row.visitor_id) item.visitors_set.add(row.visitor_id);
    if (row.event_name === "page_view") item.page_views++;
    if (row.event_name === "scan_started") item.scan_starts++;
    if (row.event_name === "scan_completed") item.scan_completed++;
    if (row.event_name === "scan_failed") item.scan_failed++;
    if (row.event_name === "email_submitted") item.email_signups++;
    if (row.event_name === "account_signup_created") item.account_signups++;
    if (isContactEvent(row)) item.contact_actions++;
  }

  return Array.from(map.values())
    .map(item => {
      const visitors = item.visitors_set.size;
      return {
        key: item.key,
        events: item.events,
        visitors,
        page_views: item.page_views,
        scan_starts: item.scan_starts,
        scan_completed: item.scan_completed,
        scan_failed: item.scan_failed,
        contact_actions: item.contact_actions,
        email_signups: item.email_signups,
        account_signups: item.account_signups,
        visitor_to_scan_rate: pct(item.scan_starts, visitors),
        scan_completion_rate: pct(item.scan_completed, item.scan_starts),
      };
    })
    .sort((a, b) => b.visitors - a.visitors || b.events - a.events || a.key.localeCompare(b.key))
    .slice(0, limit);
}

function scopeJourney(rows, limit = 10) {
  const map = new Map();
  function entry(scope) {
    const key = scope || "unknown";
    if (!map.has(key)) {
      map.set(key, {
        key,
        visitors_set: new Set(),
        selected: 0,
        started: 0,
        completed: 0,
        failed: 0,
        source_required: 0,
      });
    }
    return map.get(key);
  }

  for (const row of rows) {
    const item = entry(scanScope(row));
    if (row.visitor_id) item.visitors_set.add(row.visitor_id);
    if (row.event_name === "scan_scope_selected") item.selected++;
    if (row.event_name === "scan_started") item.started++;
    if (row.event_name === "scan_completed") item.completed++;
    if (row.event_name === "scan_failed") item.failed++;
    if (row.event_name === "scan_source_required") item.source_required++;
  }

  return Array.from(map.values())
    .map(item => ({
      key: item.key,
      visitors: item.visitors_set.size,
      selected: item.selected,
      started: item.started,
      completed: item.completed,
      failed: item.failed,
      source_required: item.source_required,
      start_to_complete_rate: pct(item.completed, item.started),
    }))
    .sort((a, b) => b.started - a.started || b.selected - a.selected || a.key.localeCompare(b.key))
    .slice(0, limit);
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
    const pageViews = publicRows.filter(row => row.event_name === "page_view");
    const scanStarted = publicRows.filter(row => row.event_name === "scan_started");
    const scanCompleted = publicRows.filter(row => row.event_name === "scan_completed");
    const scanFailed = publicRows.filter(row => row.event_name === "scan_failed");
    const contactClicks = publicRows.filter(row => /^contact_.*_clicked$/.test(row.event_name) || row.event_name === "contact_clicked");
    const contactForms = publicRows.filter(row => row.event_name === "contact_form_submitted");
    const contactFailures = publicRows.filter(row => row.event_name === "contact_form_failed");
    const emailSubmits = publicRows.filter(row => row.event_name === "email_submitted");
    const emailFailures = publicRows.filter(row => row.event_name === "email_submit_failed");
    const accountEvents = publicRows.filter(isAccountEvent);
    const accountSignupStarted = publicRows.filter(row => row.event_name === "account_signup_started");
    const accountSignupCreated = publicRows.filter(row => row.event_name === "account_signup_created");
    const accountSignupExisting = publicRows.filter(row => row.event_name === "account_signup_existing_email");
    const accountSigninSuccess = publicRows.filter(row => row.event_name === "account_signin_success");
    const blockedLogin = publicRows.filter(row => row.event_name === "scan_blocked_login_required");
    const sourceRequired = publicRows.filter(row => row.event_name === "scan_source_required");
    const alternativeConsent = publicRows.filter(row => row.event_name === "safer_alternative_consent_opened");
    const alternativeConfirmed = publicRows.filter(row => row.event_name === "safer_alternative_confirmed");
    const contactIntent = contactIntentRows(publicRows);
    const publicVisitors = uniqueVisitors(publicRows);
    const publicScanVisitors = uniqueVisitors(scanStarted);
    const signupVisitors = uniqueVisitors(accountSignupStarted);
    const createdAccountVisitors = uniqueVisitors(accountSignupCreated);
    const contactIntentVisitors = uniqueVisitors(contactIntent);

    return res.status(200).json({
      configured: true,
      actor_filter_active: actorFilterActive,
      events_30d: publicRows.length,
      events_today: today.length,
      events_7d: week.length,
      visitors_30d: uniqueCount(publicRows, "visitor_id"),
      visitors_today: uniqueCount(today, "visitor_id"),
      visitors_7d: uniqueCount(week, "visitor_id"),
      page_views_30d: pageViews.length,
      scan_starts_30d: scanStarted.length,
      scans_30d: scanCompleted.length,
      scan_failures_30d: scanFailed.length,
      scan_completion_rate: pct(scanCompleted.length, scanStarted.length),
      scan_failure_rate: pct(scanFailed.length, scanStarted.length),
      public_scan_visitors_30d: publicScanVisitors,
      visitor_to_scan_rate: pct(publicScanVisitors, publicVisitors),
      sales_clicks_30d: publicRows.filter(row => row.event_name === "contact_sales_clicked").length,
      contact_clicks_30d: contactClicks.length,
      contact_forms_30d: contactForms.length,
      contact_failures_30d: contactFailures.length,
      email_submits_30d: emailSubmits.length,
      email_failures_30d: emailFailures.length,
      account_events_30d: accountEvents.length,
      account_signup_started_30d: accountSignupStarted.length,
      account_signup_created_30d: accountSignupCreated.length,
      account_signup_existing_30d: accountSignupExisting.length,
      account_signin_success_30d: accountSigninSuccess.length,
      scan_blocked_login_30d: blockedLogin.length,
      scan_source_required_30d: sourceRequired.length,
      safer_alternative_opened_30d: alternativeConsent.length,
      safer_alternative_confirmed_30d: alternativeConfirmed.length,
      business_intent_30d: contactIntent.length,
      visitor_to_business_intent_rate: pct(contactIntentVisitors, publicVisitors),
      visitor_to_signup_rate: pct(signupVisitors, publicVisitors),
      signup_to_account_rate: pct(createdAccountVisitors, signupVisitors),
      visitor_to_completed_scan_rate: pct(uniqueVisitors(scanCompleted), publicVisitors),
      scan_start_to_complete_rate: pct(uniqueVisitors(scanCompleted), publicScanVisitors),
      alternative_confirm_rate: pct(alternativeConfirmed.length, alternativeConsent.length),
      owner_events_30d: ownerRows.length,
      owner_scans_30d: ownerRows.filter(row => row.event_name === "scan_completed").length,
      owner_visitors_30d: uniqueCount(ownerRows, "visitor_id"),
      all_events_30d: all.length,
      all_visitors_30d: uniqueCount(all, "visitor_id"),
      all_scans_30d: all.filter(row => row.event_name === "scan_completed").length,
      by_country: topCounts(countBy(publicRows, row => row.country || "unknown"), 12),
      visitors_by_country: visitorCountsBy(publicRows, row => row.country || "unknown", 12),
      country_journey: countryJourney(publicRows, 16),
      by_event: topCounts(countBy(publicRows, row => row.event_name), 12),
      by_scan_scope: topCounts(countBy(scanEvents, scanScope), 10),
      scan_scope_journey: scopeJourney(publicRows, 10),
      completed_by_scope: topCounts(countBy(scanCompleted, scanScope), 10),
      started_by_scope: topCounts(countBy(scanStarted, scanScope), 10),
      failed_by_scope: topCounts(countBy(scanFailed, scanScope), 10),
      scans_by_country: topCounts(countBy(scanCompleted, row => row.country || "unknown"), 12),
      scans_by_country_scope: topCounts(countBy(scanCompleted, countryScopeKey), 16),
      scan_statuses: topCounts(countBy(scanCompleted, scanStatus), 8),
      scan_score_buckets: topCounts(countBy(scanCompleted, scoreBucket), 8),
      contact_by_type: topCounts(countBy([...contactClicks, ...contactForms], contactType), 10),
      contact_by_country: topCounts(countBy([...contactClicks, ...contactForms], row => row.country || "unknown"), 12),
      email_by_country: topCounts(countBy(emailSubmits, row => row.country || "unknown"), 12),
      account_by_country: topCounts(countBy(accountSignupCreated, row => row.country || "unknown"), 12),
      account_events: topCounts(countBy(accountEvents, row => row.event_name), 12),
      blockers: [
        { key: "scan_blocked_login_required", count: blockedLogin.length },
        { key: "scan_source_required", count: sourceRequired.length },
        { key: "scan_failed", count: scanFailed.length },
        { key: "account_signup_existing_email", count: accountSignupExisting.length },
        { key: "email_submit_failed", count: emailFailures.length },
        { key: "contact_form_failed", count: contactFailures.length },
      ],
      conversion_rates: [
        { key: "visitor_to_signup", count: pct(signupVisitors, publicVisitors), value_type: "percent" },
        { key: "signup_to_account", count: pct(createdAccountVisitors, signupVisitors), value_type: "percent" },
        { key: "visitor_to_scan", count: pct(publicScanVisitors, publicVisitors), value_type: "percent" },
        { key: "scan_start_to_complete", count: pct(uniqueVisitors(scanCompleted), publicScanVisitors), value_type: "percent" },
        { key: "visitor_to_business_intent", count: pct(contactIntentVisitors, publicVisitors), value_type: "percent" },
      ],
      top_pages: topCounts(countBy(pageViews, row => compactPath(row.page_path)), 12),
      top_referrers: topCounts(countBy(pageViews, referrerDomain), 12),
      by_language: topCounts(countBy(publicRows, row => metadata(row, "lang") || "unknown"), 10),
      by_device: topCounts(countBy(publicRows, deviceFromRow), 8),
      by_browser: topCounts(countBy(publicRows, browserFromRow), 8),
      funnel: [
        { key: "public_visitors", count: publicVisitors },
        { key: "account_signup_started", count: signupVisitors },
        { key: "account_signup_created", count: createdAccountVisitors },
        { key: "scan_started", count: publicScanVisitors },
        { key: "scan_completed", count: uniqueVisitors(scanCompleted) },
        { key: "contact_or_signup", count: contactIntentVisitors },
      ],
      owner_by_event: topCounts(countBy(ownerRows, row => row.event_name), 8),
      owner_by_scan_scope: topCounts(countBy(ownerScanEvents, scanScope), 8),
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
