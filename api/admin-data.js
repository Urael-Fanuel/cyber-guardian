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
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
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

function getSection(req) {
  try {
    const url = new URL(req.url, "https://cyberguardianscan.com");
    return String(url.searchParams.get("section") || "leads").trim();
  } catch {
    return "leads";
  }
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

function monthKey() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body); } catch { return null; }
  }
  return req.body;
}

function addDays(days) {
  const date = new Date();
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString();
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

async function getLeads(sb) {
  const [contacts, subscribers] = await Promise.all([
    getContactMessages(sb),
    getEmailSubscribers(sb),
  ]);

  return {
    ok: true,
    contacts,
    subscribers,
    generated_at: new Date().toISOString(),
  };
}

async function deleteEmailSubscriber(sb, body) {
  const email = String(body?.email || "").trim().toLowerCase();
  if (!validEmail(email)) return { error: "Valid subscriber email is required." };

  const { error } = await sb
    .from("email_subscribers")
    .delete()
    .eq("email", email);

  if (error) {
    if (tableMissing(error)) return { error: "The email_subscribers table is not configured yet." };
    throw error;
  }

  return { ok: true, deleted_email: email };
}

async function getPlans(sb) {
  const { data, error } = await sb
    .from("cg_account_plans")
    .select("plan_code,display_name,monthly_scan_limit,price_usd,active")
    .eq("active", true)
    .order("monthly_scan_limit", { ascending: true });
  if (error) {
    if (tableMissing(error)) return { configured: false, rows: [] };
    throw error;
  }
  return { configured: true, rows: data || [] };
}

async function getAccountRows(sb) {
  const plans = await getPlans(sb);
  if (!plans.configured) return { configured: false, plans: [], rows: [] };

  const { data: userPage, error: userError } = await sb.auth.admin.listUsers({
    page: 1,
    perPage: 100,
  });
  if (userError) throw userError;

  const users = userPage?.users || [];
  const userIds = users.map(user => user.id);

  const [subscriptionsResult, usageResult] = await Promise.all([
    userIds.length
      ? sb.from("cg_user_subscriptions")
          .select("user_id,plan_code,status,current_period_start,current_period_end,updated_at")
          .in("user_id", userIds)
      : Promise.resolve({ data: [], error: null }),
    userIds.length
      ? sb.from("cg_user_scan_usage")
          .select("user_id,month_key,usage_count,updated_at")
          .eq("month_key", monthKey())
          .in("user_id", userIds)
      : Promise.resolve({ data: [], error: null }),
  ]);

  if (subscriptionsResult.error) {
    if (tableMissing(subscriptionsResult.error)) return { configured: false, plans: [], rows: [] };
    throw subscriptionsResult.error;
  }
  if (usageResult.error) {
    if (tableMissing(usageResult.error)) return { configured: false, plans: [], rows: [] };
    throw usageResult.error;
  }

  const planByCode = new Map(plans.rows.map(plan => [plan.plan_code, plan]));
  const subByUser = new Map((subscriptionsResult.data || []).map(row => [row.user_id, row]));
  const usageByUser = new Map((usageResult.data || []).map(row => [row.user_id, row]));

  const rows = users
    .map(user => {
      const sub = subByUser.get(user.id);
      const plan = planByCode.get(sub?.plan_code || "free") || planByCode.get("free");
      const usage = usageByUser.get(user.id);
      const limit = plan?.monthly_scan_limit || 10;
      const used = usage?.usage_count || 0;
      return {
        user_id: user.id,
        email: user.email,
        created_at: user.created_at,
        last_sign_in_at: user.last_sign_in_at,
        plan_code: plan?.plan_code || "free",
        plan_name: plan?.display_name || "Free",
        status: sub?.status || "free",
        quota_used: used,
        quota_limit: limit,
        quota_remaining: Math.max(limit - used, 0),
        current_period_end: sub?.current_period_end || null,
        updated_at: sub?.updated_at || usage?.updated_at || user.updated_at,
      };
    })
    .sort((a, b) => String(b.updated_at || b.created_at).localeCompare(String(a.updated_at || a.created_at)));

  return { configured: true, plans: plans.rows, rows };
}

async function getAccounts(sb) {
  const accounts = await getAccountRows(sb);
  return {
    ok: true,
    ...accounts,
    month_key: monthKey(),
    generated_at: new Date().toISOString(),
  };
}

async function findUserByEmail(sb, email) {
  const { data, error } = await sb.auth.admin.listUsers({ page: 1, perPage: 1000 });
  if (error) throw error;
  return (data?.users || []).find(user => String(user.email || "").toLowerCase() === email.toLowerCase()) || null;
}

async function upsertAccount(sb, body) {
  const email = String(body?.email || "").trim().toLowerCase();
  const password = String(body?.password || "");
  const planCode = String(body?.plan_code || "free").trim();
  const status = String(body?.status || "manual").trim();
  const durationDays = Math.max(1, Math.min(Number.parseInt(body?.duration_days || "30", 10) || 30, 366));

  if (!validEmail(email)) return { error: "Valid customer email is required." };
  if (!["manual", "active", "trialing", "canceled"].includes(status)) return { error: "Invalid subscription status." };

  const plans = await getPlans(sb);
  if (!plans.configured) return { error: "Account plans are not configured. Run migration 009." };
  if (!plans.rows.some(plan => plan.plan_code === planCode)) return { error: "Selected plan does not exist." };

  let user = await findUserByEmail(sb, email);
  let created = false;

  if (!user) {
    if (password.length < 8) {
      return { error: "Password of at least 8 characters is required for a new customer account." };
    }
    const { data, error } = await sb.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
    });
    if (error) throw error;
    user = data?.user;
    created = true;
  }

  if (!user?.id) return { error: "Could not create or find this customer account." };

  const periodStart = new Date().toISOString();
  const periodEnd = addDays(durationDays);
  const { error: subError } = await sb
    .from("cg_user_subscriptions")
    .upsert({
      user_id: user.id,
      plan_code: planCode,
      status,
      current_period_start: periodStart,
      current_period_end: periodEnd,
      updated_at: new Date().toISOString(),
    }, { onConflict: "user_id" });

  if (subError) {
    if (tableMissing(subError)) return { error: "Account plans are not configured. Run migration 009." };
    throw subError;
  }

  return {
    ok: true,
    created,
    user_id: user.id,
    email: user.email,
    plan_code: planCode,
    status,
    current_period_end: periodEnd,
  };
}

async function safeTableRows(sb, table, select, orderColumn, limit = 50) {
  const { data, error } = await sb
    .from(table)
    .select(select)
    .order(orderColumn, { ascending: false })
    .limit(limit);
  if (error) {
    if (tableMissing(error)) return { configured: false, rows: [] };
    throw error;
  }
  return { configured: true, rows: data || [] };
}

async function getMoat(sb) {
  const [intel, registry, wrappers, policies] = await Promise.all([
    safeTableRows(
      sb,
      "cg_threat_intel_reports",
      "id,report_source,scope,source_name,source_url,event_type,severity,behavior,status,country,created_at",
      "created_at",
      50
    ),
    safeTableRows(
      sb,
      "cg_registry_entries",
      "id,scope,source_name,source_url,source_owner,creator_verified,trust_score,trust_status,scan_count,clean_scan_count,review_scan_count,blocked_scan_count,user_reports_count,last_scan_status,last_threat_score,last_seen_at,updated_at",
      "updated_at",
      50
    ),
    safeTableRows(
      sb,
      "cg_wrapper_requests",
      "id,request_source,scope,source_name,source_url,decision,threat_score,threat_families,code_purpose,requested_controls,wrapper_status,contact_email,created_at,updated_at",
      "created_at",
      50
    ),
    safeTableRows(
      sb,
      "cg_runtime_policy_templates",
      "id,scope,template_name,description,status,created_at,updated_at",
      "updated_at",
      50
    ),
  ]);

  return {
    ok: true,
    configured: intel.configured && registry.configured && wrappers.configured && policies.configured,
    intel,
    registry,
    wrappers,
    policies,
    generated_at: new Date().toISOString(),
  };
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (!isAllowedOrigin(req)) return res.status(403).json({ error: "Origin not allowed" });
  if (!["GET", "POST"].includes(req.method)) return res.status(405).json({ error: "Method not allowed" });
  if (!isAdminToken(req)) return res.status(401).json({ error: "Admin token required" });

  const sb = getSupabase();
  if (!sb) return res.status(500).json({ error: "Supabase is not configured" });

  const section = getSection(req);
  try {
    if (section === "leads") {
      if (req.method === "POST") {
        const body = parseBody(req);
        if (!body) return res.status(400).json({ error: "Invalid request format" });
        if (body.action === "delete_subscriber") {
          const result = await deleteEmailSubscriber(sb, body);
          if (result.error) return res.status(400).json({ error: result.error });
          return res.status(200).json(result);
        }
        return res.status(400).json({ error: "Unknown leads action" });
      }
      if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
      return res.status(200).json(await getLeads(sb));
    }

    if (section === "accounts") {
      if (req.method === "POST") {
        const body = parseBody(req);
        if (!body) return res.status(400).json({ error: "Invalid request format" });
        const result = await upsertAccount(sb, body);
        if (result.error) return res.status(400).json({ error: result.error });
        return res.status(200).json(result);
      }
      return res.status(200).json(await getAccounts(sb));
    }

    if (section === "moat" || section === "integrity") {
      if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });
      return res.status(200).json(await getMoat(sb));
    }

    return res.status(404).json({ error: "Unknown admin data section" });
  } catch (err) {
    console.error("[admin-data]", section, err.message);
    return res.status(500).json({ error: "Admin data unavailable" });
  }
};
