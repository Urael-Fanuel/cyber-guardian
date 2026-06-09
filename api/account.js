const { createClient } = require("@supabase/supabase-js");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || "";
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

let supabaseClient = null;

function getSupabase() {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) return null;
  if (!supabaseClient) supabaseClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);
  return supabaseClient;
}

function setCors(req, res) {
  const origin = req.headers.origin || "";
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CG-Account-Token");
  res.setHeader("Content-Type", "application/json");
}

function getHeader(req, name) {
  const value = req.headers?.[name] || req.headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function getMode(req) {
  try {
    const url = new URL(req.url, "https://cyberguardianscan.com");
    return String(url.searchParams.get("mode") || "config").trim();
  } catch {
    return "config";
  }
}

function monthKey() {
  const now = new Date();
  return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}`;
}

function tableMissing(error) {
  return /relation .* does not exist|schema cache|Could not find/i.test(error?.message || "");
}

function publicConfig() {
  return {
    supabase_configured: Boolean(SUPABASE_URL && SUPABASE_ANON_KEY),
    supabase_url: SUPABASE_URL || "",
    supabase_anon_key: SUPABASE_ANON_KEY,
  };
}

async function getUserFromRequest(sb, req) {
  const token = String(getHeader(req, "x-cg-account-token") || "").trim();
  if (!token) return { error: "Account token required" };
  const { data, error } = await sb.auth.getUser(token);
  if (error || !data?.user) return { error: "Invalid or expired account session" };
  return { user: data.user };
}

async function getPlan(sb, planCode) {
  const { data, error } = await sb
    .from("cg_account_plans")
    .select("plan_code,display_name,monthly_scan_limit,price_usd")
    .eq("plan_code", planCode)
    .maybeSingle();
  if (error) {
    if (tableMissing(error)) return null;
    throw error;
  }
  return data;
}

async function getSubscription(sb, userId) {
  const { data, error } = await sb
    .from("cg_user_subscriptions")
    .select("plan_code,status,current_period_start,current_period_end,stripe_subscription_id")
    .eq("user_id", userId)
    .maybeSingle();
  if (error) {
    if (tableMissing(error)) return { configured: false, subscription: null };
    throw error;
  }
  return { configured: true, subscription: data };
}

async function getUsage(sb, userId) {
  const { data, error } = await sb
    .from("cg_user_scan_usage")
    .select("usage_count")
    .eq("user_id", userId)
    .eq("month_key", monthKey())
    .maybeSingle();
  if (error) {
    if (tableMissing(error)) return { configured: false, usage: 0 };
    throw error;
  }
  return { configured: true, usage: data?.usage_count || 0 };
}

async function accountStatus(sb, user) {
  const subResult = await getSubscription(sb, user.id);
  if (!subResult.configured) return { configured: false };

  const subscription = subResult.subscription;
  const now = Date.now();
  const isActive = subscription &&
    ["active", "trialing", "manual"].includes(subscription.status) &&
    (!subscription.current_period_end || new Date(subscription.current_period_end).getTime() > now);
  const planCode = isActive ? subscription.plan_code : "free";
  const plan = await getPlan(sb, planCode) || {
    plan_code: "free",
    display_name: "Free",
    monthly_scan_limit: 10,
    price_usd: 0,
  };
  const usageResult = await getUsage(sb, user.id);
  const used = usageResult.usage || 0;
  const limit = plan.monthly_scan_limit || 0;

  return {
    configured: usageResult.configured,
    authenticated: true,
    user_id: user.id,
    email: user.email,
    plan_code: plan.plan_code,
    plan_name: plan.display_name,
    plan_status: isActive ? subscription.status : "free",
    monthly_scan_limit: limit,
    quota_used: used,
    quota_remaining: Math.max(limit - used, 0),
    current_period_start: isActive ? subscription.current_period_start : null,
    current_period_end: isActive ? subscription.current_period_end : null,
    month_key: monthKey(),
  };
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  const mode = getMode(req);
  if (mode === "config") return res.status(200).json(publicConfig());
  if (mode !== "status") return res.status(404).json({ error: "Unknown account action" });

  const sb = getSupabase();
  if (!sb) return res.status(500).json({ error: "Supabase is not configured" });

  try {
    const { user, error } = await getUserFromRequest(sb, req);
    if (error) return res.status(401).json({ error });
    const status = await accountStatus(sb, user);
    if (status.configured === false) {
      return res.status(503).json({ error: "Account plans are not configured. Run migration 009." });
    }
    return res.status(200).json(status);
  } catch (err) {
    console.error("[account]", err.message);
    return res.status(500).json({ error: "Account status unavailable" });
  }
};
