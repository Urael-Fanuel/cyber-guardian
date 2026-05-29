const Stripe = require("stripe");

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173")
  .split(",").map(s => s.trim()).filter(Boolean);

const PLAN_PRICE_IDS = {
  pro: process.env.STRIPE_PRICE_PRO,
  team: process.env.STRIPE_PRICE_TEAM,
  business: process.env.STRIPE_PRICE_BUSINESS,
};

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

function getSiteUrl() {
  return (process.env.SITE_URL || "https://cyberguardianscan.com").replace(/\/+$/, "");
}

module.exports = async function handler(req, res) {
  setCors(req, res);

  if (req.method === "OPTIONS") return res.status(200).end();
  if (!isAllowedOrigin(getOrigin(req))) return res.status(403).json({ error: "Origin not allowed" });
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(500).json({ error: "Stripe is not configured yet." });
  }

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request" }); }
  }

  const plan = String(body?.plan || "").toLowerCase();
  const priceId = PLAN_PRICE_IDS[plan];
  if (!priceId) return res.status(400).json({ error: "Unknown or unconfigured plan." });

  const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  const siteUrl = getSiteUrl();

  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${siteUrl}/?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${siteUrl}/?checkout=cancelled#free-access`,
      allow_promotion_codes: true,
      billing_address_collection: "auto",
      metadata: { plan },
    });

    return res.status(200).json({ url: session.url });
  } catch (error) {
    console.error("[stripe-checkout]", error.message);
    return res.status(500).json({ error: "Could not start checkout." });
  }
};
