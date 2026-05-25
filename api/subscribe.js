// Cyber-Guardian AI — Email Subscribe (Vercel)
module.exports = async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST")   return res.status(405).json({ error: "Method not allowed" });

  let body = req.body;
  if (typeof body === "string") {
    try { body = JSON.parse(body); } catch { return res.status(400).json({ error: "Invalid request" }); }
  }

  const email = (body?.email || "").trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email) || email.length > 200)
    return res.status(400).json({ error: "Please enter a valid email address." });

  // Log to Vercel logs — visible in dashboard
  console.log("[SUBSCRIBE]", new Date().toISOString(), email);

  // TODO: connect to Mailchimp / ConvertKit / Beehiiv when ready

  return res.status(200).json({ success: true, message: "Thanks! We'll keep you posted on new threats." });
};
