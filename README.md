# 🚀 Cyber-Guardian AI — Deployment Guide

You have **3 packages** that work together:

```
1. website/             →  Deploy to Netlify (your public site)
2. extension-chrome/    →  Submit to Chrome Web Store ($5 one-time fee)
3. extension-firefox/   →  Submit to Firefox Add-ons (free)
```

---

## 📦 PART 1: Deploy the Website to Netlify

### Step 1.1 — Get an Anthropic API Key

1. Go to https://console.anthropic.com
2. Sign up / log in
3. Settings → API Keys → "Create Key"
4. Name it `cyber-guardian-prod`
5. **Copy the key** (starts with `sk-ant-...`) — you'll never see it again
6. **Add billing** — set a monthly cap of $50 to start (Settings → Limits)

### Step 1.2 — Push to GitHub

```bash
cd website
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/cyber-guardian.git
git push -u origin main
```

### Step 1.3 — Connect to Netlify

1. Go to https://app.netlify.com → "Add new site" → "Import from Git"
2. Choose your `cyber-guardian` repo
3. Build settings: **leave empty** (no build needed)
4. Publish directory: **.**
5. Click "Deploy"

### Step 1.4 — Add the API Key

1. In Netlify → Site settings → Environment variables → "Add variable"
2. Key: `ANTHROPIC_API_KEY`
3. Value: paste your `sk-ant-...` key
4. Save → Redeploy site

### Step 1.5 — Lock Down CORS (IMPORTANT)

Once your real domain is live, edit `netlify/functions/scan.js`:

```javascript
ALLOWED_ORIGINS: [
  "https://YOUR-REAL-DOMAIN.com",   // ← put your real domain here
  // "*"                              ← DELETE this line after deployment!
],
```

This stops other people from using your API key.

### Step 1.6 — Custom Domain (optional but recommended)

1. Buy a domain (e.g., from Namecheap, ~$10/year)
2. Netlify → Domain settings → Add custom domain
3. Follow DNS instructions
4. SSL is automatic

---

## 🌐 PART 2: Chrome Extension (Edge / Brave / Opera all work too)

### Step 2.1 — Update the Extension's API URL

If you changed your domain, edit `extension-chrome/popup.js`:

```javascript
const API_URL = "https://YOUR-REAL-DOMAIN.com/.netlify/functions/scan";
```

Same for `extension-chrome/manifest.json`:

```json
"host_permissions": ["https://YOUR-REAL-DOMAIN.com/*"],
```

### Step 2.2 — Test Locally First

1. Open Chrome → `chrome://extensions/`
2. Toggle "Developer mode" ON (top-right)
3. Click "Load unpacked"
4. Select the `extension-chrome` folder
5. The icon should appear in your toolbar — click it, test a scan

### Step 2.3 — Publish to Chrome Web Store

1. Pay one-time **$5 developer fee** at https://chrome.google.com/webstore/devconsole
2. Zip the `extension-chrome` folder
3. Upload, fill in:
   - **Category:** Developer Tools
   - **Screenshots:** Take 3-5 of your scanner in action (1280×800px)
   - **Description:** Use text from the website
4. Submit → review takes 1-3 days

---

## 🦊 PART 3: Firefox Extension

### Step 3.1 — Test Locally

1. Open Firefox → `about:debugging` → "This Firefox"
2. Click "Load Temporary Add-on"
3. Select `extension-firefox/manifest.json`
4. Test it

### Step 3.2 — Publish to Firefox Add-ons (free)

1. Go to https://addons.mozilla.org/developers/
2. Create a free developer account
3. Submit → "On this site" (public listing)
4. Upload zip of `extension-firefox` folder
5. Review takes ~1 week (or instant for "self-distributed")

---

## 💳 PART 4: Add Stripe Payments

For the Pro/Team/Business buttons to actually charge customers:

### Step 4.1 — Create Stripe Account

1. https://stripe.com → Sign up
2. Verify your business (Israeli bank account works)
3. Stripe Dashboard → Products → Create:
   - **Pro:** $9/month recurring
   - **Team:** $29/month recurring
   - **Business:** $99/month recurring

### Step 4.2 — Use Stripe Payment Links (simplest)

For each product:
1. Click "Create payment link"
2. Copy the URL (e.g., `https://buy.stripe.com/abc123`)
3. In `website/index.html`, find the "Subscribe" buttons:

```html
onclick="alert('Stripe integration: add your link here')"
```

Replace each with:

```html
onclick="window.location='https://buy.stripe.com/YOUR_LINK_FOR_PRO'"
```

### Step 4.3 — Handle Subscription Activation (later)

For now, customers pay → you manually grant their account higher quota.
Once you have ~50 paying users, integrate Stripe Webhooks to automate it.

---

## ✅ Pre-Launch Checklist

- [ ] Anthropic API key set in Netlify environment variables
- [ ] Monthly spending cap set in Anthropic console ($50 start)
- [ ] CORS `ALLOWED_ORIGINS` updated to your real domain
- [ ] `"*"` removed from `ALLOWED_ORIGINS` list
- [ ] Email addresses (`legal@`, `privacy@`, `sales@`) set up
- [ ] Stripe payment links connected to Subscribe buttons
- [ ] Tested scan with safe code → returns SAFE
- [ ] Tested scan with malicious code → returns CRITICAL
- [ ] Tested email subscription → check Netlify function logs
- [ ] Privacy Policy and Terms updated with your business details
- [ ] Tested in all 7 languages (use the flag buttons)

---

## 📊 What Each Customer Costs You

| Tier | Their Price | Your Anthropic Cost | Gross Margin |
|------|-------------|---------------------|--------------|
| Free  | $0      | ~$0.02     | (loss leader) |
| Pro   | $9/mo   | ~$0.45     | **95%** |
| Team  | $29/mo  | ~$1.50     | **95%** |
| Business | $99/mo | ~$9.00 | **91%** |

These are healthy SaaS margins. The numbers work.

---

## 🆘 Troubleshooting

**"Anthropic API error"** — Check that `ANTHROPIC_API_KEY` is set in Netlify env vars. Redeploy after adding.

**"Rate limit exceeded" on your own testing** — Edit `scan.js` to bump `MAX_REQUESTS_PER_MINUTE` to `60` during dev, then change back before launch.

**Scan returns nothing** — Open browser DevTools (F12) → Network tab → click Scan → look at the `/scan` request. The response body will tell you what's wrong.

**Extension popup is blank** — Right-click extension icon → "Inspect popup" → check Console for errors.

---

## 📈 Next Steps After Launch

1. **Submit to "Show HN"** on Hacker News (Tuesday morning EST)
2. **Post on r/ClaudeAI and r/netsec** on Reddit
3. **Tweet thread** with a malicious-vs-clean scan comparison
4. **Product Hunt launch** (12:01am PST for max visibility)
5. **Reach out to AI newsletters** (BensBites, AlphaSignal, etc.)
6. **Add to "awesome-claude" lists** on GitHub

---

**Built with Claude · Apache 2.0 License**
