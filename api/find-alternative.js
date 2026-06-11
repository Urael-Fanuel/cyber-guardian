// ─────────────────────────────────────────────────────────────────────────────
// find-alternative — search the public web (GitHub / npm) for tools that serve
// the same purpose as a flagged scan. Search only: no AI calls, no scanning.
// The frontend scans the returned candidates one by one through /api/scan,
// so every candidate scan also enriches the shared registry.
// ─────────────────────────────────────────────────────────────────────────────

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ("https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app" + (process.env.VERCEL_ENV === "production" ? "" : ",http://localhost:3000,http://localhost:5173")))
  .split(",").map(s => s.trim()).filter(Boolean);

const FETCH_TIMEOUT_MS = 8000;
const CACHE_TTL_MS = 10 * 60 * 1000;
const state = { cache: new Map(), ipHits: new Map() };

function setCors(req, res) {
  const origin = req.headers.origin || "";
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function clientIp(req) {
  const real = req.headers["x-real-ip"];
  if (real) return String(real).trim();
  const xff = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean);
  return xff.length ? xff[xff.length - 1] : "unknown";
}

function rateLimited(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const entry = state.ipHits.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count += 1;
  state.ipHits.set(ip, entry);
  return entry.count > 10;
}

async function fetchJson(url, headers = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers, signal: controller.signal });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function normalizedUrl(value) {
  return String(value || "").trim().replace(/\/$/, "").toLowerCase();
}

// Keep only meaningful search terms from the scan's purpose/tags
const STOP_WORDS = new Set(["this", "that", "with", "from", "into", "code", "tool", "tools", "server", "client", "simple", "basic", "demo", "example", "test", "using", "based", "support", "supports", "provides", "allows", "enables", "package", "extension", "skill", "various", "different", "multiple"]);
function searchTerms(raw) {
  return String(raw || "")
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, " ")
    .split(/\s+/)
    .filter(w => w.length >= 3 && !STOP_WORDS.has(w))
    .slice(0, 5);
}

function scopeQualifier(scope) {
  const value = String(scope || "").toLowerCase();
  if (value === "mcp") return "mcp server";
  if (value === "skill") return "ai skill";
  if (value === "extension") return "vscode extension";
  if (value === "github_action") return "github action";
  if (value === "package" || value === "dependency") return "";
  return "";
}

async function searchGithub(terms, scope) {
  const qualifier = scopeQualifier(scope);
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "Cyber-Guardian-Alternative-Search" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  // GitHub ANDs every search term, so a long specific query often returns zero
  // results. Start specific and progressively relax until something matches.
  const attempts = [terms.slice(0, 3), terms.slice(0, 2), terms.slice(0, 1)]
    .map(set => [qualifier, ...set].filter(Boolean).join(" ").trim())
    .filter((q, i, arr) => q && arr.indexOf(q) === i);

  for (const attempt of attempts) {
    const data = await fetchJson(`https://api.github.com/search/repositories?q=${encodeURIComponent(attempt)}&sort=stars&order=desc&per_page=8`, headers);
    const items = data && Array.isArray(data.items) ? data.items : [];
    const results = items
      .filter(repo => !repo.archived && !repo.fork)
      .map(repo => ({
        source_name: repo.full_name,
        source_url: repo.html_url,
        description: String(repo.description || "").slice(0, 160),
        stars: Number(repo.stargazers_count || 0),
        provider: "github",
      }));
    if (results.length >= 2) return results;
  }
  return [];
}

async function searchNpm(terms) {
  const query = encodeURIComponent(terms.join(" "));
  const data = await fetchJson(`https://registry.npmjs.org/-/v1/search?text=${query}&size=8`);
  if (!data || !Array.isArray(data.objects)) return [];
  return data.objects.map(obj => ({
    source_name: obj.package?.name || "",
    source_url: obj.package?.links?.npm || `https://www.npmjs.com/package/${obj.package?.name || ""}`,
    description: String(obj.package?.description || "").slice(0, 160),
    stars: Math.round(Number(obj.score?.detail?.popularity || 0) * 1000),
    provider: "npm",
  })).filter(item => item.source_name);
}

async function handler(req, res) {
  setCors(req, res);
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "GET") return res.status(405).json({ error: "Method not allowed" });

  if (rateLimited(clientIp(req))) {
    res.setHeader("Retry-After", "60");
    return res.status(429).json({ error: "Too many requests." });
  }

  const url = new URL(req.url, "http://localhost");
  const scope = String(url.searchParams.get("scope") || "mcp").slice(0, 30);
  const purpose = String(url.searchParams.get("q") || "").slice(0, 300);
  const excludeUrl = normalizedUrl(url.searchParams.get("exclude") || "");

  const terms = searchTerms(purpose);
  if (!terms.length) return res.status(200).json({ candidates: [], reason: "no_terms" });

  const cacheKey = `${scope}:${terms.join(" ")}`;
  const cached = state.cache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    const fresh = cached.candidates.filter(c => normalizedUrl(c.source_url) !== excludeUrl);
    return res.status(200).json({ candidates: fresh.slice(0, 3), cached: true });
  }

  const isPackage = ["package", "dependency"].includes(scope);
  const [githubResults, npmResults] = await Promise.all([
    searchGithub(terms, scope),
    isPackage ? searchNpm(terms) : Promise.resolve([]),
  ]);

  const seen = new Set();
  const candidates = [...githubResults, ...npmResults]
    .filter(item => {
      const key = normalizedUrl(item.source_url);
      if (!key || seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => b.stars - a.stars);

  state.cache.set(cacheKey, { candidates, expiresAt: Date.now() + CACHE_TTL_MS });
  if (state.cache.size > 500) {
    const oldest = [...state.cache.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt).slice(0, 250);
    for (const [k] of oldest) state.cache.delete(k);
  }

  const fresh = candidates.filter(c => normalizedUrl(c.source_url) !== excludeUrl);
  return res.status(200).json({ candidates: fresh.slice(0, 3) });
}

module.exports = handler;
