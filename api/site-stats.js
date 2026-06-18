// api/site-stats.js — Cyber-Guardian Site Scan Statistics
const { createClient } = require('@supabase/supabase-js');
const { securityScoreForResult, isVerifiedInstallResult } = require('../lib/security-score');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ('https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app' + (process.env.VERCEL_ENV === 'production' ? '' : ',http://localhost:3000,http://localhost:5173')))
  .split(',').map(s => s.trim()).filter(Boolean);

function getOrigin(req) {
  return req.headers.origin || '';
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function setCors(req, res) {
  const origin = getOrigin(req);
  if (origin && isAllowedOrigin(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Content-Type', 'application/json');
}

function getUrl(req) {
  try {
    return new URL(req.url, 'https://cyberguardianscan.com');
  } catch {
    return new URL('https://cyberguardianscan.com/api/site-stats');
  }
}

function rejectDisallowedOrigin(req, res) {
  if (isAllowedOrigin(getOrigin(req))) return false;
  res.status(403).json({ error: 'Origin not allowed' });
  return true;
}

const BLOCKING_THREAT_FAMILIES = new Set([
  'REVERSE_SHELL',
  'BACKDOOR',
  'CREDENTIAL_THEFT',
  'API_KEY_THEFT',
  'MCP_CREDENTIAL_EXFILTRATION',
  'DATA_EXFILTRATION',
  'C2_CALLBACK',
  'KEYLOGGER_PATTERN',
  'CLIPBOARD_HIJACK',
  'CRYPTO_MINING',
  'PRIVILEGE_ESCALATION',
  'LOGIC_BOMB'
]);

const MAX_ALTERNATIVE_SOURCE_CHARS = 50000;
const MAX_ALTERNATIVE_SOURCE_FILES = 6;

function tableMissing(error) {
  const message = `${error?.message || ''} ${error?.details || ''} ${error?.hint || ''} ${error?.code || ''}`;
  return /relation .* does not exist|column .* does not exist|schema cache|Could not find|PGRST20[04]/i.test(message);
}

function cleanEvidenceText(value, max = 500) {
  return String(value || '').replace(/\s+/g, ' ').trim().slice(0, max);
}

function normalizeEvidenceRow(row) {
  return {
    evidence_id: cleanEvidenceText(row.evidence_id, 80),
    family: cleanEvidenceText(row.family || 'UNCLASSIFIED', 80).toUpperCase(),
    severity: cleanEvidenceText(row.severity || 'MEDIUM', 20).toUpperCase(),
    confidence: Math.max(0, Math.min(1, Number(row.confidence || 0))),
    evidence: cleanEvidenceText(row.evidence, 500),
    line_hint: cleanEvidenceText(row.line_hint, 500),
    plain_explanation: cleanEvidenceText(row.plain_explanation, 500),
    impact_key: cleanEvidenceText(row.impact_key, 80),
    user_impact: cleanEvidenceText(row.user_impact, 500),
    fix_key: cleanEvidenceText(row.fix_key, 80),
    fix_guidance: cleanEvidenceText(row.fix_guidance, 500),
  };
}

async function evidenceMapForRecentScans(sb, scans) {
  const scanRunIds = [...new Set(
    (scans || [])
      .slice(0, 10)
      .map(scan => scan.scan_run_id)
      .filter(Boolean)
  )];
  if (!scanRunIds.length) return new Map();

  const { data, error } = await sb
    .from('cg_scan_evidence')
    .select('scan_run_id,evidence_id,family,severity,confidence,evidence,line_hint,plain_explanation,impact_key,user_impact,fix_key,fix_guidance,created_at')
    .in('scan_run_id', scanRunIds)
    .order('created_at', { ascending: true });

  if (error) {
    if (!tableMissing(error)) console.error('[site-stats-evidence]', error.message);
    return new Map();
  }

  const byRun = new Map();
  for (const row of data || []) {
    if (!row.scan_run_id) continue;
    if (!byRun.has(row.scan_run_id)) byRun.set(row.scan_run_id, []);
    byRun.get(row.scan_run_id).push(normalizeEvidenceRow(row));
  }
  return byRun;
}

function githubRequestHeaders() {
  const headers = {
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'Cyber-Guardian-Alternative-Verifier',
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

// Only these GitHub-owned hosts may be fetched for alternative-source verification.
// The last two are legitimate redirect targets GitHub itself uses for raw content.
const ALTERNATIVE_SOURCE_HOSTS = [
  'github.com',
  'raw.githubusercontent.com',
  'api.github.com',
  'codeload.github.com',
  'objects.githubusercontent.com',
];

function trustedSourceHost(hostname) {
  return ALTERNATIVE_SOURCE_HOSTS.some(host =>
    hostname === host || (host.startsWith('*.') && hostname.endsWith(host.slice(1))));
}

function parseGithubSourceUrl(value) {
  let url;
  try {
    url = new URL(String(value || '').trim());
  } catch {
    return null;
  }

  if (url.protocol !== 'https:') return null;
  const parts = url.pathname.split('/').filter(Boolean);

  if (url.hostname === 'raw.githubusercontent.com' && parts.length >= 4) {
    const [owner, repo, branch, ...pathParts] = parts;
    return {
      kind: 'file',
      owner,
      repo,
      branch,
      path: pathParts.join('/'),
      raw_url: url.toString(),
      source_url: url.toString(),
    };
  }

  if (url.hostname !== 'github.com' || parts.length < 2) return null;
  const [owner, repo, marker, branch, ...pathParts] = parts;
  const cleanRepo = String(repo || '').replace(/\.git$/i, '');

  if ((marker === 'blob' || marker === 'raw') && branch && pathParts.length) {
    return {
      kind: 'file',
      owner,
      repo: cleanRepo,
      branch,
      path: pathParts.join('/'),
      raw_url: `https://raw.githubusercontent.com/${owner}/${cleanRepo}/${branch}/${pathParts.join('/')}`,
      source_url: `https://github.com/${owner}/${cleanRepo}/blob/${branch}/${pathParts.join('/')}`,
    };
  }

  return {
    kind: 'repo',
    owner,
    repo: cleanRepo,
    source_url: `https://github.com/${owner}/${cleanRepo}`,
  };
}

async function fetchTextWithLimit(url, headers = {}) {
  const initial = new URL(url);
  if (initial.protocol !== 'https:' || !trustedSourceHost(initial.hostname)) {
    throw new Error('Source host is not trusted.');
  }
  const response = await fetch(url, { headers });
  if (!response.ok) throw new Error(`Source fetch failed: ${response.status}`);
  // Re-check the host after any redirect, so a GitHub URL cannot bounce us to an untrusted host.
  if (!trustedSourceHost(new URL(response.url || url).hostname)) {
    throw new Error('Source redirected to an untrusted host.');
  }
  const text = await response.text();
  return text.slice(0, MAX_ALTERNATIVE_SOURCE_CHARS);
}

async function fetchGithubJson(url) {
  const initial = new URL(url);
  if (initial.protocol !== 'https:' || !trustedSourceHost(initial.hostname)) {
    throw new Error('GitHub host is not trusted.');
  }
  const response = await fetch(url, { headers: githubRequestHeaders() });
  if (!response.ok) throw new Error(`GitHub API failed: ${response.status}`);
  // Re-check the host after any redirect before trusting the response.
  if (!trustedSourceHost(new URL(response.url || url).hostname)) {
    throw new Error('GitHub request redirected to an untrusted host.');
  }
  return response.json();
}

function isUsefulSourcePath(path) {
  const p = String(path || '').toLowerCase();
  if (!p || /(^|\/)(node_modules|vendor|dist|build|coverage|\.git|\.next|out)\//.test(p)) return false;
  if (/\.(png|jpe?g|gif|webp|svg|ico|lock|zip|tar|gz|7z|exe|dll|so|dylib|pdf)$/i.test(p)) return false;
  return /\.(js|mjs|cjs|ts|tsx|jsx|py|json|ya?ml|toml|md|sh)$/i.test(p);
}

function sourcePathRank(path) {
  const p = String(path || '').toLowerCase();
  let score = 0;
  if (/(package\.json|manifest\.json|requirements\.txt|pyproject\.toml|setup\.py|action\.ya?ml)$/.test(p)) score += 20;
  if (/(mcp|skill|extension|server|tool|agent|workflow|index|main|src)/.test(p)) score += 8;
  if (/\.(js|ts|py|mjs|cjs)$/.test(p)) score += 6;
  if (/\.(json|ya?ml|toml)$/.test(p)) score += 4;
  if (/readme\.md$/.test(p)) score += 1;
  return score;
}

async function fetchCurrentGithubSource(sourceUrl) {
  const source = parseGithubSourceUrl(sourceUrl);
  if (!source) throw new Error('Only GitHub source URLs can be automatically verified right now.');

  if (source.kind === 'file') {
    const code = await fetchTextWithLimit(source.raw_url, githubRequestHeaders());
    return {
      code,
      source_url: source.source_url,
      source_owner: source.owner,
      source_name: `${source.owner}/${source.repo}/${source.path}`,
      files: [source.path],
    };
  }

  const repoApi = `https://api.github.com/repos/${source.owner}/${source.repo}`;
  const repo = await fetchGithubJson(repoApi);
  const branch = repo.default_branch || 'main';
  const tree = await fetchGithubJson(`${repoApi}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
  const candidates = Array.isArray(tree.tree) ? tree.tree : [];
  const files = candidates
    .filter(item => item.type === 'blob')
    .filter(item => item.size > 0 && item.size <= 35000)
    .filter(item => isUsefulSourcePath(item.path))
    .sort((a, b) => {
      const rankDelta = sourcePathRank(b.path) - sourcePathRank(a.path);
      if (rankDelta) return rankDelta;
      return (a.size || 0) - (b.size || 0);
    })
    .slice(0, MAX_ALTERNATIVE_SOURCE_FILES);

  if (!files.length) throw new Error('No useful source files were found for automatic verification.');

  let code = '';
  const included = [];
  for (const file of files) {
    if (code.length >= MAX_ALTERNATIVE_SOURCE_CHARS) break;
    const rawUrl = `https://raw.githubusercontent.com/${source.owner}/${source.repo}/${branch}/${file.path}`;
    try {
      const text = await fetchTextWithLimit(rawUrl, githubRequestHeaders());
      const block = `\n\n// Source file: ${file.path}\n${text}`;
      if (code.length + block.length > MAX_ALTERNATIVE_SOURCE_CHARS) continue;
      code += block;
      included.push(file.path);
    } catch {
      // Skip individual files that cannot be fetched; the remaining files still provide a useful verification sample.
    }
  }

  if (!code.trim()) throw new Error('Could not fetch source files for automatic verification.');
  return {
    code: code.trim(),
    source_url: source.source_url,
    source_owner: source.owner,
    source_name: `${source.owner}/${source.repo}`,
    files: included,
  };
}

function threatFamilies(summary) {
  return String(summary || '')
    .split(',')
    .map(name => name.trim().toUpperCase())
    .filter(Boolean);
}

function classifyScan(scan) {
  if (!scan) return 'inconclusive';
  const families = threatFamilies(scan.threats_summary);
  const threatCount = Number(scan.threat_count || 0);
  const decision = String(scan.decision || '').trim().toLowerCase();
  const riskType = String(scan.risk_type || '').trim().toLowerCase();
  const coverage = scan.scan_coverage && typeof scan.scan_coverage === 'object' ? scan.scan_coverage : {};
  const incompleteCoverage = scan.coverage_capped === true || coverage.complete === false;

  if (incompleteCoverage) return 'inconclusive';
  if (['safe', 'install_ok'].includes(decision)) return 'safe';
  if (['blocked', 'do_not_install'].includes(decision)) return 'blocked';
  if (['fix_before_use', 'install_with_caution', 'review'].includes(decision)) return 'review';
  if (riskType === 'malicious_behavior') return 'blocked';
  if (riskType === 'security_weakness') return 'review';
  if (riskType === 'insufficient_context') return 'inconclusive';

  if (scan.status === 'STATUS_SAFE' && threatCount === 0 && families.length === 0) return 'safe';
  if (families.some(name => BLOCKING_THREAT_FAMILIES.has(name))) return 'blocked';
  if (threatCount > 0 || families.length > 0) return 'review';
  return 'inconclusive';
}

function isConclusivePublicScan(scan) {
  return ['safe', 'review', 'blocked'].includes(classifyScan(scan));
}

function normalizeScope(scope) {
  const value = String(scope || '').trim().toLowerCase();
  if (value === 'mcp' || value.includes('mcp')) return 'mcp';
  if (value === 'skill' || value.includes('skill')) return 'skill';
  if (value === 'extension' || value === 'ext' || value.includes('extension') || value.includes('ide')) return 'extension';
  if (value.includes('action') || value.includes('workflow') || value.includes('package') || value.includes('npm') || value.includes('pypi') || value.includes('depend')) return 'supply_chain';
  return 'supply_chain';
}

function alternativeScopeKey(scope) {
  const value = String(scope || '').trim().toLowerCase();
  if (value.includes('action') || value.includes('workflow')) return 'github_action';
  if (value.includes('package') || value.includes('npm') || value.includes('pypi')) return 'package';
  if (value.includes('depend')) return 'dependency';
  return normalizeScope(scope);
}

function arrayValue(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function listParam(url, name) {
  return String(url.searchParams.get(name) || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean)
    .slice(0, 12);
}

const TAG_STOP_WORDS = new Set([
  'ai', 'api', 'app', 'apps', 'code', 'coding', 'dev', 'developer', 'extension', 'extensions',
  'github', 'ide', 'mcp', 'npm', 'package', 'plugin', 'plugins', 'repo', 'server', 'servers',
  'skill', 'skills', 'tool', 'tools', 'vscode', 'cursor', 'claude', 'openai', 'view', 'kit',
]);

function tokenize(value) {
  return String(value || '')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map(token => token.trim())
    .filter(token => token.length >= 4)
    .filter(token => !TAG_STOP_WORDS.has(token))
    .slice(0, 12);
}

function tagSet(scan) {
  const tags = [
    ...arrayValue(scan.use_case_tags),
    ...arrayValue(scan.capabilities),
  ].flatMap(tokenize);

  const component = String(scan.component_type || '').toLowerCase();
  if (component && !['unknown', 'other', scan.scope].includes(component)) {
    tags.push(...tokenize(component));
  }

  tags.push(...tokenize(scan.code_purpose));
  tags.push(...tokenize(scan.source_name));
  return new Set(tags);
}

function similarityScore(a, b) {
  if (!a || !b || alternativeScopeKey(a.scope) !== alternativeScopeKey(b.scope)) return 0;
  const aTags = tagSet(a);
  const bTags = tagSet(b);
  if (aTags.size === 0 || bTags.size === 0) return 0;
  let overlap = 0;
  for (const tag of aTags) if (bTags.has(tag)) overlap++;
  return overlap;
}

function normalizedUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const url = new URL(raw);
    url.hash = '';
    url.search = '';
    return url.toString().replace(/\/$/, '').toLowerCase();
  } catch {
    return raw.replace(/\/$/, '').toLowerCase();
  }
}

function saferAlternatives(scan, scans) {
  const decision = classifyScan(scan);
  if (decision === 'safe') return [];
  const currentUrl = normalizedUrl(scan.source_url);
  const seenUrls = new Set();
  const ranked = scans
    .filter(candidate => candidate !== scan)
    .filter(candidate => alternativeScopeKey(candidate.scope) === alternativeScopeKey(scan.scope))
    .filter(candidate => {
      const candidateUrl = normalizedUrl(candidate.source_url);
      if (!candidateUrl) return false;
      if (currentUrl && candidateUrl === currentUrl) return false;
      return true;
    })
    .filter(candidate => ['safe', 'review'].includes(classifyScan(candidate)))
    .map(candidate => ({ candidate, score: similarityScore(scan, candidate) }))
    // Require a real topical match (3+ shared tags). One shared generic word used to
    // surface unrelated tools (e.g. a hello-world demo) as an "alternative".
    .filter(item => item.score >= 3)
    .sort((a, b) => {
      const decisionDelta = (classifyScan(a.candidate) === 'safe' ? 0 : 1) - (classifyScan(b.candidate) === 'safe' ? 0 : 1);
      if (decisionDelta) return decisionDelta;
      if (b.score !== a.score) return b.score - a.score;
      return (a.candidate.threat_score || 0) - (b.candidate.threat_score || 0);
    })
    .filter(({ candidate }) => {
      const candidateUrl = normalizedUrl(candidate.source_url);
      if (seenUrls.has(candidateUrl)) return false;
      seenUrls.add(candidateUrl);
      return true;
    });

  return ranked.slice(0, 3).map(({ candidate }) => ({
    source_name: candidate.source_name || '',
    source_url: candidate.source_url || '',
    code_purpose: candidate.code_purpose || '',
    scope: candidate.scope || '',
    component_type: candidate.component_type || '',
    capabilities: arrayValue(candidate.capabilities).slice(0, 4),
    decision: classifyScan(candidate),
    threat_score: candidate.threat_score || 0,
    security_score: securityScoreForResult(candidate, classifyScan(candidate)),
    scanned_at: candidate.scanned_at,
    verification_status: 'historical_match_only',
    requires_fresh_rescan: true,
  }));
}

// ── Web-alternative search (mode=web_alternatives) ─────────────────────────
// Searches GitHub/npm for tools with the same purpose as a flagged scan.
// Search only — no AI calls. The frontend scans returned candidates via /api/scan.
const WEB_ALT_TIMEOUT_MS = 8000;
const webAltState = { cache: new Map() };
const WEB_ALT_STOP_WORDS = new Set(['this', 'that', 'with', 'from', 'into', 'code', 'tool', 'tools', 'server', 'client', 'simple', 'basic', 'demo', 'example', 'test', 'using', 'based', 'support', 'supports', 'provides', 'allows', 'enables', 'package', 'extension', 'skill', 'various', 'different', 'multiple']);

async function webAltFetchJson(targetUrl, headers = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WEB_ALT_TIMEOUT_MS);
  try {
    const response = await fetch(targetUrl, { headers, signal: controller.signal });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

function webAltSearchTerms(raw) {
  return String(raw || '')
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length >= 3 && !WEB_ALT_STOP_WORDS.has(w))
    .slice(0, 5);
}

function webAltScopeQualifier(scope) {
  const value = String(scope || '').toLowerCase();
  if (value === 'mcp') return 'mcp server';
  if (value === 'skill') return 'ai skill';
  if (value === 'extension') return 'vscode extension';
  if (value === 'github_action') return 'github action';
  return '';
}

async function webAltSearchGithub(terms, scope) {
  const qualifier = webAltScopeQualifier(scope);
  const headers = { Accept: 'application/vnd.github+json', 'User-Agent': 'Cyber-Guardian-Alternative-Search' };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

  // GitHub ANDs every search term — start specific, relax until results appear
  const attempts = [terms.slice(0, 3), terms.slice(0, 2), terms.slice(0, 1)]
    .map(set => [qualifier, ...set].filter(Boolean).join(' ').trim())
    .filter((q, i, arr) => q && arr.indexOf(q) === i);

  for (const attempt of attempts) {
    const data = await webAltFetchJson(`https://api.github.com/search/repositories?q=${encodeURIComponent(attempt)}&sort=stars&order=desc&per_page=8`, headers);
    const items = data && Array.isArray(data.items) ? data.items : [];
    const results = items
      .filter(repo => !repo.archived && !repo.fork)
      .map(repo => ({
        source_name: repo.full_name,
        source_url: repo.html_url,
        description: String(repo.description || '').slice(0, 160),
        stars: Number(repo.stargazers_count || 0),
        provider: 'github',
      }));
    if (results.length >= 2) return results;
  }
  return [];
}

async function webAltSearchNpm(terms) {
  const data = await webAltFetchJson(`https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(terms.join(' '))}&size=8`);
  if (!data || !Array.isArray(data.objects)) return [];
  return data.objects.map(obj => ({
    source_name: obj.package?.name || '',
    source_url: obj.package?.links?.npm || `https://www.npmjs.com/package/${obj.package?.name || ''}`,
    description: String(obj.package?.description || '').slice(0, 160),
    stars: Math.round(Number(obj.score?.detail?.popularity || 0) * 1000),
    provider: 'npm',
  })).filter(item => item.source_name);
}

async function handleWebAlternatives(url, res) {
  const scope = String(url.searchParams.get('scope') || 'mcp').slice(0, 30);
  const purpose = String(url.searchParams.get('q') || '').slice(0, 300);
  const excludeUrl = normalizedUrl(url.searchParams.get('exclude') || '');

  const terms = webAltSearchTerms(purpose);
  if (!terms.length) return res.status(200).json({ candidates: [], reason: 'no_terms' });

  const cacheKey = `${scope}:${terms.join(' ')}`;
  const cached = webAltState.cache.get(cacheKey);
  if (cached && Date.now() < cached.expiresAt) {
    const fresh = cached.candidates.filter(c => normalizedUrl(c.source_url) !== excludeUrl);
    return res.status(200).json({ candidates: fresh.slice(0, 3), cached: true });
  }

  const isPackage = ['package', 'dependency'].includes(scope);
  const [githubResults, npmResults] = await Promise.all([
    webAltSearchGithub(terms, scope),
    isPackage ? webAltSearchNpm(terms) : Promise.resolve([]),
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

  webAltState.cache.set(cacheKey, { candidates, expiresAt: Date.now() + 10 * 60 * 1000 });
  if (webAltState.cache.size > 500) {
    const oldest = [...webAltState.cache.entries()].sort((a, b) => a[1].expiresAt - b[1].expiresAt).slice(0, 250);
    for (const [k] of oldest) webAltState.cache.delete(k);
  }

  const fresh = candidates.filter(c => normalizedUrl(c.source_url) !== excludeUrl);
  return res.status(200).json({ candidates: fresh.slice(0, 3) });
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(200).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const url = getUrl(req);
    const mode = String(url.searchParams.get('mode') || 'stats').trim().toLowerCase();

    if (mode === 'web_alternatives') {
      return await handleWebAlternatives(url, res);
    }

    if (mode === 'alternative_source') {
      try {
        const sourceUrl = url.searchParams.get('source_url') || '';
        const source = await fetchCurrentGithubSource(sourceUrl);
        return res.status(200).json({
          status: 'ok',
          source: 'github_current_source',
          scope: normalizeScope(url.searchParams.get('scope') || ''),
          fetched_at: new Date().toISOString(),
          ...source,
        });
      } catch (err) {
        return res.status(400).json({
          status: 'source_unavailable',
          error: err.message || 'Could not fetch current source for verification.',
        });
      }
    }

    if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: 'Not configured' });
    const sb = createClient(SUPABASE_URL, SUPABASE_KEY);

    // Code-history search: look up whether a code fingerprint (hash) or a source
    // name/URL was already scanned, and return its verdict + Verified badge.
    if (mode === 'search') {
      const hash = String(url.searchParams.get('hash') || '').trim().toLowerCase();
      const q = String(url.searchParams.get('q') || '').trim();
      const searchCols = 'scope,status,threat_score,threat_count,threats_summary,scanned_at,source_name,source_url,source_owner,code_hash';
      let searchQuery = sb.from('site_scans').select(searchCols).order('scanned_at', { ascending: false }).limit(20);
      if (/^[a-f0-9]{16,64}$/.test(hash)) {
        searchQuery = searchQuery.eq('code_hash', hash);
      } else if (q.length >= 3) {
        const term = q.replace(/[%,()*]/g, ' ').slice(0, 120);
        searchQuery = searchQuery.or(`source_name.ilike.%${term}%,source_url.ilike.%${term}%`);
      } else {
        return res.status(400).json({ error: 'Provide a code fingerprint (hash) or a search term of at least 3 characters.' });
      }
      const { data: searchRows, error: searchError } = await searchQuery;
      if (searchError) {
        if (tableMissing(searchError)) return res.status(200).json({ status: 'empty', matches: [] });
        throw searchError;
      }
      const matches = (searchRows || []).filter(isConclusivePublicScan).map(s => {
        const decision = classifyScan(s);
        return {
          source_name: s.source_name || '',
          source_url: s.source_url || '',
          scope: s.scope || '',
          decision,
          security_score: securityScoreForResult(s, decision),
          verified_by_cyber_guardian: isVerifiedInstallResult(s, decision),
          scanned_at: s.scanned_at,
          code_fingerprint: s.code_hash || '',
        };
      });
      return res.status(200).json({ status: matches.length ? 'found' : 'not_found', matches });
    }

    // Verified-tools showcase: gold-badge (Verified) scans only, for the homepage banner.
    if (mode === 'verified') {
      const verifiedCols = 'scope,status,threat_score,threat_count,threats_summary,scanned_at,source_name,source_url,source_owner,code_purpose,code_hash';
      const { data: verifiedRows, error: verifiedError } = await sb
        .from('site_scans')
        .select(verifiedCols)
        .order('scanned_at', { ascending: false })
        .limit(300);
      if (verifiedError) {
        if (tableMissing(verifiedError)) return res.status(200).json({ status: 'empty', items: [] });
        throw verifiedError;
      }
      const seen = new Set();
      const items = [];
      for (const s of (verifiedRows || [])) {
        const decision = classifyScan(s);
        if (!isVerifiedInstallResult(s, decision)) continue;
        const key = String(s.source_url || s.source_name || s.code_hash || '').toLowerCase();
        if (key && seen.has(key)) continue;
        if (key) seen.add(key);
        items.push({
          source_name: s.source_name || '',
          source_url: s.source_url || '',
          scope: s.scope || '',
          code_purpose: s.code_purpose || '',
          security_score: securityScoreForResult(s, decision),
          scanned_at: s.scanned_at,
          code_fingerprint: s.code_hash || '',
        });
        if (items.length >= 12) break;
      }
      return res.status(200).json({ status: items.length ? 'ok' : 'empty', items });
    }

    const baseSelect = 'scope,status,threat_score,threat_count,threats_summary,scanned_at,source_name,source_url,source_owner,code_purpose,component_type,capabilities,use_case_tags,decision,risk_type,scan_coverage,coverage_capped';
    const enrichedSelect = `scan_run_id,${baseSelect}`;
    let { data: scans, error } = await sb
      .from('site_scans')
      .select(`${enrichedSelect},dynamic_sandbox`)
      .order('scanned_at', { ascending: false })
      .limit(5000);

    if (error && tableMissing(error)) {
      const enriched = await sb
        .from('site_scans')
        .select(enrichedSelect)
        .order('scanned_at', { ascending: false })
        .limit(5000);
      scans = enriched.data;
      error = enriched.error;
    }

    if (error && tableMissing(error)) {
      const withoutRunId = await sb
        .from('site_scans')
        .select(`${baseSelect},dynamic_sandbox`)
        .order('scanned_at', { ascending: false })
        .limit(5000);
      scans = withoutRunId.data;
      error = withoutRunId.error;
    }

    if (error && tableMissing(error)) {
      const legacy = await sb
        .from('site_scans')
        .select('scope,status,threat_score,threat_count,threats_summary,scanned_at')
        .order('scanned_at', { ascending: false })
        .limit(5000);
      scans = legacy.data;
      error = legacy.error;
    }
    if (error) throw error;
    const allScans = scans || [];
    const inconclusive = allScans.filter(s => classifyScan(s) === 'inconclusive').length;
    scans = allScans.filter(isConclusivePublicScan);

    if (!scans || scans.length === 0) {
      if (mode === 'alternatives') {
        return res.status(200).json({ alternatives: [], source: 'site_scans', status: 'empty' });
      }
      return res.status(200).json({
        total: 0, safe: 0, moderate: 0, critical: 0,
        review: 0, blocked: 0,
        inconclusive,
        detection_rate: 0, attention_rate: 0, blocked_rate: 0, avg_threat_score: 0,
        by_scope: { mcp: 0, skill: 0, extension: 0, supply_chain: 0 },
        recent: [], trend: []
      });
    }

    if (mode === 'alternatives') {
      const virtualScan = {
        scope: url.searchParams.get('scope') || 'mcp',
        status: 'STATUS_CRITICAL',
        threat_score: 100,
        threat_count: 1,
        threats_summary: url.searchParams.get('threats') || '',
        source_url: url.searchParams.get('source_url') || '',
        code_purpose: url.searchParams.get('purpose') || '',
        component_type: url.searchParams.get('component_type') || '',
        capabilities: listParam(url, 'capabilities'),
        use_case_tags: listParam(url, 'tags'),
      };
      return res.status(200).json({
        alternatives: saferAlternatives(virtualScan, scans).slice(0, 1),
        source: 'site_scans',
        status: 'ok',
      });
    }

    const total     = scans.length;
    const decisions = scans.map(s => ({ scan: s, decision: classifyScan(s) }));
    const safe      = decisions.filter(s => s.decision === 'safe').length;
    const review    = decisions.filter(s => s.decision === 'review').length;
    const blocked   = decisions.filter(s => s.decision === 'blocked').length;
    const moderate  = review;
    const critical  = blocked;
    const attention_rate = total > 0 ? Math.round(((review + blocked) / total) * 100) : 0;
    const blocked_rate = total > 0 ? Math.round((blocked / total) * 100) : 0;
    const detection_rate = attention_rate;
    const avg_threat_score = total > 0 ? Math.round(scans.reduce((a, s) => a + (s.threat_score || 0), 0) / total) : 0;
    const evidenceByRun = await evidenceMapForRecentScans(sb, scans);

    const by_scope = { mcp: 0, skill: 0, extension: 0, supply_chain: 0 };
    for (const s of scans) {
      const scope = normalizeScope(s.scope);
      if (by_scope[scope] !== undefined) by_scope[scope]++;
    }

    // Last 10 scans for recent feed
    const recent = scans.slice(0, 10).map(s => ({
      scan_run_id:       s.scan_run_id || '',
      scope:            s.scope || normalizeScope(s.scope),
      status:           s.status,
      raw_status:       s.status,
      decision:         classifyScan(s),
      threat_score:     s.threat_score,
      security_score:   securityScoreForResult(s, classifyScan(s)),
      verified_by_cyber_guardian: isVerifiedInstallResult(s, classifyScan(s)),
      threat_count:     s.threat_count,
      threats_summary:  s.threats_summary || '',
      scanned_at:       s.scanned_at,
      source_name:      s.source_name || '',
      source_url:       s.source_url || '',
      source_owner:     s.source_owner || '',
      code_purpose:     s.code_purpose || '',
      component_type:   s.component_type || s.scope || '',
      capabilities:     arrayValue(s.capabilities),
      use_case_tags:    arrayValue(s.use_case_tags),
      dynamic_sandbox:  s.dynamic_sandbox && typeof s.dynamic_sandbox === 'object' ? s.dynamic_sandbox : {},
      evidence:         s.scan_run_id ? (evidenceByRun.get(s.scan_run_id) || []) : [],
      alternatives:     saferAlternatives(s, scans),
    }));

    // Daily trend — last 7 days
    const trend = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const dayScans = scans.filter(s => s.scanned_at && s.scanned_at.startsWith(dateStr));
      const dayDecisions = dayScans.map(s => classifyScan(s));
      trend.push({
        date:     dateStr,
        total:    dayScans.length,
        mcp:      dayScans.filter(s => normalizeScope(s.scope) === 'mcp').length,
        skill:    dayScans.filter(s => normalizeScope(s.scope) === 'skill').length,
        extension: dayScans.filter(s => normalizeScope(s.scope) === 'extension').length,
        supply_chain: dayScans.filter(s => normalizeScope(s.scope) === 'supply_chain').length,
        threats:  dayDecisions.filter(d => d === 'blocked').length,
        blocked:  dayDecisions.filter(d => d === 'blocked').length,
        review:   dayDecisions.filter(d => d === 'review').length
      });
    }

    return res.status(200).json({
      total, safe, moderate, critical, review, blocked, inconclusive,
      detection_rate, attention_rate, blocked_rate, avg_threat_score,
      by_scope, recent, trend,
      last_scan: scans[0]?.scanned_at || null
    });

  } catch (err) {
    console.error('[site-stats]', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
