// api/site-stats.js — Cyber-Guardian Site Scan Statistics
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app,http://localhost:3000,http://localhost:5173')
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

function threatFamilies(summary) {
  return String(summary || '')
    .split(',')
    .map(name => name.trim().toUpperCase())
    .filter(Boolean);
}

function classifyScan(scan) {
  if (!scan || scan.status === 'STATUS_SAFE') return 'safe';
  const families = threatFamilies(scan.threats_summary);
  if (families.some(name => BLOCKING_THREAT_FAMILIES.has(name))) return 'blocked';
  return 'review';
}

function normalizeScope(scope) {
  const value = String(scope || '').trim().toLowerCase();
  if (value === 'mcp' || value.includes('mcp')) return 'mcp';
  if (value === 'skill' || value.includes('skill')) return 'skill';
  if (value === 'extension' || value === 'ext' || value.includes('extension') || value.includes('ide')) return 'extension';
  return 'extension';
}

function arrayValue(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
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
  if (!a || !b || normalizeScope(a.scope) !== normalizeScope(b.scope)) return 0;
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
    .filter(candidate => normalizeScope(candidate.scope) === normalizeScope(scan.scope))
    .filter(candidate => {
      const candidateUrl = normalizedUrl(candidate.source_url);
      if (!candidateUrl) return false;
      if (currentUrl && candidateUrl === currentUrl) return false;
      return true;
    })
    .filter(candidate => ['safe', 'review'].includes(classifyScan(candidate)))
    .map(candidate => ({ candidate, score: similarityScore(scan, candidate) }))
    .filter(item => item.score > 0)
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
    component_type: candidate.component_type || '',
    capabilities: arrayValue(candidate.capabilities).slice(0, 4),
    decision: classifyScan(candidate),
    threat_score: candidate.threat_score || 0,
    scanned_at: candidate.scanned_at,
  }));
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(200).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: 'Not configured' });

  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_KEY);
    let { data: scans, error } = await sb
      .from('site_scans')
      .select('scope,status,threat_score,threat_count,threats_summary,scanned_at,source_name,source_url,source_owner,code_purpose,component_type,capabilities,use_case_tags')
      .order('scanned_at', { ascending: false })
      .limit(5000);

    if (error && /column .* does not exist|schema cache|Could not find/i.test(error.message || '')) {
      const legacy = await sb
        .from('site_scans')
        .select('scope,status,threat_score,threat_count,threats_summary,scanned_at')
        .order('scanned_at', { ascending: false })
        .limit(5000);
      scans = legacy.data;
      error = legacy.error;
    }
    if (error) throw error;

    if (!scans || scans.length === 0) {
      return res.status(200).json({
        total: 0, safe: 0, moderate: 0, critical: 0,
        review: 0, blocked: 0,
        detection_rate: 0, attention_rate: 0, blocked_rate: 0, avg_threat_score: 0,
        by_scope: { mcp: 0, skill: 0, extension: 0 },
        recent: [], trend: []
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

    const by_scope = { mcp: 0, skill: 0, extension: 0 };
    for (const s of scans) {
      const scope = normalizeScope(s.scope);
      if (by_scope[scope] !== undefined) by_scope[scope]++;
    }

    // Last 10 scans for recent feed
    const recent = scans.slice(0, 10).map(s => ({
      scope:            normalizeScope(s.scope),
      status:           s.status,
      raw_status:       s.status,
      decision:         classifyScan(s),
      threat_score:     s.threat_score,
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
        threats:  dayDecisions.filter(d => d === 'blocked').length,
        blocked:  dayDecisions.filter(d => d === 'blocked').length,
        review:   dayDecisions.filter(d => d === 'review').length
      });
    }

    return res.status(200).json({
      total, safe, moderate, critical, review, blocked,
      detection_rate, attention_rate, blocked_rate, avg_threat_score,
      by_scope, recent, trend,
      last_scan: scans[0]?.scanned_at || null
    });

  } catch (err) {
    console.error('[site-stats]', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
