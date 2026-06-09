// api/mcp-scan.js — Cyber-Guardian Dashboard API (Vercel Node.js)
// Routes: ?action=stats | servers | threats | history | trigger

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const API_SECRET   = process.env.SCANNER_API_SECRET || '';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || ('https://cyberguardianscan.com,https://cyber-guardian-mu.vercel.app' + (process.env.VERCEL_ENV === 'production' ? '' : ',http://localhost:3000,http://localhost:5173')))
  .split(',').map(s => s.trim()).filter(Boolean);

function getSupabase() {
  return createClient(SUPABASE_URL, SUPABASE_KEY);
}

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
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json');
}

function rejectDisallowedOrigin(req, res) {
  if (isAllowedOrigin(getOrigin(req))) return false;
  res.status(403).json({ error: 'Origin not allowed' });
  return true;
}

function clampInt(value, fallback, min, max) {
  const parsed = parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

async function actionStats(sb, res) {
  const { data: runs }    = await sb.from('mcp_scan_runs').select('id,started_at,completed_at,total_scanned,total_malicious,by_source,by_risk_level,by_category').order('started_at', { ascending: false }).limit(1);
  const { data: servers } = await sb.from('mcp_servers').select('risk_level, source');
  const { data: cats }    = await sb.from('mcp_threat_category_counts').select('category,total');
  const { data: trend }   = await sb.from('mcp_scan_runs').select('started_at,total_scanned,total_malicious').order('started_at', { ascending: false }).limit(7);

  const riskCounts = {}, srcCounts = {};
  for (const r of (servers || [])) {
    riskCounts[r.risk_level] = (riskCounts[r.risk_level] || 0) + 1;
    srcCounts[r.source]      = (srcCounts[r.source] || 0) + 1;
  }

  res.status(200).json({
    latest_run:        runs?.[0] || {},
    risk_counts:       riskCounts,
    source_counts:     srcCounts,
    threat_categories: cats || [],
    scan_trend:        [...(trend || [])].reverse(),
    total_servers:     Object.values(riskCounts).reduce((a,b) => a+b, 0),
    total_threats:     (cats || []).reduce((a, r) => a + (r.total || 0), 0),
  });
}

async function actionServers(sb, params, res) {
  const page    = clampInt(params.get('page'), 1, 1, 10000);
  const perPage = clampInt(params.get('per_page'), 50, 1, 100);
  const source  = params.get('source');
  const risk    = params.get('risk_level');
  const offset  = (page - 1) * perPage;

  let query = sb.from('mcp_servers')
    .select('id,name,source,url,description,stars,language,owner,risk_score,risk_level,threat_count,scan_date,files_scanned')
    .order('risk_score', { ascending: false })
    .range(offset, offset + perPage - 1);

  if (source) query = query.eq('source', source);
  if (risk)   query = query.eq('risk_level', risk);

  const { data } = await query;
  res.status(200).json({ page, per_page: perPage, servers: data || [] });
}

async function actionThreats(sb, params, res) {
  const limit  = clampInt(params.get('limit'), 50, 1, 200);
  const source = params.get('source');
  let query = sb.from('mcp_threats_view').select('server_name,source,url,risk_level,risk_score,category,severity,title,description,file_path,line_number,scan_date').limit(limit);
  if (source) query = query.eq('source', source);
  const { data } = await query;
  res.status(200).json({ threats: data || [] });
}

async function actionHistory(sb, res) {
  const { data } = await sb.from('mcp_scan_runs').select('id,started_at,completed_at,total_scanned,total_malicious,by_source,by_risk_level,by_category').order('started_at', { ascending: false }).limit(30);
  res.status(200).json({ history: [...(data || [])].reverse() });
}

async function actionTrigger(body, res) {
  if (!API_SECRET) return res.status(403).json({ error: 'Trigger endpoint is disabled' });
  let payload = {};
  try { payload = typeof body === 'string' ? JSON.parse(body) : body; } catch { return res.status(400).json({ error: 'Invalid JSON' }); }
  if (payload.secret !== API_SECRET) return res.status(401).json({ error: 'Unauthorized' });
  res.status(200).json({ status: 'Use GitHub Actions to trigger a scan', note: 'Go to Actions tab → Daily MCP Security Scan → Run workflow' });
}

module.exports = async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') {
    if (rejectDisallowedOrigin(req, res)) return;
    return res.status(204).end();
  }
  if (rejectDisallowedOrigin(req, res)) return;

  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: 'Supabase not configured' });

  const url    = new URL(req.url, `https://${req.headers.host}`);
  const params = url.searchParams;
  const action = params.get('action') || 'stats';
  const sb     = getSupabase();

  try {
    if (req.method === 'GET') {
      if (action === 'stats')   return await actionStats(sb, res);
      if (action === 'servers') return await actionServers(sb, params, res);
      if (action === 'threats') return await actionThreats(sb, params, res);
      if (action === 'history') return await actionHistory(sb, res);
      return res.status(400).json({ error: `Unknown action: ${action}` });
    }
    if (req.method === 'POST' && action === 'trigger') return await actionTrigger(req.body, res);
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    console.error('[mcp-scan]', err);
    return res.status(500).json({ error: 'Server error' });
  }
};
