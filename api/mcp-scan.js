// api/mcp-scan.js — Cyber-Guardian Dashboard API (Vercel Node.js)
// Routes: ?action=stats | servers | threats | history | trigger

const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const API_SECRET   = process.env.SCANNER_API_SECRET || '';

function getSupabase() {
  return createClient(SUPABASE_URL, SUPABASE_KEY);
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json');
}

async function actionStats(sb, res) {
  const { data: runs }    = await sb.table('mcp_scan_runs').select('*').order('started_at', { ascending: false }).limit(1);
  const { data: servers } = await sb.table('mcp_servers').select('risk_level, source');
  const { data: cats }    = await sb.table('mcp_threat_category_counts').select('*');
  const { data: trend }   = await sb.table('mcp_scan_runs').select('started_at,total_scanned,total_malicious').order('started_at', { ascending: false }).limit(7);

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
  const page    = parseInt(params.get('page') || '1', 10);
  const perPage = Math.min(parseInt(params.get('per_page') || '50', 10), 100);
  const source  = params.get('source');
  const risk    = params.get('risk_level');
  const offset  = (page - 1) * perPage;

  let query = sb.table('mcp_servers')
    .select('id,name,source,url,description,stars,language,owner,risk_score,risk_level,threat_count,scan_date,files_scanned')
    .order('risk_score', { ascending: false })
    .range(offset, offset + perPage - 1);

  if (source) query = query.eq('source', source);
  if (risk)   query = query.eq('risk_level', risk);

  const { data } = await query;
  res.status(200).json({ page, per_page: perPage, servers: data || [] });
}

async function actionThreats(sb, params, res) {
  const limit  = Math.min(parseInt(params.get('limit') || '50', 10), 200);
  const source = params.get('source');
  let query = sb.table('mcp_threats_view').select('*').limit(limit);
  if (source) query = query.eq('source', source);
  const { data } = await query;
  res.status(200).json({ threats: data || [] });
}

async function actionHistory(sb, res) {
  const { data } = await sb.table('mcp_scan_runs').select('*').order('started_at', { ascending: false }).limit(30);
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
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(204).end();

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
    return res.status(500).json({ error: `Server error: ${err.message}` });
  }
};
