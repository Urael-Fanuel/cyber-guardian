// api/site-stats.js — Cyber-Guardian Site Scan Statistics
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Content-Type', 'application/json');
}

module.exports = async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!SUPABASE_URL || !SUPABASE_KEY) return res.status(500).json({ error: 'Not configured' });

  try {
    const sb = createClient(SUPABASE_URL, SUPABASE_KEY);
    const { data: scans } = await sb.from('site_scans').select('*').order('scanned_at', { ascending: false });

    if (!scans || scans.length === 0) {
      return res.status(200).json({
        total: 0, safe: 0, moderate: 0, critical: 0,
        detection_rate: 0, avg_threat_score: 0,
        by_scope: { mcp: 0, skill: 0, extension: 0 },
        recent: [], trend: []
      });
    }

    const total     = scans.length;
    const safe      = scans.filter(s => s.status === 'STATUS_SAFE').length;
    const moderate  = scans.filter(s => s.status === 'STATUS_MODERATE').length;
    const critical  = scans.filter(s => s.status === 'STATUS_CRITICAL').length;
    const detection_rate = total > 0 ? Math.round(((moderate + critical) / total) * 100) : 0;
    const avg_threat_score = total > 0 ? Math.round(scans.reduce((a, s) => a + (s.threat_score || 0), 0) / total) : 0;

    const by_scope = { mcp: 0, skill: 0, extension: 0 };
    for (const s of scans) {
      if (by_scope[s.scope] !== undefined) by_scope[s.scope]++;
    }

    // Last 10 scans for recent feed
    const recent = scans.slice(0, 10).map(s => ({
      scope:            s.scope,
      status:           s.status,
      threat_score:     s.threat_score,
      threat_count:     s.threat_count,
      threats_summary:  s.threats_summary || '',
      scanned_at:       s.scanned_at
    }));

    // Daily trend — last 7 days
    const trend = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dateStr = d.toISOString().split('T')[0];
      const dayScans = scans.filter(s => s.scanned_at && s.scanned_at.startsWith(dateStr));
      trend.push({
        date:     dateStr,
        total:    dayScans.length,
        threats:  dayScans.filter(s => s.status !== 'STATUS_SAFE').length
      });
    }

    return res.status(200).json({
      total, safe, moderate, critical,
      detection_rate, avg_threat_score,
      by_scope, recent, trend,
      last_scan: scans[0]?.scanned_at || null
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
