"""
api/mcp-scan.py  —  Vercel Serverless Function (Python runtime)
================================================================
Exposes the MCP scanner results to the Cyber-Guardian dashboard.

Routes (via query param ?action=...):
  GET  ?action=stats          → latest scan summary + charts data
  GET  ?action=servers        → all scanned servers (paginated)
  GET  ?action=threats        → high/critical servers only
  GET  ?action=history        → last N scan runs
  POST ?action=trigger        → manual scan trigger (protected by API_SECRET)
"""

from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import os
import subprocess
import sys

from supabase import create_client

SUPABASE_URL  = os.environ["SUPABASE_URL"]
SUPABASE_KEY  = os.environ["SUPABASE_SERVICE_KEY"]   # service role for API
API_SECRET    = os.environ.get("SCANNER_API_SECRET", "")


def get_supabase():
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def cors_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
    }


def json_response(data: dict, status: int = 200) -> dict:
    return {
        "statusCode": status,
        "headers": cors_headers(),
        "body": json.dumps(data, default=str),
    }


def error_response(msg: str, status: int = 400) -> dict:
    return json_response({"error": msg}, status)


# ──────────────────────────────────────────────
#  ACTION HANDLERS
# ──────────────────────────────────────────────

def action_stats(sb) -> dict:
    """Dashboard overview: counts, chart data, latest run info."""
    # Latest scan run
    run_res = sb.table("mcp_scan_runs").select("*").order(
        "started_at", desc=True
    ).limit(1).execute()
    latest_run = run_res.data[0] if run_res.data else {}

    # Risk level distribution (all time latest scan)
    risk_res = sb.table("mcp_servers").select(
        "risk_level"
    ).execute()
    risk_counts: dict[str, int] = {}
    for row in (risk_res.data or []):
        lvl = row["risk_level"]
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    # Source distribution
    src_res = sb.table("mcp_servers").select("source").execute()
    src_counts: dict[str, int] = {}
    for row in (src_res.data or []):
        s = row["source"]
        src_counts[s] = src_counts.get(s, 0) + 1

    # Top threat categories (from the view)
    cat_res = sb.table("mcp_threat_category_counts").select("*").execute()

    # Trend: last 7 scan runs
    trend_res = sb.table("mcp_scan_runs").select(
        "started_at,total_scanned,total_malicious"
    ).order("started_at", desc=True).limit(7).execute()

    return json_response({
        "latest_run":     latest_run,
        "risk_counts":    risk_counts,
        "source_counts":  src_counts,
        "threat_categories": cat_res.data or [],
        "scan_trend":     list(reversed(trend_res.data or [])),
        "total_servers":  sum(risk_counts.values()),
        "total_threats":  sum(
            row.get("total", 0) for row in (cat_res.data or [])
        ),
    })


def action_servers(sb, params: dict) -> dict:
    """Paginated list of all scanned servers."""
    page     = int(params.get("page", ["1"])[0])
    per_page = min(int(params.get("per_page", ["50"])[0]), 100)
    source   = params.get("source", [None])[0]
    risk     = params.get("risk_level", [None])[0]
    offset   = (page - 1) * per_page

    query = sb.table("mcp_servers").select(
        "id,name,source,url,description,stars,language,owner,"
        "risk_score,risk_level,threat_count,scan_date,files_scanned"
    ).order("risk_score", desc=True).range(offset, offset + per_page - 1)

    if source:
        query = query.eq("source", source)
    if risk:
        query = query.eq("risk_level", risk)

    res = query.execute()
    return json_response({
        "page":     page,
        "per_page": per_page,
        "servers":  res.data or [],
    })


def action_threats(sb, params: dict) -> dict:
    """High and critical risk servers with full threat details."""
    limit  = min(int(params.get("limit", ["50"])[0]), 200)
    source = params.get("source", [None])[0]

    query = sb.table("mcp_threats_view").select("*").limit(limit)
    if source:
        query = query.eq("source", source)

    res = query.execute()
    return json_response({"threats": res.data or []})


def action_history(sb) -> dict:
    """Last 30 scan run records for the trend chart."""
    res = sb.table("mcp_scan_runs").select("*").order(
        "started_at", desc=True
    ).limit(30).execute()
    return json_response({"history": list(reversed(res.data or []))})


def action_trigger(sb, body: str) -> dict:
    """
    Manually trigger a scan.
    POST body: {"secret": "<SCANNER_API_SECRET>"}
    Runs the scanner as a background subprocess (fire-and-forget).
    Note: Vercel functions time out at 60s — for production use a
    GitHub Actions manual dispatch instead (see the workflow file).
    """
    if not API_SECRET:
        return error_response("Trigger endpoint is disabled (no API_SECRET set)", 403)

    try:
        payload = json.loads(body or "{}")
    except json.JSONDecodeError:
        return error_response("Invalid JSON body", 400)

    if payload.get("secret") != API_SECRET:
        return error_response("Unauthorized", 401)

    # Fire-and-forget — Vercel will kill the function before it finishes,
    # but this is useful for local testing via the Vercel CLI.
    subprocess.Popen(
        [sys.executable, "mcp_scanner.py"],
        env=os.environ.copy(),
    )
    return json_response({"status": "scan triggered", "note": "runs in background"})


# ──────────────────────────────────────────────
#  VERCEL HANDLER
# ──────────────────────────────────────────────

def handler(request, context):
    """Vercel Python serverless function entry point."""
    method = request.get("method", "GET").upper()
    parsed = urlparse(request.get("url", ""))
    params = parse_qs(parsed.query)
    action = params.get("action", ["stats"])[0]

    # CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": cors_headers(), "body": ""}

    sb = get_supabase()

    try:
        if method == "GET":
            if action == "stats":
                return action_stats(sb)
            elif action == "servers":
                return action_servers(sb, params)
            elif action == "threats":
                return action_threats(sb, params)
            elif action == "history":
                return action_history(sb)
            else:
                return error_response(f"Unknown action: {action}")

        elif method == "POST":
            if action == "trigger":
                body = request.get("body", "")
                return action_trigger(sb, body)
            else:
                return error_response("Unknown POST action")

        else:
            return error_response("Method not allowed", 405)

    except Exception as e:
        return error_response(f"Server error: {str(e)}", 500)
