const SERVER_NAME = "cyber-guardian-remote-mcp";
const SERVER_VERSION = "0.1.0";
const PROTOCOL_VERSION = "2025-06-18";
const DEFAULT_API_BASE_URL = "https://cyberguardianscan.com";

const SCOPES = ["mcp", "skill", "extension", "github_action", "package", "dependency"];
const LANGUAGES = ["en", "he", "de", "ja", "ko", "fr", "pt"];

const TOOLS = [
  {
    name: "scan_code",
    title: "Scan code with Cyber-Guardian",
    description: "Scan pasted MCP, AI Skill, IDE extension, GitHub Action, package, or dependency code and return an install decision with evidence.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["code"],
      properties: {
        code: { type: "string", minLength: 5, description: "Code, manifest, workflow, prompt, package metadata, or dependency file content." },
        scope: { type: "string", enum: SCOPES, default: "mcp" },
        source_url: { type: "string", description: "Optional original source URL." },
        source_name: { type: "string", description: "Optional package, repo, skill, extension, or MCP server name." },
        source_owner: { type: "string", description: "Optional creator or organization." },
        output_language: { type: "string", enum: LANGUAGES, default: "en" },
      },
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "find_safer_alternative",
    title: "Find a safer alternative",
    description: "Find a lower-risk similar component from Cyber-Guardian scan history. The result must be verified again before production use.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["scope"],
      properties: {
        scope: { type: "string", enum: SCOPES, default: "mcp" },
        purpose: { type: "string" },
        threats: { type: "string" },
        source_url: { type: "string" },
        component_type: { type: "string" },
        capabilities: { type: "array", items: { type: "string" }, maxItems: 12 },
        tags: { type: "array", items: { type: "string" }, maxItems: 12 },
        output_language: { type: "string", enum: LANGUAGES, default: "en" },
      },
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "get_security_stats",
    title: "Get Cyber-Guardian security stats",
    description: "Return public Cyber-Guardian scan counts by decision and component type.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: { output_language: { type: "string", enum: LANGUAGES, default: "en" } },
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
  {
    name: "service_info",
    title: "Cyber-Guardian Remote MCP service info",
    description: "Return supported tools, scopes, and integration notes.",
    inputSchema: { type: "object", additionalProperties: false, properties: {} },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id",
    "Access-Control-Expose-Headers": "MCP-Protocol-Version, Mcp-Session-Id",
    "MCP-Protocol-Version": PROTOCOL_VERSION,
  };
}

function jsonResponse(payload, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: {
      ...corsHeaders(),
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id, code, message, data) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  return { jsonrpc: "2.0", id, error };
}

function normalizeScope(scope) {
  const value = String(scope || "mcp").trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (value === "github" || value === "github_actions" || value === "workflow") return "github_action";
  if (value === "npm" || value === "pypi" || value === "package_json" || value === "setup_py") return "package";
  if (value === "dependencies" || value === "dependency_manifest" || value === "requirements" || value === "lockfile") return "dependency";
  return SCOPES.includes(value) ? value : "mcp";
}

function cleanText(value, max = 500) {
  return String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
}

function cleanList(value) {
  return Array.isArray(value) ? value.map(item => cleanText(item, 80)).filter(Boolean).slice(0, 12) : [];
}

function apiBase(env) {
  return String(env.CG_API_BASE_URL || DEFAULT_API_BASE_URL).replace(/\/+$/, "");
}

function sharedAuthToken(env) {
  return String(env.CG_REMOTE_MCP_SHARED_TOKEN || "").trim();
}

function isAuthorized(request, env) {
  const required = sharedAuthToken(env);
  if (!required) return false;
  const auth = request.headers.get("Authorization") || "";
  return auth === `Bearer ${required}`;
}

async function callCyberGuardian(url, options = {}) {
  const response = await fetch(url, {
    method: options.method || "GET",
    headers: options.headers || {},
    body: options.body,
  });
  const text = await response.text();
  let data = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`Cyber-Guardian returned non-JSON response (${response.status}).`);
    }
  }
  if (!response.ok) {
    throw new Error(data.error || data.message || `Cyber-Guardian request failed with HTTP ${response.status}.`);
  }
  return data;
}

function accountHeaders(request, env) {
  const headers = {
    "Content-Type": "application/json",
    "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}`,
    "X-CG-Client": "remote-mcp",
  };

  const accountToken = request.headers.get("X-CG-Account-Token") || request.headers.get("X-CyberGuardian-Account-Token") || "";
  if (accountToken) headers["X-CG-Account-Token"] = accountToken;
  if (env.CG_REMOTE_MCP_API_TOKEN) headers["X-CG-Account-Token"] = env.CG_REMOTE_MCP_API_TOKEN;
  return headers;
}

function decisionFromScan(scan) {
  const decision = String(scan?.decision_details?.decision || scan?.decision || "").toLowerCase();
  const status = String(scan?.status || "").toUpperCase();
  if (decision === "do_not_install" || decision === "blocked" || status === "STATUS_CRITICAL") return "do_not_install";
  if (decision === "install_ok" || decision === "safe" || status === "STATUS_SAFE") return "safe_to_install";
  return "fix_or_review_before_use";
}

function findingRows(scan) {
  const evidence = Array.isArray(scan?.evidence_report) ? scan.evidence_report : [];
  const threats = Array.isArray(scan?.threats) ? scan.threats : [];
  return (evidence.length ? evidence : threats).slice(0, 10).map(item => ({
    family: cleanText(item.family || item.threat_family || "UNCLASSIFIED", 80).toUpperCase(),
    severity: cleanText(item.severity || "MEDIUM", 24).toUpperCase(),
    confidence: Number(item.confidence || 0),
    evidence: cleanText(item.evidence || item.line_hint || "", 260),
    explanation: cleanText(item.plain_explanation || item.description || item.explanation || "", 500),
    impact: cleanText(item.user_impact || item.plain_language || "", 500),
    fix: cleanText(item.fix_guidance || item.fix || item.recommendation || "", 500),
  }));
}

function scanText(scan, args) {
  const decision = decisionFromScan(scan);
  const findings = findingRows(scan);
  const lines = [
    "Cyber-Guardian scan result",
    "===========================",
    `Decision: ${decision}`,
    `Threat score: ${Number(scan?.threat_score || 0)}/100`,
    `Scan type: ${normalizeScope(args.scope).toUpperCase()}`,
    "",
    cleanText(scan?.decision_details?.plain_explanation || scan?.summary || "Cyber-Guardian returned a security decision.", 900),
    "",
    "Evidence:",
  ];
  if (!findings.length) {
    lines.push("- No concrete threat evidence was returned.");
  } else {
    for (const finding of findings) {
      lines.push(`- ${finding.family} (${finding.severity})`);
      if (finding.evidence) lines.push(`  Evidence: ${finding.evidence}`);
      if (finding.explanation) lines.push(`  Meaning: ${finding.explanation}`);
      if (finding.impact) lines.push(`  Impact: ${finding.impact}`);
      if (finding.fix) lines.push(`  Fix: ${finding.fix}`);
    }
  }
  const next = cleanText(scan?.decision_details?.next_step || scan?.recommendation || "", 900);
  if (next) lines.push("", `Recommended next step: ${next}`);
  return lines.join("\n");
}

async function scanCode(request, env, args) {
  const code = String(args.code || "");
  if (code.trim().length < 5) throw new Error("Provide at least 5 characters of code or configuration to scan.");
  if (code.length > 50000) throw new Error("Input is too large for the remote MCP beta. Please keep scans under 50,000 characters.");

  const payload = {
    code,
    scope: normalizeScope(args.scope),
    source_url: cleanText(args.source_url, 500),
    source_name: cleanText(args.source_name, 180),
    source_owner: cleanText(args.source_owner, 120),
  };

  const scan = await callCyberGuardian(`${apiBase(env)}/api/scan`, {
    method: "POST",
    headers: accountHeaders(request, env),
    body: JSON.stringify(payload),
  });

  const structured = {
    decision: decisionFromScan(scan),
    status: scan.status || "",
    threat_score: Number(scan.threat_score || 0),
    scope: payload.scope,
    summary: cleanText(scan?.decision_details?.plain_explanation || scan.summary || "", 900),
    recommendation: cleanText(scan?.decision_details?.next_step || scan.recommendation || "", 900),
    findings: findingRows(scan),
    code_profile: scan.code_profile || {},
  };

  return {
    content: [
      { type: "text", text: scanText(scan, payload) },
      { type: "text", text: JSON.stringify(structured, null, 2) },
    ],
    structuredContent: structured,
  };
}

function statsUrl(env, mode, params = {}) {
  const url = new URL(`${apiBase(env)}/api/site-stats`);
  if (mode) url.searchParams.set("mode", mode);
  for (const [key, value] of Object.entries(params)) {
    if (Array.isArray(value)) {
      if (value.length) url.searchParams.set(key, value.join(","));
    } else if (value !== undefined && value !== null && String(value).trim()) {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

async function getSecurityStats(env) {
  const stats = await callCyberGuardian(`${apiBase(env)}/api/site-stats`, {
    headers: { "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}` },
  });
  const structured = {
    total: Number(stats.total || 0),
    safe: Number(stats.safe || 0),
    review: Number(stats.review || 0),
    blocked: Number(stats.blocked || 0),
    by_scope: stats.by_scope || {},
    last_scan: stats.last_scan || null,
  };
  return {
    content: [
      { type: "text", text: `Cyber-Guardian stats\n====================\nTotal: ${structured.total}\nClean: ${structured.safe}\nReview: ${structured.review}\nDo not install: ${structured.blocked}` },
      { type: "text", text: JSON.stringify(structured, null, 2) },
    ],
    structuredContent: structured,
  };
}

async function findSaferAlternative(env, args) {
  const data = await callCyberGuardian(statsUrl(env, "alternatives", {
    scope: normalizeScope(args.scope),
    threats: cleanText(args.threats, 500),
    source_url: cleanText(args.source_url, 1000),
    purpose: cleanText(args.purpose, 500),
    component_type: cleanText(args.component_type, 120),
    capabilities: cleanList(args.capabilities),
    tags: cleanList(args.tags),
  }), {
    headers: { "User-Agent": `${SERVER_NAME}/${SERVER_VERSION}` },
  });

  const alternative = Array.isArray(data.alternatives) ? data.alternatives[0] : null;
  if (!alternative) {
    return {
      content: [{ type: "text", text: "No reliable safer alternative is available yet." }],
      structuredContent: { status: "no_alternative", alternative: null },
    };
  }
  const structured = {
    status: "historical_candidate_requires_fresh_verification",
    alternative,
  };
  return {
    content: [
      { type: "text", text: `Potential safer alternative found\n================================\nSource: ${alternative.source_name || alternative.source_url || "unknown"}\nDecision: ${alternative.decision || "candidate"}\n\nImportant: verify the current source before trusting it.` },
      { type: "text", text: JSON.stringify(structured, null, 2) },
    ],
    structuredContent: structured,
  };
}

function serviceInfo(env) {
  return {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    protocol_version: PROTOCOL_VERSION,
    api_base_url: apiBase(env),
    supported_scopes: SCOPES,
    supported_languages: LANGUAGES,
    tools: TOOLS.map(tool => tool.name),
    notes: [
      "This remote MCP does not execute submitted code.",
      "It routes scans to Cyber-Guardian's existing scan API.",
      "If CG_REMOTE_MCP_SHARED_TOKEN is configured, clients must send Authorization: Bearer <token>.",
      "Production customer auth should move to OAuth or account API tokens mapped to Supabase plans.",
    ],
  };
}

async function handleRpc(request, env, message) {
  const id = message?.id ?? null;
  const method = String(message?.method || "");
  const params = message?.params || {};

  if (method === "initialize") {
    return rpcResult(id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: { tools: {}, resources: {} },
      serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      instructions: "Use Cyber-Guardian before recommending MCP servers, AI Skills, IDE extensions, GitHub Actions, packages, or dependency manifests.",
    });
  }

  if (method === "notifications/initialized") return null;
  if (method === "ping") return rpcResult(id, {});
  if (method === "tools/list") return rpcResult(id, { tools: TOOLS });

  if (method === "tools/call") {
    const name = params.name;
    const args = params.arguments || {};
    if (name === "scan_code") return rpcResult(id, await scanCode(request, env, args));
    if (name === "find_safer_alternative") return rpcResult(id, await findSaferAlternative(env, args));
    if (name === "get_security_stats") return rpcResult(id, await getSecurityStats(env));
    if (name === "service_info") {
      const info = serviceInfo(env);
      return rpcResult(id, { content: [{ type: "text", text: JSON.stringify(info, null, 2) }], structuredContent: info });
    }
    return rpcError(id, -32601, `Unknown tool: ${name}`);
  }

  if (method === "resources/list") {
    return rpcResult(id, {
      resources: [{
        uri: "cyberguardian://service/info",
        name: "Cyber-Guardian Remote MCP service information",
        mimeType: "application/json",
      }],
    });
  }

  if (method === "resources/read") {
    const uri = String(params.uri || "");
    if (uri !== "cyberguardian://service/info") return rpcError(id, -32602, `Unknown resource: ${uri}`);
    return rpcResult(id, { contents: [{ uri, mimeType: "application/json", text: JSON.stringify(serviceInfo(env), null, 2) }] });
  }

  return rpcError(id, -32601, `Unsupported method: ${method}`);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders() });
    if (url.pathname === "/health") return jsonResponse({ ok: true, name: SERVER_NAME, version: SERVER_VERSION });
    if (url.pathname !== "/mcp") return jsonResponse({ error: "Not found" }, 404);
    if (request.method !== "POST") return jsonResponse({ error: "Use POST /mcp for JSON-RPC MCP requests." }, 405);
    if (!isAuthorized(request, env)) return jsonResponse(rpcError(null, -32001, "Unauthorized"), 401);

    let message;
    try {
      message = await request.json();
    } catch {
      return jsonResponse(rpcError(null, -32700, "Parse error"), 400);
    }

    try {
      if (Array.isArray(message)) {
        const results = [];
        for (const item of message) {
          const result = await handleRpc(request, env, item);
          if (result) results.push(result);
        }
        return jsonResponse(results);
      }
      const result = await handleRpc(request, env, message);
      if (!result) return new Response(null, { status: 202, headers: corsHeaders() });
      return jsonResponse(result);
    } catch (err) {
      return jsonResponse(rpcError(message?.id ?? null, -32000, err?.message || "Cyber-Guardian Remote MCP error"), 500);
    }
  },
};
