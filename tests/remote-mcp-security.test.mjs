import assert from "node:assert/strict";
import worker from "../remote-mcp/worker.js";

function rpcRequest(token = "", body = null) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return new Request("https://mcp.cyberguardianscan.com/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(body || {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    }),
  });
}

async function testMissingSecretFailsClosed() {
  const response = await worker.fetch(rpcRequest(), {});
  assert.equal(response.status, 401);
}

async function testWrongSecretIsRejected() {
  const response = await worker.fetch(rpcRequest("wrong-token"), {
    CG_REMOTE_MCP_SHARED_TOKEN: "correct-token",
  });
  assert.equal(response.status, 401);
}

async function testCorrectSecretIsAccepted() {
  const response = await worker.fetch(rpcRequest("correct-token"), {
    CG_REMOTE_MCP_SHARED_TOKEN: "correct-token",
  });
  assert.equal(response.status, 200);
  const payload = await response.json();
  assert.equal(payload.result.serverInfo.name, "cyber-guardian-remote-mcp");
}

async function testAlternativeIsRescannedAndRequiresVerifiedScore() {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options = {}) => {
    calls.push({ url: String(url), options });
    const parsed = new URL(String(url));
    const mode = parsed.searchParams.get("mode");
    if (mode === "alternatives") {
      return Response.json({
        alternatives: [{ source_name: "history/candidate", source_url: "https://github.com/history/candidate" }],
      });
    }
    if (mode === "web_alternatives") {
      return Response.json({
        candidates: [{ source_name: "live/verified", source_url: "https://github.com/live/verified" }],
      });
    }
    if (parsed.pathname === "/api/scan") {
      const body = JSON.parse(options.body);
      if (body.code.includes("history/candidate")) {
        return Response.json({ status: "STATUS_SAFE", threat_score: 8, security_score: 92 });
      }
      return Response.json({
        status: "STATUS_SAFE",
        threat_score: 0,
        security_score: 98,
        verified_by_cyber_guardian: true,
      });
    }
    throw new Error(`Unexpected request: ${url}`);
  };

  try {
    const response = await worker.fetch(rpcRequest("correct-token", {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: "find_safer_alternative",
        arguments: {
          scope: "mcp",
          purpose: "secure repository file search",
          source_url: "https://github.com/risky/original",
          user_confirmed: true,
        },
      },
    }), {
      CG_REMOTE_MCP_SHARED_TOKEN: "correct-token",
      CG_API_BASE_URL: "https://cyberguardianscan.com",
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.result.structuredContent.status, "verified_current_alternative");
    assert.equal(payload.result.structuredContent.alternative.source_name, "live/verified");
    assert.equal(payload.result.structuredContent.verification.security_score, 98);
    assert.equal(payload.result.structuredContent.attempts[0].security_score, 92);
    assert.equal(calls.filter(call => new URL(call.url).pathname === "/api/scan").length, 2);
    assert.deepEqual(calls.map(call => {
      const url = new URL(call.url);
      return url.pathname === "/api/scan" ? "scan" : url.searchParams.get("mode");
    }), ["alternatives", "scan", "web_alternatives", "scan"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

async function testAlternativeRequiresUserConsentWithoutCallingApis() {
  const originalFetch = globalThis.fetch;
  let apiCalls = 0;
  globalThis.fetch = async () => {
    apiCalls++;
    throw new Error("No API call should happen before consent.");
  };
  try {
    const response = await worker.fetch(rpcRequest("correct-token", {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "find_safer_alternative",
        arguments: { scope: "mcp", purpose: "repository search" },
      },
    }), {
      CG_REMOTE_MCP_SHARED_TOKEN: "correct-token",
      CG_API_BASE_URL: "https://cyberguardianscan.com",
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.equal(payload.result.structuredContent.status, "consent_required");
    assert.equal(payload.result.structuredContent.max_scan_credits, 3);
    assert.equal(apiCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

await testMissingSecretFailsClosed();
await testWrongSecretIsRejected();
await testCorrectSecretIsAccepted();
await testAlternativeRequiresUserConsentWithoutCallingApis();
await testAlternativeIsRescannedAndRequiresVerifiedScore();

console.log("remote-mcp security tests: ok");
