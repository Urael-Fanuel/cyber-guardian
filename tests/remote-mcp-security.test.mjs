import assert from "node:assert/strict";
import worker from "../remote-mcp/worker.js";

function rpcRequest(token = "") {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  return new Request("https://mcp.cyberguardianscan.com/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({
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

await testMissingSecretFailsClosed();
await testWrongSecretIsRejected();
await testCorrectSecretIsAccepted();

console.log("remote-mcp security tests: ok");
