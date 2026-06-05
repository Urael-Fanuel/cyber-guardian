# Message to Send Testers

Cyber-Guardian is opening a private Remote MCP test.

Remote MCP endpoint:

```text
https://mcp.cyberguardianscan.com/mcp
```

What it does:

- Scans MCP servers, AI Skills, IDE extensions, GitHub Actions, packages, and dependencies.
- Returns a clear install decision: safe, fix/review, or do not install.
- Explains findings in plain language with technical evidence.
- Does not execute submitted code.

Private beta note:

If we enabled beta protection, use this header:

```text
Authorization: Bearer <private-beta-token>
```

Test request:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

Main test tool:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "scan_code",
    "arguments": {
      "scope": "skill",
      "output_language": "en",
      "code": "console.log('hello from a test skill');"
    }
  }
}
```

Please report:

- Did the MCP client connect?
- Did `tools/list` show tools?
- Did `scan_code` return a clear result?
- Which client did you use?
- Any error message shown by the client.

