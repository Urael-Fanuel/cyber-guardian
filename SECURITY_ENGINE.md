# Cyber-Guardian Security Engine

Cyber-Guardian should use a hybrid detection model:

1. Deterministic static rules for high-confidence findings.
2. AI analysis for semantic review, explanation, and ambiguous cases.
3. A merged verdict that never lets the AI downgrade a high-confidence static finding.

## Current Static Rules

The canonical 60-family registry lives in `api/scan.js` as `THREAT_FAMILIES`.
The API prompt, output metadata, and tests use this registry as the source of truth.

The first high-confidence deterministic rules live in `api/scan.js` as `STATIC_RULES`:

- `REVERSE_SHELL`
- `API_KEY_THEFT`
- `DYNAMIC_EVAL`
- `OS_COMMAND_EXECUTION`
- `SUPPLY_CHAIN_ATTACK`
- `FILE_SYSTEM_ATTACK`
- `PROMPT_INJECTION`

These are intentionally high-signal patterns. They should produce fewer false positives
than broad keyword matching.

Every scan response includes:

- `threat_families_checked`: the full 60-family list.
- `coverage.total_families`: currently `60`.
- `coverage.static_families`: how many families have deterministic static rules.
- `coverage.ai_families`: how many families are covered by AI semantic analysis.

## Rule Requirements

Every deterministic rule should define:

- `family`: canonical threat family name.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `score`: minimum threat score if the rule matches.
- `pattern`: the detection pattern.
- `description`: plain-English explanation for the report.

## Product Rule

The AI may add findings, improve explanation, or classify ambiguous behavior. It must not
remove or downgrade deterministic findings.

## Next Deterministic Rule Families To Add

- `SSRF_ATTEMPT`
- `PATH_TRAVERSAL`
- `COOKIE_THEFT`
- `BROWSER_HIJACK`
- `KEYLOGGER_PATTERN`
- `SCREEN_CAPTURE`
- `CRYPTO_MINING`
- `RANSOMWARE_PATTERN`
- `TYPOSQUATTING`
- `DEPENDENCY_CONFUSION`
- `TOOL_POISONING`
- `TOOL_DESCRIPTION_MANIPULATION`
- `RESOURCE_HIJACKING`
- `CROSS_TOOL_CONFUSION`

## Longer-Term Shape

Move rules into a shared module or JSON/YAML registry once the rule set grows past
20-30 rules. Keep tests for every rule with malicious and benign fixtures.
