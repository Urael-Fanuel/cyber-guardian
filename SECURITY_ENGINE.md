# Cyber-Guardian Security Engine

Cyber-Guardian uses a hybrid detection model:

1. A canonical 60-family threat registry.
2. Deterministic static rules for every family.
3. AI analysis for semantic review, explanation, and ambiguous cases.
4. Optional dynamic sandbox evidence from an external isolated runner/provider.
5. A merged verdict that never lets AI downgrade a high-confidence deterministic finding.

## Canonical Registry

The source of truth lives in `api/scan.js`:

- `THREAT_FAMILIES`: exactly 60 canonical family names.
- `THREAT_FAMILY_DEFINITIONS`: one definition per family.
- `ALL_STATIC_RULES`: deterministic rule coverage for every family.

The automated tests enforce:

- exactly 60 families;
- no duplicate family names;
- every family has a definition;
- every family has at least one static rule;
- every static rule maps to a canonical family.

## Response Metadata

Every normalized scan response includes:

- `threat_families_checked`: the full 60-family list.
- `threat_family_definitions`: definitions for the 60 families.
- `coverage.total_families`: currently `60`.
- `coverage.static_families`: currently `60`.
- `coverage.ai_families`: currently `60`.
- `coverage.static_covered_families`: list of families with static rules.
- `dynamic_sandbox`: optional evidence returned by an isolated sandbox runner.
- `analysis_orchestrator`: the final evidence-routing layer that groups findings by
  specialist domain and records quality gates.
- `evidence_report`: plain-language and technical evidence for the most important
  findings.
- `remediation_plan`: prioritized fix categories that help a developer understand
  what to change before rescanning.

## Orchestrator and Specialist Evidence

The first production phase now uses a lightweight orchestrator. It does not run
extra model calls for every scan; instead, it routes the merged static, semantic,
and optional runtime findings into specialist buckets:

- code execution;
- network and exfiltration;
- prompt and tool-instruction security;
- secrets and identity;
- filesystem and local data;
- supply chain;
- resource safety;
- runtime behavior.

The final verdict belongs to the orchestrator, not to a single detector. This keeps
the product honest: deterministic findings cannot be downgraded, historical clean
alternatives must be rescanned before recommendation, and runtime claims require
real isolated-runner evidence before being shown as active runtime protection.

## Rule Requirements

Every deterministic rule defines:

- `family`: canonical threat family name.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `score`: minimum threat score if the rule matches.
- `pattern`: the detection pattern.
- `description`: plain-English explanation for the report.

## Product Rule

The AI may add findings, improve explanation, or classify ambiguous behavior. It must not
remove or downgrade deterministic findings.

Dynamic sandbox evidence may raise a verdict when runtime behavior is suspicious or
malicious. Untrusted code is not executed inside the Vercel API; dynamic execution belongs
in a separate hardened runner/provider with strict time, network, and filesystem limits.

## Advanced Evasion Coverage

The engine explicitly checks for advanced bypass patterns:

- Living-off-the-land file staging: normal OS or developer tools such as `cp`,
  `rsync`, `robocopy`, `xcopy`, `shutil`, or `fs.copyFile` moving sensitive files
  toward temporary, public, upload, cache, or shared locations.
- Non-adjacent data flow: sensitive sources such as env vars, tokens, cookies,
  SSH keys, cloud credentials, or local files reaching network, DNS, shell,
  archive, logging, clipboard, or external upload sinks.
- Input-dependent activation: risky behavior hidden behind rare user requests
  such as crypto wallet, private key, production, payroll, invoice, backup, or
  token-related inputs.
- Dynamic library/native payload loading: `ctypes.CDLL`, `dlopen`,
  `LoadLibrary`, `ffi`, `.node` modules, WebAssembly, dynamic plugins, or
  downloaded native payloads.

The semantic layer is instructed to perform data-flow analysis and to challenge
the functional justification for file, network, process, shell, package-install,
and dynamic-library behavior. The sandbox fuzzing profile also asks a future
isolated runner to generate edge-case inputs, monitor file integrity events,
record dynamic library loads, and detect sensitive-file staging.

## Quality Notes

The current deterministic rules are production seed rules. Some are high-confidence
malware/security signatures, while some are broader indicators that should be refined with
benign and malicious fixtures. The next maturity step is to add fixture tests per family
and tune false positives.
