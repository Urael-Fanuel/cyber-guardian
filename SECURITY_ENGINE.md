# Cyber-Guardian Security Engine

Cyber-Guardian uses a hybrid detection model:

1. A canonical 60-family threat registry.
2. Deterministic static rules for every family.
3. Semantic review for intent, explanation, and ambiguous cases.
4. Optional behavior evidence when deeper review is available.
5. A merged verdict that never lets semantic review downgrade a high-confidence deterministic finding.

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
- `coverage.semantic_families`: currently `60`.
- `coverage.static_covered_families`: list of families with static rules.
- `behavior_review`: optional public evidence returned by deeper behavior review.
- `security_report`: public decision metadata for the scan.
- `evidence_report`: plain-language and technical evidence for the most important
  findings.
- `remediation_plan`: prioritized fix categories that help a developer understand
  what to change before rescanning.

## Evidence and Decisions

The production response is intentionally public-safe. It summarizes what was found,
why it matters, and what to fix without exposing internal routing, internal scoring
gates, or future implementation details.

The final verdict is based on merged evidence, not a single detector. Deterministic
findings cannot be downgraded, historical clean alternatives must be rescanned before
recommendation, and deeper behavior claims are shown only when verified evidence is
available.

## Rule Requirements

Every deterministic rule defines:

- `family`: canonical threat family name.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
- `score`: minimum threat score if the rule matches.
- `pattern`: the detection pattern.
- `description`: plain-English explanation for the report.

## Product Rule

Semantic review may add findings, improve explanation, or classify ambiguous behavior. It must not
remove or downgrade deterministic findings.

Behavior evidence may raise a verdict when runtime behavior is suspicious or
malicious. Untrusted code is not executed inside the Vercel API.

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
and dynamic-library behavior.

## Quality Notes

The current deterministic rules are production seed rules. Some are high-confidence
malware/security signatures, while some are broader indicators that should be refined with
benign and malicious fixtures. The next maturity step is to add fixture tests per family
and tune false positives.
