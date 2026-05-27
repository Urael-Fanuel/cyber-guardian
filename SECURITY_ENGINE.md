# Cyber-Guardian Security Engine

Cyber-Guardian uses a hybrid detection model:

1. A canonical 60-family threat registry.
2. Deterministic static rules for every family.
3. AI analysis for semantic review, explanation, and ambiguous cases.
4. A merged verdict that never lets AI downgrade a high-confidence deterministic finding.

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

## Quality Notes

The current deterministic rules are production seed rules. Some are high-confidence
malware/security signatures, while some are broader indicators that should be refined with
benign and malicious fixtures. The next maturity step is to add fixture tests per family
and tune false positives.
