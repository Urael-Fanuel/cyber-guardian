\# Project Collaboration Instructions

===

# The project owner is not a programmer and should not be expected to infer

# technical steps independently.

# 

# When the owner needs to perform an action manually, always guide them one step

# at a time. For every step, explain:

# 

# \- exactly what to click, paste, run, or check

# \- why the step matters

# \- what result they should expect

# \- when they should stop and send a screenshot or the result back

# 

# Do not assume the owner understands programming concepts such as SQL,

# migrations, deployments, environment variables, APIs, Git, Vercel, or Supabase.

# If one of these terms is needed, explain it in simple language before asking

# them to act.

# 

# Prefer short, clear Hebrew instructions for manual steps. Avoid giving many

# steps at once unless the owner explicitly asks for a full checklist.

# 

# \## Future API Split

# 

# Vercel Hobby currently limits the project to 12 Serverless Functions per

# deployment. Because of that, some API endpoints were intentionally consolidated:

# 

# \- account public config and account status live together in `api/account.js`

# \- admin leads and customer account management live together in `api/admin-data.js`

# 

# This consolidation is a deployment-limit workaround, not the preferred long-term

# architecture. When the project moves to a plan/environment that allows more API

# functions, split these back into separate focused endpoints for clearer

# maintenance.

# 

# \## Future Model Routing

# 

# Remember this product direction for future implementation: Cyber-Guardian

# should eventually route each scan to the right analysis agent/model based on

# the code type, risk, and complexity.

# 

# Examples:

# 

# \- simple deterministic or low-risk scans can use cheaper/faster models

# \- complex MCP, skill, IDE extension, package, dependency, or GitHub Actions

# &#x20; scans can use stronger models

# \- very complex or high-risk scans should be routed to the strongest available

# &#x20; model, such as Anthropic Opus when appropriate, or a newer/better model when

# &#x20; one is released

# 

# The goal is not to lock the product to one model. The long-term architecture

# should support multiple scan modules and model providers, with clear routing

# logic, cost control, and auditability.

# 

# \## Future Paid Alternative Discovery

# 

# Remember this product direction: when a scan returns "do not install",

# "fix before use", or another warning, the product should eventually offer a

# paid "Find a safer alternative" workflow.

# 

# Long-term behavior:

# 

# \- search the existing Supabase scan history for similar lower-risk code first

# \- if no reliable match exists, use external discovery systems such as Apify,

# &#x20; repository search, package registries, and other vetted sources

# \- scan candidate alternatives before recommending them

# \- never recommend an alternative solely because it was clean in a historical

# &#x20; scan; historical scans are candidates only

# \- before showing an alternative as safe, fetch the current source and rescan it

# &#x20; because attackers may publish clean code first and later replace it with

# &#x20; malicious behavior

# \- show one strong recommended alternative, not a confusing list

# \- make it clear that alternatives still require review and rescanning

# \- support paid team/company/enterprise plans and monthly credits

# \- consider future partnerships with authors who publish clean, reviewed MCPs,

# &#x20; Skills, IDE extensions, packages, and workflows

# 

# This feature should be treated as a premium business value: companies do not

# only want warnings; they want a safe replacement path.

# 

# \## Strategic Moat Roadmap

# 

# Remember this strategic direction: Cyber-Guardian should become more than a

# scanner. It should become a defensible trust network for MCPs, AI Skills, IDE

# extensions, GitHub Actions, packages, and dependencies.

# 

# Prioritized moat pillars:

# 

# \- decentralized threat intelligence web: future MCP/IDE agents report

# &#x20; anonymized runtime anomalies such as unexpected `.env` access, network

# &#x20; callbacks, blocked permission attempts, and suspicious shell execution

# \- Trust Score \& Registry: scanned sources build dynamic reputation from scan

# &#x20; history, creator verification, recent behavior, and community reports

# \- autonomous sandbox fuzzing: when an isolated runner is connected, scan

# &#x20; payloads include honeytokens and attack objectives for active boundary tests

# \- Secure Wrapper workflow: when there is no clean alternative, queue a wrapper

# &#x20; request that can generate a controlled policy layer around the risky tool

# \- Runtime MCP Firewall: future local agent should enforce permissions during

# &#x20; live use, then report policy blocks back into threat intelligence

# 

# Do not overclaim these features publicly. Show them as active foundations,

# beta workflows, or future agent capabilities unless the local agent/runner is

# actually connected and verified.

# 

# \## Paid Launch Runtime Security Priority

# 

# Remember this as a high-priority product decision: as soon as Cyber-Guardian

# starts rolling out payment collection, paid plans, credits, or commercial

# packages, immediately prioritize implementation of:

# 

# \- a real isolated sandbox runner for dynamic execution and fuzzing

# \- Runtime MCP Firewall / local runtime agent enforcement

# \- file-system integrity monitoring during sandbox runs

# \- dynamic library/native payload load monitoring

# \- network/DNS/process/shell telemetry from the runner

# \- customer-facing evidence reports that explain what happened during runtime

# 

# This is not optional polish. It is part of making Cyber-Guardian credible for

# businesses, SaaS companies, security teams, and enterprise buyers. Keep public

claims honest until these components are actually connected and verified.

Cyber Guardian Scan – AGENTS.md Complete Edition

===

## 0\. Purpose of This File

This file is the single source of truth for Codex and any AI coding agent working on Cyber Guardian Scan.

Codex must read this file before making changes.

This file defines:

* Product vision
* Brand direction
* Scan result language
* Security status model
* Website direction
* Monetization strategy
* Database strategy
* Certification strategy
* Safe alternatives strategy
* Logo rules
* Design rules
* Implementation roadmap
* Codex operating rules

Do not ignore this file.

\---

# 1\. North Star Vision

Cyber Guardian Scan should become:

**The Trust Standard for AI Tools**

The long-term goal:

Developers, businesses, organizations, AI users and security teams should feel uncomfortable installing, connecting, running or trusting AI tools that have not been scanned by Cyber Guardian Scan.

Cyber Guardian Scan is not just a scanner.

Cyber Guardian Scan is a trust standard.

The ultimate question the market should ask:

**Has it been verified by Cyber Guardian Scan?**

\---

# 2\. Product Name

The official product name is:

**Cyber Guardian Scan**

Do not rename the product.

Do not replace the brand name with:

* Cyber Guardian Security Score
* Cyber Guardian Certified
* Cyber Guardian Verified
* Safe Alternatives Engine
* Public Reputation Database

These are features, trust assets, sub-products or modules.

They are not replacements for the main brand.

\---

# 3\. Core Mission

Cyber Guardian Scan exists to verify whether AI-related code and tools can be trusted before installation, execution or integration.

The product must help users answer:

**Can I trust this code before installing it?**

The product should protect users before the moment of risk:

* Before installation
* Before execution
* Before connecting to systems
* Before granting permissions
* Before giving access to data
* Before trusting an AI tool, MCP server, extension, package or workflow

\---

# 4\. Core Positioning

Cyber Guardian Scan should be positioned as:

**The Trust Standard for AI Tools**

Secondary slogans:

**Before You Install AI, Verify It.**

**Has your code been scanned by Cyber Guardian Scan?**

Hebrew slogan:

**האם הקוד שאתה הולך להתקין נסרק על ידי Cyber Guardian Scan?**

Cyber Guardian Scan is not an offensive hacking brand.

Cyber Guardian Scan is not a military cyber brand.

Cyber Guardian Scan is a professional verification, trust and security decision platform.

\---

# 5\. Core Product Mechanism

Cyber Guardian Scan already has MCP code that users can integrate into:

* OpenAI
* Claude
* VS Code
* Cursor

The goal is automatic security verification.

Whenever a user is about to install, connect, paste, run or integrate code, AI tools, MCP servers, extensions, packages or workflows, Cyber Guardian Scan should scan it first and return:

* Verified by Cyber Guardian Scan™
* Cyber Guardian Security Score™
* Risk Level
* Scan Status
* Install Recommendation
* Findings
* Reasons
* Code location of problems when possible
* Recommended fixes
* Scan metadata

The product should appear exactly at the moment of risk.

Users should not need to remember to scan manually.

\---

# 6\. Required Scan Result Format

Every scan result should use this structure:

```text
Verified by Cyber Guardian Scan™

Cyber Guardian Security Score: XX / 100

Status:
Safe for Install / Needs Review / Danger for Install / Rescan Required

Risk Level:
Low / Medium / High / Critical

Recommendation:
Short and clear recommendation.

Reasons:
Top 3 detected risks or reasons for approval.

Scan Metadata:
- Scan Date
- Version
- Commit Hash
- Code Fingerprint / Hash
- Source URL
```

Important:

Do not say that code is safe forever.

Only say that this exact version, commit or code fingerprint was scanned.

\---

# 7\. Official Scan Result Statuses

Cyber Guardian Scan must not classify every result only as Safe or Danger.

Some code may not be clearly malicious, but still requires human review or developer clarification.

Required statuses:

## 7.1 Safe for Install

Use when the scan found no meaningful security concerns.

Output:

```text
🟢 Safe for Install

The scanned version appears suitable for installation based on current findings.
```

## 7.2 Needs Review

Use when the code is not clearly dangerous, but contains suspicious, weak, incomplete, risky or unclear patterns.

Examples:

* Insecure configuration
* Excessive permissions
* Weak validation
* Unsafe input handling
* Unclear network calls
* Risky file access
* Hardcoded secrets pattern
* Missing authentication checks
* Poor permission boundaries
* Potential prompt injection exposure
* Unsafe dependency usage
* Code that may be unsafe due to poor implementation rather than malicious intent

Output:

```text
🟡 Needs Review

This code was not identified as malicious, but security concerns require further review before installation.
```

## 7.3 Danger for Install

Use when the code contains high-risk or clearly dangerous behavior.

Examples:

* Credential theft
* Hidden command execution
* Reverse shell
* Keylogger behavior
* Data exfiltration
* Malicious dependency
* Obfuscated payload
* Unauthorized access behavior

Output:

```text
🔴 Danger for Install

This code contains security risks that make installation unsafe.
```

## 7.4 Rescan Required

Use when the code changed since the last verified scan.

Output:

```text
⚪ Rescan Required

This code has changed since the last Cyber Guardian Scan verification and must be rescanned before installation.
```

\---

# 8\. Code Findings Requirements

When Cyber Guardian Scan identifies a problem, it should show the exact location whenever technically possible.

Each finding should include:

* Severity: Low / Medium / High / Critical
* Status: Safe / Needs Review / Danger
* File Path
* Line Number
* Code Snippet
* Problem Explanation
* Why It Matters
* Recommended Fix
* Whether the issue appears malicious or likely unintentional

Example:

```text
Severity: High

Status: Needs Review

File:
src/auth/token-handler.js

Line:
147

Issue:
User input reaches authentication logic without sufficient validation.

Why It Matters:
An attacker may manipulate input values and bypass intended security controls.

Recommended Fix:
Validate and sanitize all user-controlled values before authentication processing.

Assessment:
Likely developer oversight. No evidence of malicious intent.
```

Important rule:

Cyber Guardian Scan must distinguish between:

## Malicious Code

Code intentionally designed to steal data, execute unauthorized actions, gain access, hide activity or harm users.

## Unsafe Code

Code that is not necessarily malicious but contains security weaknesses, poor implementation, missing validation, excessive permissions or insecure architecture.

The product should help developers improve unsafe code and achieve a higher Cyber Guardian Security Score™, not only block installation.

\---

# 9\. Verification Freshness Rule

Cyber Guardian Scan verifies specific code versions, commits and fingerprints.

If the code changes, verification expires.

If a code fingerprint is different from the last scan, show:

```text
This code has changed since the last Cyber Guardian Scan.
Rescan required before install.
```

Verification statuses:

## Verified Current

The code is identical to the last scanned version.

## Changed Since Scan

The code changed and needs a new scan.

## Dangerous / Block Install

The scan found serious risks.

Do not claim that a tool is permanently safe.

Say:

**This exact version was scanned.**

\---

# 10\. Scan Metadata

Every scan result and database record should include:

* Tool Name
* Category
* Source URL
* Scan Date
* Version
* Commit Hash
* Code Fingerprint / Hash
* Cyber Guardian Security Score
* Status
* Risk Level
* Top Risks
* Install Recommendation
* Freshness Status

\---

# 11\. Core Trust Assets

The following phrases are strategic brand assets.

Use them consistently:

1. Verified by Cyber Guardian Scan™
2. Cyber Guardian Security Score™
3. Cyber Guardian Certification™
4. Cyber Guardian Certified™
5. Safe Alternatives Engine™
6. Public Reputation Database
7. Safe for Install
8. Needs Review
9. Danger for Install
10. Rescan Required

The phrase **Verified by Cyber Guardian Scan™** should appear repeatedly across the product.

It should appear in:

* Scan results
* Reports
* Badges
* Dashboard
* MCP output
* Extension output
* Public database
* Developer certification pages
* Marketing materials
* GitHub README badges
* Tool pages

Long-term goal:

Make **Verified by Cyber Guardian Scan™** a recognized trust mark for AI tools, code, MCP servers, extensions and packages.

\---

# 12\. Business Model Vision

Cyber Guardian Scan should support multiple revenue engines.

## 12.1 Revenue Engine 1 – User Scans

Users scan MCP servers, AI tools, packages, GitHub repositories, extensions and workflows before installation.

## 12.2 Revenue Engine 2 – Developer Certification

Developers pay to scan their own code, receive detailed findings, improve the code and reach a high Cyber Guardian Security Score.

Goal:

Help developers publish code that is worthy of:

**Verified by Cyber Guardian Scan™**

## 12.3 Revenue Engine 3 – Public Reputation Database

A public searchable database of scanned tools.

Users can search before installation and see:

* Score
* Status
* Last scan date
* Freshness
* Risk level
* Recommendation

## 12.4 Revenue Engine 4 – Safe Alternatives Engine

If a code/tool is dangerous, Cyber Guardian Scan should suggest safer verified alternatives that perform a similar function.

## 12.5 Revenue Engine 5 – Sponsored Verified Placement

Developers may pay to promote their verified tools.

Important:

Sponsored tools must be clearly marked as Sponsored.

Never allow payment to change the security score.

Trust is more important than revenue.

\---

# 13\. Public Reputation Database

The database should not claim that a tool is permanently safe.

It should show:

* Tool name
* Category
* Source URL
* Score
* Status
* Scan date
* Version
* Commit hash
* Code fingerprint
* Freshness status
* Top risks
* Install recommendation

The database should help users answer:

**Was this exact code already scanned?**

If yes:

Show score and result.

If no:

Recommend scan before install.

If changed:

Show **Rescan Required**.

Suggested routes:

* /verified-tools
* /reputation-database

Recommended filters:

* MCP Server
* AI Agent
* AI Skill
* VS Code Extension
* Cursor Tool
* GitHub Repo
* GitHub Action
* npm Package
* Dependency

\---

# 14\. Safe Alternatives Engine™

When a scanned tool is dangerous, the product should search for safer alternatives.

The alternatives should be based on:

* Similar purpose
* Same category
* Similar functionality
* Higher Cyber Guardian Security Score
* Current verification status

Output example:

```text
Danger for Install

Recommended Verified Alternatives:

1. Tool A
Verified by Cyber Guardian Scan™
Score: 97/100
Safe for Install

2. Tool B
Verified by Cyber Guardian Scan™
Score: 94/100
Safe for Install
```

Important:

Do not claim that alternatives are identical.

Say they are safer alternatives with similar functionality.

Future upgrade:

**One Click Safe Replacement™**

\---

# 15\. Developer Certification

Developers should be able to:

1. Upload or connect code
2. Run a deep scan
3. Receive security findings
4. See file paths and line numbers
5. Understand why issues matter
6. Fix problems
7. Rescan
8. Improve score
9. Earn a verification badge

Output:

```text
Verified by Cyber Guardian Scan™

Cyber Guardian Security Score: 96/100

Recommended for Install
```

Avoid:

* 100% safe
* Fully secure
* Approved forever
* Guaranteed safe

Use:

* Verified
* Recommended for Install
* High Security Score
* This version was scanned

\---

# 16\. Official Brand Logo

The official Cyber Guardian Scan logo consists of:

* Shield
* Verification Checkmark
* Digital Fragmentation Elements

The logo represents:

* Protection
* Verification
* Trust
* Digital Security
* Code Validation

Do not introduce:

* Eyes
* One-eye symbols
* Illuminati-style graphics
* Swords
* Weapons
* Hacker masks
* Aggressive military visuals

The shield and checkmark are the primary visual symbols of the brand.

The logo should be treated as a trust certification mark, not merely a company logo.

Do not create multiple unrelated logos for different product modules.

Use one unified brand logo across:

* Security Score
* Certification
* Public Database
* Reports
* Browser Extension
* MCP output
* Enterprise pages

Create badge variations, not separate logos.

\---

# 17\. Design Direction

The website must remain:

**Dark Premium SaaS Design**

Do not make the website light themed.

The feeling should be:

* Trust
* Verification
* Authority
* Enterprise
* Premium
* Clean
* Professional
* Developer-friendly

Not:

* Hacker
* Underground
* Cyberpunk
* Military
* Matrix-style
* Scary
* Aggressive
* Childish

Preferred palette:

* Deep Navy
* Teal
* Violet
* Soft gradients

Use:

* Large whitespace
* Clean typography
* Elegant cards
* Smooth transitions
* Clear visual hierarchy
* Premium dashboard elements

Avoid:

* Excessive neon
* Too many borders
* Visual clutter
* Generic cyber stock visuals
* Weapon imagery
* One-eye symbolism

Design inspiration:

* Stripe
* Linear
* Vercel

But keep the site dark and authoritative.

\---

# 18\. Homepage Recommended Structure

The homepage should be organized in this order:

1. Hero Section
2. Trust Indicators
3. What Cyber Guardian Scan Scans
4. Cyber Guardian Security Score
5. Verified by Cyber Guardian Scan Badge
6. How Detection Works
7. Live Scan Demo
8. Public Reputation Database Preview
9. Safe Alternatives Engine
10. Developer Certification
11. Enterprise / Teams
12. FAQ
13. Final CTA

\---

# 19\. Homepage Core Message

The homepage should make the user understand within 5 seconds:

1. What Cyber Guardian Scan does
2. Why it matters
3. Why the user should trust it
4. What action to take next

Hero headline option:

```text
Before You Install AI, Verify It.
```

Subheadline:

```text
Scan MCP servers, AI agents, IDE extensions, GitHub repositories, npm packages and automations before giving them access to your systems, data, credentials or workflows.
```

Main question:

```text
Has your code been scanned by Cyber Guardian Scan?
```

CTA:

```text
Scan Code Now
```

Secondary CTA:

```text
Search Verified Tools
```

Trust phrase:

```text
Verified by Cyber Guardian Scan™
```

\---

# 20\. Detection Engine

Show the security engine as layered protection.

Layers:

1. Static Analysis
2. AI Semantic Review
3. Behavior Analysis
4. Threat Intelligence
5. Policy / Risk Rules

Explain that findings may include:

* Credential theft
* Prompt injection
* Excessive permissions
* Hidden command execution
* Risky network behavior
* Unsafe file access
* Obfuscation
* Dangerous dependencies
* Poor validation
* Unsafe architecture

\---

# 21\. Enterprise Positioning

Cyber Guardian Scan should be ready for teams and organizations.

Enterprise features may include:

* Team Dashboard
* Shared Reports
* Audit Trail
* API Access
* CI/CD Integration
* Policy Enforcement
* Approved Tool Catalog
* Private Scans
* Role-Based Access
* Compliance Support

CTA:

```text
Contact Sales
```

\---

# 22\. Pricing / Monetization Structure

Suggested tiers:

## Free

* Limited scans
* Basic score
* Basic recommendation

## Pro

* More scans
* Detailed findings
* Reports
* Safe alternatives

## Developer Certification

* Code improvement guidance
* Certification badge
* Public verified listing

## Team / Enterprise

* API
* CI/CD
* Policy enforcement
* Team dashboard
* Private scans

Pricing values can be placeholders unless real prices exist.

\---

# 23\. Legal and Trust Language

Do not use:

* 100% safe
* Guaranteed safe
* Approved forever
* Fully secure
* Permanently verified

Use:

* Verified by Cyber Guardian Scan™
* Recommended for Install
* High Security Score
* This version was scanned
* Rescan required if code changes
* Based on current findings
* No critical issues detected in this version

Important:

Trust is the core asset.

Do not overpromise.

\---

# 24\. Implementation Rules for Codex

Work one task at a time.

Do not work on multiple tasks in one run.

Do not redesign unrelated sections.

Do not rename the product.

Do not remove existing functionality.

Do not change backend logic unless the current task explicitly requires it.

Before coding:

1. Inspect the current codebase.
2. Identify relevant files.
3. Explain the implementation plan.
4. Then implement only the requested task.

After coding:

1. Summarize what changed.
2. List modified files.
3. Explain how to test.
4. Mention possible risks.
5. Stop.

Do not continue to the next task automatically.

\---

# 25\. Prompt Template for Codex

Use this prompt for each task:

```text
Read AGENTS.md first.

Implement ONLY TASK XX.

Do not work on any other task.

Do not anticipate future tasks.

Do not redesign unrelated sections.

Before coding:
1. Inspect the current codebase.
2. Identify the files that need to change.
3. Explain your plan shortly.

Then implement ONLY TASK XX.

After completion, provide:
1. Summary of changes
2. Modified files
3. How to test
4. Any risks or notes
5. Recommended next task

Stop after completing this task.
```

\---

# 26\. Implementation Roadmap

## TASK 01 – Redesign Hero Section

Goal:

Make the homepage immediately communicate that Cyber Guardian Scan is the trust standard for AI tools.

Requirements:

* Keep product name Cyber Guardian Scan.
* Add headline: Before You Install AI, Verify It.
* Add supporting message: Has your code been scanned by Cyber Guardian Scan?
* Add explanation that the product scans:

  * MCP Servers
  * AI Agents
  * AI Skills
  * IDE Extensions
  * VS Code Extensions
  * Cursor Tools
  * GitHub Repositories
  * GitHub Actions
  * npm Packages
  * Dependencies
* Add visual flow:
Code / AI Tool → Cyber Guardian Scan → Security Score → Safe / Needs Review / Danger for Install
* Add CTA: Scan Code Now
* Add secondary CTA: Search Verified Tools
* Use premium dark SaaS design.

Success:

A visitor understands the value in under 5 seconds.

\---

## TASK 02 – Add Verified by Cyber Guardian Scan Badge

Goal:

Turn **Verified by Cyber Guardian Scan™** into a visible trust mark.

Requirements:

* Create a premium badge component.
* Badge text: Verified by Cyber Guardian Scan™
* Badge should support statuses:

  * Safe for Install
  * Needs Review
  * Danger for Install
  * Rescan Required
* Badge should support score display:

  * Cyber Guardian Security Score: XX/100
* Use the badge in homepage demo sections.

Important:

The badge means “this version was scanned”, not “safe forever”.

\---

## TASK 03 – Add Cyber Guardian Security Score Section

Goal:

Explain the scoring system.

Requirements:

Show example:

```text
Cyber Guardian Security Score™
96 / 100
Safe for Install
```

Subscores:

* Code Safety
* Credential Risk
* Prompt Injection Risk
* Supply Chain Risk
* Permissions Risk

Design:

Premium dashboard card.

\---

## TASK 04 – Add Scan Freshness / Fingerprint Explanation

Goal:

Explain why the database remains trustworthy even when code changes.

Requirements:

Add section explaining:

Cyber Guardian Scan verifies specific versions, commits and code fingerprints.

If the code changes, verification expires and rescan is required.

Show statuses:

* Verified Current
* Changed Since Scan
* Danger for Install
* Rescan Required

\---

## TASK 05 – Create Live Scan Demo UI

Goal:

Show the product value instantly.

Requirements:

Add demo input:

```text
Paste GitHub repo, npm package, MCP server or AI tool URL
```

Add button:

```text
Scan Now
```

If backend is not ready:

Create polished static demo result.

Demo result should show:

* Verified by Cyber Guardian Scan™
* Cyber Guardian Security Score
* Safe / Needs Review / Danger for Install
* Top findings
* Scan date
* Code fingerprint

\---

## TASK 06 – Add Public Reputation Database Preview

Goal:

Show that Cyber Guardian Scan is building a searchable trust database.

Requirements:

Create section:

```text
Public Reputation Database
```

Show table/cards with:

* Tool name
* Category
* Score
* Status
* Last scanned
* Freshness
* Recommendation

Add CTA:

```text
Search Verified Tools
```

Important:

Show that results are version/fingerprint based.

\---

## TASK 07 – Add Safe Alternatives Engine Section

Goal:

Show that Cyber Guardian Scan does not only block dangerous code, it recommends safer alternatives.

Requirements:

Example flow:

```text
Original tool:
Danger for Install
Score: 24/100

Recommended alternatives:
Tool A – Score 97 – Safe for Install
Tool B – Score 94 – Safe for Install
Tool C – Score 91 – Safe for Install
```

Important:

Say “similar functionality”, not “identical replacement”.

\---

## TASK 08 – Add Developer Certification Section

Goal:

Create a paid value proposition for developers.

Requirements:

Explain that developers can scan their own code, find issues, improve the score and earn:

```text
Verified by Cyber Guardian Scan™
```

Include:

* Upload / connect repository
* Get detailed security findings
* Fix issues
* Rescan
* Publish verified badge

CTA:

```text
Get Certified
```

Important:

Avoid legal absolute wording like “100% safe” or “fully approved”.

Use:

* Verified
* Recommended for Install
* High Security Score

\---

## TASK 09 – Add Detection Engine Section

Goal:

Explain why users should trust the findings.

Show layers:

1. Static Analysis
2. AI Semantic Review
3. Behavior Analysis
4. Threat Intelligence
5. Policy / Risk Rules

Design:

Modern layered cards.

\---

## TASK 10 – Add Enterprise Section

Goal:

Position Cyber Guardian Scan for teams and organizations.

Include:

* Team Dashboard
* Shared Reports
* Audit Trail
* API Access
* CI/CD Integration
* Policy Enforcement
* Approved Tool Catalog

CTA:

```text
Contact Sales
```

\---

## TASK 11 – Improve Visual Consistency

Goal:

Make the whole website feel premium and coherent.

Requirements:

* Keep dark premium design
* More whitespace
* Better section spacing
* Consistent typography
* Consistent cards
* Softer gradients
* Clear CTA hierarchy
* Smooth animations
* Better mobile responsiveness

Do not change product logic.

\---

## TASK 12 – Add Pricing / Monetization Structure

Goal:

Prepare commercial model.

Suggested tiers:

Free:

* Limited scans
* Basic score
* Basic recommendation

Pro:

* More scans
* Detailed findings
* Reports
* Safe alternatives

Developer Certification:

* Code improvement guidance
* Certification badge
* Public verified listing

Team / Enterprise:

* API
* CI/CD
* Policy enforcement
* Team dashboard
* Private scans

Important:

Pricing values can be placeholders unless real prices exist.

\---

## TASK 13 – Add Legal Trust Language

Goal:

Avoid risky promises.

Do not use:

* 100% safe
* Guaranteed safe
* Approved forever
* Fully secure

Use:

* Verified by Cyber Guardian Scan™
* Recommended for Install
* High Security Score
* This version was scanned
* Rescan required if code changes

\---

## TASK 14 – Create First Database Page

Goal:

Create page for scanned tools.

Suggested route:

```text
/verified-tools
```

Alternative:

```text
/reputation-database
```

Requirements:

* Search input
* Filters:

  * MCP
  * AI Agent
  * Extension
  * GitHub Repo
  * npm Package
* Score column
* Status column
* Last scanned column
* Freshness column
* View report button

Use mock data if backend is not ready.

\---

## TASK 15 – Create Report Page / Report Preview

Goal:

Show professional scan reports.

Report should include:

* Executive Summary
* Cyber Guardian Security Score
* Verified by Cyber Guardian Scan™
* Safe / Needs Review / Danger for Install
* Findings
* Risk explanations
* Recommendations
* Scan metadata
* Code fingerprint
* Version / commit

\---

## TASK 16 – Add Needs Review UX

Goal:

Represent uncertain or unsafe-but-not-malicious code professionally.

Requirements:

Add UI state for:

```text
Needs Review
```

Show:

* Yellow status
* Explanation
* Findings
* File path
* Line number
* Recommended fix
* Assessment:

  * likely developer oversight
  * unclear intent
  * suspicious pattern

Important:

Needs Review is not the same as Danger for Install.

\---

## TASK 17 – Add Malicious vs Unsafe Explanation

Goal:

Educate users and developers.

Explain:

Malicious code is intentionally harmful.

Unsafe code may be caused by poor implementation, weak validation, excessive permissions, missing safeguards or insecure architecture.

The product helps developers improve unsafe code and achieve a higher score.

\---

# 27\. Recommended Execution Order

Recommended order:

1. TASK 01 – Hero Section
2. TASK 02 – Verified Badge
3. TASK 03 – Security Score
4. TASK 05 – Live Scan Demo
5. TASK 16 – Needs Review UX
6. TASK 06 – Public Reputation Database Preview
7. TASK 14 – First Database Page
8. TASK 04 – Scan Freshness / Fingerprint
9. TASK 07 – Safe Alternatives Engine
10. TASK 08 – Developer Certification
11. TASK 15 – Report Preview
12. TASK 17 – Malicious vs Unsafe Explanation
13. TASK 09 – Detection Engine
14. TASK 10 – Enterprise
15. TASK 12 – Pricing
16. TASK 13 – Legal Trust Language
17. TASK 11 – Visual Consistency

\---

# 28\. Final North Star

Every feature must move Cyber Guardian Scan closer to this future:

Developers, AI users, businesses and organizations should feel uncomfortable installing or connecting AI tools that have not been scanned by Cyber Guardian Scan.

The long-term goal is for people to ask:

```text
Has it been verified by Cyber Guardian Scan?
```

If a feature moves the product closer to that future, build it.

If it does not, it is probably not a priority.

