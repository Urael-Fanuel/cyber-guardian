#!/usr/bin/env python3
"""
MCP Server Security Scanner
============================
Scans GitHub, npm, and mcp.so for MCP servers and analyzes their code
for security threats. Results are saved to Supabase.

Author: Cyber-Guardian
"""

import os
import re
import json
import time
import base64
import asyncio
import hashlib
import logging
import textwrap
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

import httpx
from supabase import create_client, Client

# ─────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────

GITHUB_TOKEN   = os.environ["GITHUB_TOKEN"]          # required
SUPABASE_URL   = os.environ["SUPABASE_URL"]           # required
SUPABASE_KEY   = os.environ["SUPABASE_SERVICE_KEY"]   # required (service role)
SCAN_LIMIT     = int(os.environ.get("SCAN_LIMIT", 30))   # total items per run
SCAN_SCOPES    = [
    scope.strip().lower()
    for scope in os.environ.get("SCAN_SCOPES", "skill,mcp,extension").split(",")
    if scope.strip().lower() in {"mcp", "skill", "extension"}
]
SCAN_SCOPE_LIMITS_RAW = os.environ.get("SCAN_SCOPE_LIMITS", "skill:15,mcp:10,extension:5")
GITHUB_DELAY   = float(os.environ.get("GITHUB_DELAY", 1.2))   # seconds between API calls
NPM_DELAY      = float(os.environ.get("NPM_DELAY", 0.5))
CYBER_GUARDIAN_URL = os.environ.get("CYBER_GUARDIAN_URL", "https://cyberguardianscan.com")
CG_MAX_INPUT_CHARS = int(os.environ.get("CG_MAX_INPUT_CHARS", "50000"))
CG_SCAN_DELAY  = float(os.environ.get("CG_SCAN_DELAY", 1.0))  # seconds between CG API calls
CG_ADMIN_BYPASS_SECRET = os.environ.get("CG_ADMIN_BYPASS_SECRET", "")
if not SCAN_SCOPES:
    SCAN_SCOPES = ["mcp"]


def parse_scope_limits(raw: str) -> dict[str, int]:
    limits: dict[str, int] = {}
    for part in raw.split(","):
        if ":" not in part:
            continue
        scope, value = part.split(":", 1)
        scope = scope.strip().lower()
        if scope not in {"mcp", "skill", "extension"}:
            continue
        try:
            limit = int(value.strip())
        except ValueError:
            continue
        if limit > 0:
            limits[scope] = limit
    return limits


SCAN_SCOPE_LIMITS = parse_scope_limits(SCAN_SCOPE_LIMITS_RAW)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("mcp-scanner")


# ─────────────────────────────────────────────
#  DATA MODELS
# ─────────────────────────────────────────────

class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class ThreatCategory(str, Enum):
    RCE               = "remote_code_execution"
    CREDENTIAL_THEFT  = "credential_theft"
    DATA_EXFILTRATION = "data_exfiltration"
    FILE_ACCESS       = "sensitive_file_access"
    PROMPT_INJECTION  = "prompt_injection"
    OBFUSCATION       = "obfuscation"
    SUPPLY_CHAIN      = "supply_chain"
    PERSISTENCE       = "persistence"
    BACKDOOR          = "backdoor"
    CRYPTOMINING      = "cryptomining"
    INFO_DISCLOSURE   = "information_disclosure"

@dataclass
class Threat:
    category:    ThreatCategory
    severity:    ThreatSeverity
    title:       str
    description: str
    file_path:   str        = ""
    line_number: int        = 0
    code_snippet: str       = ""
    pattern:     str        = ""

@dataclass
class ScannedServer:
    name:          str
    source:        str        # "github" | "npm" | "mcpso"
    url:           str
    description:   str        = ""
    stars:         int        = 0
    language:      str        = ""
    owner:         str        = ""
    package_name:  str        = ""
    version:       str        = ""
    weekly_dl:     int        = 0
    scan_date:     str        = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_score:    int        = 0       # 0–100
    risk_level:    str        = "clean" # clean | low | medium | high | critical
    threats:       list[Threat] = field(default_factory=list)
    files_scanned: int        = 0
    scan_error:    str        = ""
    content_hash:  str        = ""
    source_code:   str        = ""  # combined code for AI scan (max 200k chars)


# ─────────────────────────────────────────────
#  THREAT DETECTION ENGINE
# ─────────────────────────────────────────────

# Each rule: (pattern, title, description, category, severity)
THREAT_RULES: list[tuple] = [

    # ── Remote Code Execution ──────────────────────────────────────────
    (
        r"eval\s*\([^)]*(?:input|request|query|param|data|args|command|cmd)",
        "Dynamic eval() with user input",
        "eval() called with externally-influenced data — arbitrary code execution risk.",
        ThreatCategory.RCE, ThreatSeverity.CRITICAL,
    ),
    (
        r"exec\s*\([^)]*(?:input|request|query|param|data|args|command|cmd)",
        "exec() with user-controlled data",
        "exec() receiving dynamic data can allow attackers to run arbitrary code.",
        ThreatCategory.RCE, ThreatSeverity.CRITICAL,
    ),
    (
        r"subprocess\.(run|Popen|call|check_output)\s*\([^)]*(?:shell\s*=\s*True|f['\"]|format\()",
        "subprocess with shell=True or f-string",
        "Shell injection risk: subprocess launched with dynamic command construction.",
        ThreatCategory.RCE, ThreatSeverity.CRITICAL,
    ),
    (
        r"os\.system\s*\([^)]*(?:f['\"]|\+|format|%)",
        "os.system() with dynamic command",
        "Dynamic os.system() call is vulnerable to command injection.",
        ThreatCategory.RCE, ThreatSeverity.HIGH,
    ),
    (
        r"__import__\s*\([^)]*(?:input|request|data|args)",
        "Dynamic __import__ with user input",
        "Dynamically importing modules based on user input allows code injection.",
        ThreatCategory.RCE, ThreatSeverity.HIGH,
    ),
    (
        r"compile\s*\(.*?exec",
        "compile() + exec pattern",
        "compile() used to build executable bytecode dynamically.",
        ThreatCategory.RCE, ThreatSeverity.HIGH,
    ),

    # ── Credential Theft ──────────────────────────────────────────────
    (
        r"(?:os\.environ|getenv)\s*[\.\[]\s*['\"](?:AWS_SECRET|GITHUB_TOKEN|OPENAI_API_KEY|"
        r"ANTHROPIC_API_KEY|DATABASE_URL|SECRET_KEY|PRIVATE_KEY|PASSWORD|PASSWD|AUTH_TOKEN)['\"]",
        "Reads sensitive environment variable",
        "The server reads well-known secret environment variables — may be collecting credentials.",
        ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.HIGH,
    ),
    (
        r"open\s*\([^)]*(?:\.aws/credentials|\.ssh/id_rsa|\.gnupg|\.netrc|/etc/shadow|"
        r"\.npmrc|\.pypirc|authorized_keys)",
        "Reads credential file from disk",
        "Direct access to known credential/key files on the host filesystem.",
        ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.CRITICAL,
    ),
    (
        r"keyring\.get_password|SecretService|CryptUnprotectData|security find-generic-password",
        "Accesses system keychain/credential store",
        "Attempts to extract passwords from the OS keychain or secret store.",
        ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.CRITICAL,
    ),
    (
        r"(?:psutil|subprocess).*?(?:cmdline|environ|maps).*?(?:password|token|secret|key)",
        "Reads process memory/env for credentials",
        "Scanning running processes for secrets is a credential-harvesting technique.",
        ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.HIGH,
    ),

    # ── Data Exfiltration ─────────────────────────────────────────────
    (
        r"requests\.(get|post|put|patch)\s*\([^)]*(?:f['\"]|format\(|%\s*(?:\(|[a-z]))[^)]*"
        r"(?:data|json|files|content)\s*=",
        "HTTP POST with dynamic data to variable URL",
        "Data sent via HTTP to a dynamically constructed URL — potential exfiltration.",
        ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.HIGH,
    ),
    (
        r"(?:webhook|ngrok|requestbin|pipedream|burp\.suite|interact\.sh|canarytokens|"
        r"beeceptor|hookbin)",
        "Known data-capture/exfiltration domain",
        "Reference to known webhook capture or OAST (Out-of-band Application Security Testing) service.",
        ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.HIGH,
    ),
    (
        r"smtplib|sendmail|send_message.*?(?:password|token|key|secret|credential)",
        "Email exfiltration of credentials",
        "SMTP used to email captured secrets to an external address.",
        ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.CRITICAL,
    ),
    (
        r"socket\.connect\s*\(\s*\(['\"](?:\d{1,3}\.){3}\d{1,3}['\"]",
        "Hardcoded IP socket connection",
        "Raw TCP socket connection to a hardcoded IP — possible C2 callback.",
        ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.HIGH,
    ),

    # ── Sensitive File Access ─────────────────────────────────────────
    (
        r"open\s*\([^)]*(?:/etc/passwd|/etc/hosts|/proc/self|/var/log|/root/|~/.bash_history|"
        r"~/.zsh_history|~/Library/Cookies)",
        "Reads sensitive system file",
        "Direct read of a system file that should not be accessed by an MCP server.",
        ThreatCategory.FILE_ACCESS, ThreatSeverity.HIGH,
    ),
    (
        r"glob\.glob\s*\([^)]*(?:\*\.\s*(?:pem|key|pfx|p12|cer|crt|jks)|"
        r"\.env|\.secret|credentials)",
        "Glob search for key/credential files",
        "Scanning the filesystem for private key or credential files.",
        ThreatCategory.FILE_ACCESS, ThreatSeverity.CRITICAL,
    ),
    (
        r"shutil\.copy.*?(?:\.ssh|\.gnupg|\.aws|id_rsa|\.pem|\.key)",
        "Copies key/SSH files",
        "Credential or private key files are being copied — potential data staging.",
        ThreatCategory.FILE_ACCESS, ThreatSeverity.CRITICAL,
    ),

    # ── Prompt Injection ──────────────────────────────────────────────
    (
        r"(?:ignore|disregard|forget)\s+(?:previous|prior|above|all)\s+(?:instructions?|prompts?|rules?|constraints?)",
        "Prompt injection pattern in tool definition",
        "Tool description or response contains a classic prompt injection attempt.",
        ThreatCategory.PROMPT_INJECTION, ThreatSeverity.HIGH,
    ),
    (
        r"<\s*SYSTEM\s*>|<\s*INST\s*>|\[INST\]|\[\[SYS\]\]|###\s*System|"
        r"<\|im_start\|>system",
        "Fake system prompt delimiter injection",
        "Embedded fake LLM control tokens designed to hijack model behavior.",
        ThreatCategory.PROMPT_INJECTION, ThreatSeverity.CRITICAL,
    ),
    (
        r"(?:tool_description|description)\s*=.*?(?:you are|act as|pretend|your new role|"
        r"from now on|jailbreak)",
        "Role-override in tool description",
        "Tool description attempts to redefine the AI model's identity or override safety guardrails.",
        ThreatCategory.PROMPT_INJECTION, ThreatSeverity.HIGH,
    ),

    # ── Obfuscation ───────────────────────────────────────────────────
    (
        r"(?:exec|eval)\s*\(\s*base64\.b64decode",
        "Base64-decoded execution",
        "Executing base64-decoded content is a classic obfuscation technique.",
        ThreatCategory.OBFUSCATION, ThreatSeverity.CRITICAL,
    ),
    (
        r"bytes\.fromhex\s*\([^)]{20,}\)\s*\.decode",
        "Hex-encoded payload execution",
        "Long hex string decoded at runtime — typical of obfuscated malicious payloads.",
        ThreatCategory.OBFUSCATION, ThreatSeverity.HIGH,
    ),
    (
        r"zlib\.decompress\s*\(.*?\)\s*.*?(?:exec|eval)",
        "Compressed + executed payload",
        "Code decompressed with zlib and then executed — common dropper technique.",
        ThreatCategory.OBFUSCATION, ThreatSeverity.CRITICAL,
    ),
    (
        r"(?:marshal|pickle)\.loads?\s*\(.*?(?:base64|b64|hex|decompress)",
        "Deserialization of obfuscated payload",
        "Deserializing encoded/compressed data with pickle or marshal — arbitrary code risk.",
        ThreatCategory.OBFUSCATION, ThreatSeverity.CRITICAL,
    ),
    (
        r"chr\s*\(\d+\)\s*(?:\+\s*chr\s*\(\d+\)\s*){5,}",
        "Character-code string construction",
        "String built from chr() calls — evades string-based detection of malicious content.",
        ThreatCategory.OBFUSCATION, ThreatSeverity.MEDIUM,
    ),

    # ── Supply Chain ──────────────────────────────────────────────────
    (
        r"(?:install_requires|dependencies)[^]]*?['\"](?:[a-z0-9_-]+)\s*==\s*\*",
        "Wildcard version dependency",
        "Dependency pinned to '*' — susceptible to supply-chain poisoning via future versions.",
        ThreatCategory.SUPPLY_CHAIN, ThreatSeverity.MEDIUM,
    ),
    (
        r"pip\s+install\s+.*?--index-url\s+(?!https://pypi\.org)",
        "Custom pip index URL",
        "Dependencies fetched from a non-standard index — possible dependency confusion attack.",
        ThreatCategory.SUPPLY_CHAIN, ThreatSeverity.HIGH,
    ),
    (
        r"postinstall|preinstall|prepare.*?(?:curl|wget|bash|sh\s+-c)",
        "Install hook downloads+executes remote code",
        "npm lifecycle hook fetches and executes code at install time — supply-chain risk.",
        ThreatCategory.SUPPLY_CHAIN, ThreatSeverity.CRITICAL,
    ),

    # ── Persistence ───────────────────────────────────────────────────
    (
        r"crontab|/etc/cron\.|LaunchAgents|launchd|systemd.*?\.service.*?ExecStart",
        "Attempts to install persistence mechanism",
        "Modifies system scheduling or service configuration to survive reboots.",
        ThreatCategory.PERSISTENCE, ThreatSeverity.HIGH,
    ),
    (
        r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|"
        r"reg\s+add.*?\\Run",
        "Windows registry Run key modification",
        "Adds a Windows Registry autorun entry — classic malware persistence technique.",
        ThreatCategory.PERSISTENCE, ThreatSeverity.CRITICAL,
    ),

    # ── Backdoor / Reverse Shell ──────────────────────────────────────
    (
        r"(?:nc|ncat|netcat|socat)\s+-[le].*?\d{2,5}|"
        r"bash\s+-i\s+>&\s*/dev/tcp/|"
        r"python.*?-c.*?socket.*?connect.*?os\.dup2",
        "Reverse shell pattern",
        "Classic reverse shell construction detected — creates remote interactive shell access.",
        ThreatCategory.BACKDOOR, ThreatSeverity.CRITICAL,
    ),
    (
        r"paramiko|fabric.*?(?:connect|run).*?(?:password|pkey).*?(?:os\.|subprocess|exec)",
        "SSH backdoor via paramiko",
        "SSH connection combined with command execution — possible remote access backdoor.",
        ThreatCategory.BACKDOOR, ThreatSeverity.HIGH,
    ),

    # ── Cryptomining ──────────────────────────────────────────────────
    (
        r"(?:monero|xmrig|stratum\+tcp|mining\.pool|cryptonight|randomx)",
        "Cryptomining reference",
        "Reference to known mining algorithm, pool, or software — possible cryptojacker.",
        ThreatCategory.CRYPTOMINING, ThreatSeverity.HIGH,
    ),
    (
        r"import\s+(?:hashlib|multiprocessing).*?(?:sha256|sha3_256).*?(?:nonce|difficulty|target)",
        "Proof-of-work mining loop",
        "Proof-of-work calculation loop consistent with embedded cryptocurrency miner.",
        ThreatCategory.CRYPTOMINING, ThreatSeverity.MEDIUM,
    ),
]

# Compile all patterns once at startup
COMPILED_RULES = [
    (re.compile(pat, re.IGNORECASE | re.MULTILINE | re.DOTALL), title, desc, cat, sev)
    for pat, title, desc, cat, sev in THREAT_RULES
]

# File extensions to analyze
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh",
    ".json",   # package.json scripts, deps
    ".toml",   # pyproject.toml
    ".yaml", ".yml",  # workflow files
}
MAX_FILE_SIZE = 500_000  # 500 KB — skip huge minified files
MAX_ARCHIVE_SIZE = 20_000_000
MAX_ARCHIVE_MEMBERS = 2000
MAX_EXTRACTED_BYTES = 5_000_000

def compute_risk_score(threats: list[Threat]) -> tuple[int, str]:
    severity_weights = {
        ThreatSeverity.CRITICAL: 40,
        ThreatSeverity.HIGH:     20,
        ThreatSeverity.MEDIUM:   10,
        ThreatSeverity.LOW:       5,
        ThreatSeverity.INFO:      1,
    }
    score = min(100, sum(severity_weights[t.severity] for t in threats))
    if score == 0:    level = "clean"
    elif score < 10:  level = "low"
    elif score < 30:  level = "medium"
    elif score < 60:  level = "high"
    else:             level = "critical"
    return score, level

def analyze_content(content: str, file_path: str) -> list[Threat]:
    """Run all threat rules against a file's content."""
    found: list[Threat] = []
    seen_titles: set[str] = set()

    for compiled, title, description, category, severity in COMPILED_RULES:
        if title in seen_titles:
            continue
        match = compiled.search(content)
        if not match:
            continue

        seen_titles.add(title)
        # Extract a short code snippet around the match
        start = max(0, match.start() - 60)
        end   = min(len(content), match.end() + 60)
        snippet = content[start:end].strip()
        # Calculate approximate line number
        line_no = content[:match.start()].count("\n") + 1

        found.append(Threat(
            category=category,
            severity=severity,
            title=title,
            description=description,
            file_path=file_path,
            line_number=line_no,
            code_snippet=textwrap.shorten(snippet, width=300),
            pattern=compiled.pattern[:80],
        ))
    return found


# ─────────────────────────────────────────────
#  SOURCE: GITHUB
# ─────────────────────────────────────────────

GITHUB_SEARCH_QUERIES = [
    "mcp server topic:mcp",
    "\"model context protocol\" server language:python",
    "\"model context protocol\" server language:typescript",
    "mcp-server in:name",
    "mcp_server in:name",
]

GITHUB_SKILL_SEARCH_QUERIES = [
    "\"Claude Skill\" language:markdown",
    "\"Claude Skills\" language:markdown",
    "\"Cursor Skill\" language:markdown",
    "\"AI Skill\" \"SKILL.md\"",
    "\"SKILL.md\" \"description:\"",
]

GITHUB_EXTENSION_SEARCH_QUERIES = [
    "topic:vscode-extension language:typescript",
    "\"vscode\" \"activationEvents\" \"package.json\"",
    "\"contributes\" \"commands\" \"activationEvents\" \"package.json\"",
    "topic:cursor-extension language:typescript",
    "\"jetbrains\" \"plugin.xml\" language:kotlin",
]

GITHUB_QUERIES_BY_SCOPE = {
    "mcp": GITHUB_SEARCH_QUERIES,
    "skill": GITHUB_SKILL_SEARCH_QUERIES,
    "extension": GITHUB_EXTENSION_SEARCH_QUERIES,
}

async def fetch_github_repositories(client: httpx.AsyncClient, limit: int, queries: list[str]) -> list[dict]:
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    results: dict[str, dict] = {}   # full_name → repo dict

    for query in queries:
        if len(results) >= limit:
            break
        url = "https://api.github.com/search/repositories"
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": 50}
        try:
            r = await client.get(url, headers=headers, params=params, timeout=20)
            r.raise_for_status()
            for item in r.json().get("items", []):
                results[item["full_name"]] = item
        except Exception as e:
            log.warning(f"GitHub search error [{query}]: {e}")
        await asyncio.sleep(GITHUB_DELAY)

    return list(results.values())[:limit]


async def fetch_github_servers(client: httpx.AsyncClient, limit: int) -> list[dict]:
    return await fetch_github_repositories(client, limit, GITHUB_SEARCH_QUERIES)


async def fetch_github_scope(client: httpx.AsyncClient, scope: str, limit: int) -> list[dict]:
    queries = GITHUB_QUERIES_BY_SCOPE.get(scope, GITHUB_SEARCH_QUERIES)
    return await fetch_github_repositories(client, limit, queries)


async def fetch_github_code(client: httpx.AsyncClient, full_name: str) -> dict[str, str]:
    """Fetch all scannable files from a GitHub repo using the Trees API."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    files: dict[str, str] = {}
    try:
        # Get default branch
        r = await client.get(
            f"https://api.github.com/repos/{full_name}",
            headers=headers, timeout=15,
        )
        r.raise_for_status()
        branch = r.json().get("default_branch", "main")
        await asyncio.sleep(GITHUB_DELAY)

        # Get file tree
        r = await client.get(
            f"https://api.github.com/repos/{full_name}/git/trees/{branch}",
            headers=headers, params={"recursive": "1"}, timeout=20,
        )
        r.raise_for_status()
        tree = r.json().get("tree", [])
        await asyncio.sleep(GITHUB_DELAY)

        # Fetch individual files
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item["path"]
            ext  = "." + path.rsplit(".", 1)[-1] if "." in path else ""
            size = item.get("size", 0)
            if ext.lower() not in SCAN_EXTENSIONS or size > MAX_FILE_SIZE:
                continue

            try:
                r = await client.get(
                    f"https://api.github.com/repos/{full_name}/contents/{path}",
                    headers=headers, timeout=15,
                )
                r.raise_for_status()
                raw = r.json()
                if raw.get("encoding") == "base64":
                    content = base64.b64decode(raw["content"]).decode("utf-8", errors="replace")
                    files[path] = content
            except Exception as e:
                log.debug(f"  Skipping {path}: {e}")
            await asyncio.sleep(0.3)

    except Exception as e:
        log.warning(f"Failed to fetch code for {full_name}: {e}")

    return files


async def scan_github_server(client: httpx.AsyncClient, repo: dict) -> ScannedServer:
    full_name = repo["full_name"]
    log.info(f"  [GitHub] Scanning {full_name}")
    server = ScannedServer(
        name=repo.get("name", full_name),
        source="github",
        url=repo.get("html_url", ""),
        description=repo.get("description", "") or "",
        stars=repo.get("stargazers_count", 0),
        language=repo.get("language", "") or "",
        owner=repo.get("owner", {}).get("login", ""),
    )

    files = await fetch_github_code(client, full_name)
    server.files_scanned = len(files)

    all_content = "\n".join(files.values())
    server.content_hash = hashlib.sha256(all_content.encode()).hexdigest()[:16]
    server.source_code  = all_content[:200000]  # store for AI scan

    all_threats: list[Threat] = []
    for path, content in files.items():
        all_threats.extend(analyze_content(content, path))

    server.threats   = all_threats
    server.risk_score, server.risk_level = compute_risk_score(all_threats)
    return server


# ─────────────────────────────────────────────
#  SOURCE: NPM
# ─────────────────────────────────────────────

NPM_SEARCH_TERMS = [
    "mcp-server",
    "model-context-protocol",
    "@modelcontextprotocol",
    "mcp-tool",
]

NPM_SKILL_SEARCH_TERMS = [
    "claude skill",
    "cursor skill",
    "ai skill",
    "prompt injection skill",
    "agent skill",
]

NPM_EXTENSION_SEARCH_TERMS = [
    "vscode extension",
    "cursor extension",
    "jetbrains plugin",
    "code extension",
    "ide extension",
]

NPM_TERMS_BY_SCOPE = {
    "mcp": NPM_SEARCH_TERMS,
    "skill": NPM_SKILL_SEARCH_TERMS,
    "extension": NPM_EXTENSION_SEARCH_TERMS,
}

async def fetch_npm_packages(client: httpx.AsyncClient, limit: int, terms: list[str]) -> list[dict]:
    results: dict[str, dict] = {}

    for term in terms:
        if len(results) >= limit:
            break
        try:
            r = await client.get(
                "https://registry.npmjs.org/-/v1/search",
                params={"text": term, "size": 50},
                timeout=15,
            )
            r.raise_for_status()
            for obj in r.json().get("objects", []):
                pkg = obj.get("package", {})
                results[pkg["name"]] = pkg
        except Exception as e:
            log.warning(f"npm search error [{term}]: {e}")
        await asyncio.sleep(NPM_DELAY)

    return list(results.values())[:limit]


async def fetch_npm_servers(client: httpx.AsyncClient, limit: int) -> list[dict]:
    return await fetch_npm_packages(client, limit, NPM_SEARCH_TERMS)


async def fetch_npm_scope(client: httpx.AsyncClient, scope: str, limit: int) -> list[dict]:
    terms = NPM_TERMS_BY_SCOPE.get(scope, NPM_SEARCH_TERMS)
    return await fetch_npm_packages(client, limit, terms)


async def fetch_npm_tarball_contents(client: httpx.AsyncClient, name: str, version: str) -> dict[str, str]:
    """Download and extract the npm tarball to analyze JS/TS source files."""
    import tarfile
    import io

    files: dict[str, str] = {}
    try:
        url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        r = await client.get(url, timeout=30, follow_redirects=True)
        if r.status_code != 200:
            return files
        content_length = int(r.headers.get("content-length") or 0)
        if content_length > MAX_ARCHIVE_SIZE or len(r.content) > MAX_ARCHIVE_SIZE:
            log.warning(f"  npm tarball too large, skipping {name}")
            return files

        tgz = io.BytesIO(r.content)
        with tarfile.open(fileobj=tgz, mode="r:gz") as tar:
            members = tar.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                log.warning(f"  npm tarball has too many files, skipping {name}")
                return files
            extracted_bytes = 0
            for member in members:
                path = member.name
                ext  = "." + path.rsplit(".", 1)[-1] if "." in path else ""
                if ext.lower() not in SCAN_EXTENSIONS:
                    continue
                if member.size > MAX_FILE_SIZE:
                    continue
                if extracted_bytes + member.size > MAX_EXTRACTED_BYTES:
                    break
                try:
                    f = tar.extractfile(member)
                    if f:
                        content = f.read().decode("utf-8", errors="replace")
                        files[path] = content
                        extracted_bytes += member.size
                except Exception:
                    pass
    except Exception as e:
        log.debug(f"  npm tarball error {name}: {e}")
    return files


async def scan_npm_server(client: httpx.AsyncClient, pkg: dict) -> ScannedServer:
    name = pkg["name"]
    log.info(f"  [npm] Scanning {name}")

    try:
        r = await client.get(f"https://registry.npmjs.org/{name}", timeout=15)
        r.raise_for_status()
        data    = r.json()
        version = data.get("dist-tags", {}).get("latest", "")
        dl_url  = f"https://api.npmjs.org/downloads/point/last-week/{name}"
        dr      = await client.get(dl_url, timeout=10)
        weekly_dl = dr.json().get("downloads", 0) if dr.status_code == 200 else 0
    except Exception as e:
        log.warning(f"  npm metadata error {name}: {e}")
        version, weekly_dl = "", 0

    server = ScannedServer(
        name=name,
        source="npm",
        url=f"https://www.npmjs.com/package/{name}",
        description=pkg.get("description", "") or "",
        package_name=name,
        version=version,
        weekly_dl=weekly_dl,
    )

    files = await fetch_npm_tarball_contents(client, name, version)
    server.files_scanned = len(files)

    all_content = "\n".join(files.values())
    server.content_hash = hashlib.sha256(all_content.encode()).hexdigest()[:16]
    server.source_code  = all_content[:200000]  # store for AI scan

    all_threats: list[Threat] = []
    for path, content in files.items():
        all_threats.extend(analyze_content(content, path))

    server.threats   = all_threats
    server.risk_score, server.risk_level = compute_risk_score(all_threats)
    return server


# ─────────────────────────────────────────────
#  SOURCE: MCP.SO
# ─────────────────────────────────────────────

async def fetch_mcpso_servers(client: httpx.AsyncClient, limit: int) -> list[dict]:
    """Scrape mcp.so server listing (public directory)."""
    servers: list[dict] = []
    page = 1
    while len(servers) < limit:
        try:
            r = await client.get(
                "https://mcp.so/api/servers",
                params={"page": page, "limit": 50},
                timeout=15,
                headers={"User-Agent": "CyberGuardian-MCP-Scanner/1.0 (security research)"},
            )
            if r.status_code == 404:
                break
            r.raise_for_status()
            data = r.json()
            items = data if isinstance(data, list) else data.get("data", data.get("servers", []))
            if not items:
                break
            servers.extend(items)
            page += 1
        except Exception as e:
            log.warning(f"mcp.so fetch error (page {page}): {e}")
            break
        await asyncio.sleep(1.0)
    return servers[:limit]


async def scan_mcpso_server(client: httpx.AsyncClient, item: dict) -> Optional[ScannedServer]:
    """For mcp.so entries that link to GitHub, delegate to the GitHub scanner."""
    github_url = item.get("github") or item.get("repository") or item.get("url", "")
    if "github.com/" not in github_url:
        return None

    # Parse owner/repo from URL
    parts = github_url.rstrip("/").split("github.com/")[-1].split("/")
    if len(parts) < 2:
        return None
    full_name = f"{parts[0]}/{parts[1]}"

    repo_mock = {
        "full_name":        full_name,
        "name":             item.get("name", parts[1]),
        "html_url":         f"https://github.com/{full_name}",
        "description":      item.get("description", ""),
        "stargazers_count": item.get("stars", 0),
        "language":         item.get("language", ""),
        "owner":            {"login": parts[0]},
        "default_branch":   "main",
    }
    server = await scan_github_server(client, repo_mock)
    server.source = "mcpso"
    return server


# ─────────────────────────────────────────────
#  CYBER-GUARDIAN AI SCANNER
# ─────────────────────────────────────────────

async def scan_with_cyber_guardian(client: httpx.AsyncClient, code: str, scope: str = "mcp") -> dict:
    """Send code to Cyber-Guardian AI scanner and get threat analysis."""
    if not code or not code.strip():
        return {}
    headers = {"Content-Type": "application/json"}
    headers["X-CG-Skip-Persist"] = "1"
    if CG_ADMIN_BYPASS_SECRET:
        headers["X-CG-Admin-Secret"] = CG_ADMIN_BYPASS_SECRET
    try:
        r = await client.post(
            f"{CYBER_GUARDIAN_URL}/api/scan",
            json={"code": code[:CG_MAX_INPUT_CHARS], "scope": scope},
            timeout=60,
            headers=headers,
        )
        if r.status_code == 200:
            result = r.json()
            log.info(f"  [CG] status={result.get('status')} score={result.get('threat_score')}")
            return result
        else:
            log.warning(f"  [CG] scan returned {r.status_code}")
    except Exception as e:
        log.warning(f"  [CG] scan error: {e}")
    return {}


def _clean_text(value, max_len=240):
    return str(value or "").strip()[:max_len]


def _clean_list(value, max_items=8):
    if not isinstance(value, list):
        return []
    seen = []
    for item in value:
        cleaned = _clean_text(item, 48).lower()
        if cleaned and cleaned not in seen:
            seen.append(cleaned)
        if len(seen) >= max_items:
            break
    return seen


def _site_scan_row(scope: str, result: dict, server=None) -> dict:
    status = result.get("status", "STATUS_AMBIGUOUS")
    threats = result.get("threats", [])
    threats_summary = ""
    if status != "STATUS_SAFE":
        threats_summary = ", ".join([t.get("family", "") for t in threats[:5] if t.get("family")])

    profile = result.get("code_profile") if isinstance(result.get("code_profile"), dict) else {}
    row = {
        "scope":            scope,
        "status":           status,
        "threat_score":     result.get("threat_score", 0),
        "threat_count":     len(threats),
        "threats_summary":  threats_summary,
        "code_purpose":     _clean_text(profile.get("purpose") or profile.get("summary"), 280),
        "component_type":   _clean_text(profile.get("component_type") or scope, 48).lower(),
        "capabilities":     _clean_list(profile.get("capabilities"), 8),
        "use_case_tags":    _clean_list(profile.get("use_case_tags") or profile.get("keywords"), 10),
    }
    if server:
        row.update({
            "source_name":  _clean_text(getattr(server, "name", ""), 160),
            "source_url":   _clean_text(getattr(server, "url", ""), 500),
            "source_owner": _clean_text(getattr(server, "owner", ""), 120),
            "code_hash":    _clean_text(getattr(server, "content_hash", ""), 80),
        })
    return row


def save_site_scan(sb: Client, scope: str, result: dict, server=None) -> bool:
    """Save AI scan result to site_scans table (visible in dashboard)."""
    if not result or not result.get("status"):
        return False
    row = _site_scan_row(scope, result, server)
    try:
        sb.table("site_scans").insert(row).execute()
        log.info(f"  [CG] saved site_scan scope={scope} status={row.get('status')}")
        return True
    except Exception as e:
        legacy_markers = ("schema cache", "column", "could not find")
        if any(marker in str(e).lower() for marker in legacy_markers):
            try:
                legacy = {key: row[key] for key in ("scope", "status", "threat_score", "threat_count", "threats_summary")}
                sb.table("site_scans").insert(legacy).execute()
                log.warning("  [CG] saved legacy site_scan; run migration 005 for enriched metadata")
                return True
            except Exception as retry_error:
                log.warning(f"  [CG] Failed to save legacy site scan: {retry_error}")
        else:
            log.warning(f"  [CG] Failed to save site scan: {e}")
        return False


# ─────────────────────────────────────────────
#  SUPABASE STORAGE
# ─────────────────────────────────────────────

def get_supabase() -> Client:
    return create_client(SUPABASE_URL, SUPABASE_KEY)


def save_scan_run(sb: Client, run_id: str, stats: dict) -> None:
    sb.table("mcp_scan_runs").upsert({
        "id":           run_id,
        "started_at":   stats["started_at"],
        "completed_at": stats["completed_at"],
        "total_scanned": stats["total_scanned"],
        "total_malicious": stats["total_malicious"],
        "by_source":    stats["by_source"],
        "by_risk_level": stats["by_risk_level"],
        "by_category":   stats["by_category"],
    }).execute()


def save_server(sb: Client, server: ScannedServer, run_id: str) -> Optional[str]:
    """Upsert a server record, return its DB id."""
    threats_json = [
        {k: (v.value if hasattr(v, "value") else v)
         for k, v in asdict(t).items()}
        for t in server.threats
    ]
    row = {
        "name":           server.name,
        "source":         server.source,
        "url":            server.url,
        "description":    server.description[:500],
        "stars":          server.stars,
        "language":       server.language,
        "owner":          server.owner,
        "package_name":   server.package_name,
        "version":        server.version,
        "weekly_downloads": server.weekly_dl,
        "scan_date":      server.scan_date,
        "risk_score":     server.risk_score,
        "risk_level":     server.risk_level,
        "threats":        threats_json,
        "threat_count":   len(server.threats),
        "files_scanned":  server.files_scanned,
        "content_hash":   server.content_hash,
        "scan_run_id":    run_id,
    }
    try:
        res = sb.table("mcp_servers").upsert(
            row, on_conflict="url"
        ).execute()
        return res.data[0]["id"] if res.data else None
    except Exception as e:
        log.error(f"Supabase save error [{server.name}]: {e}")
        return None


# ─────────────────────────────────────────────
#  MAIN ORCHESTRATOR
# ─────────────────────────────────────────────

async def run_mcp_only_scan():
    run_id     = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.time()
    MAX_RUNTIME = int(os.environ.get("MAX_RUNTIME_MINUTES", "10")) * 60
    log.info(f"╔══ MCP Security Scan START  run_id={run_id} ══╗")

    def time_remaining():
        return MAX_RUNTIME - (time.time() - start_time)

    def should_stop():
        remaining = time_remaining()
        if remaining <= 0:
            log.warning(f"⏰ Time budget nearly exhausted ({remaining:.0f}s left) — stopping gracefully")
            return True
        return False

    sb = get_supabase()
    all_servers: list[ScannedServer] = []

    async with httpx.AsyncClient(follow_redirects=True) as client:

        # ── 1. Discover servers ────────────────────────────────────────
        log.info("▶ Discovering GitHub servers…")
        github_repos = await fetch_github_servers(client, SCAN_LIMIT // 3)
        log.info(f"  Found {len(github_repos)} GitHub repos")

        log.info("▶ Discovering npm packages…")
        npm_pkgs = await fetch_npm_servers(client, SCAN_LIMIT // 3)
        log.info(f"  Found {len(npm_pkgs)} npm packages")

        log.info("▶ Discovering mcp.so servers…")
        mcpso_items = await fetch_mcpso_servers(client, SCAN_LIMIT // 3)
        log.info(f"  Found {len(mcpso_items)} mcp.so entries")

        # ── 2. Scan each server ────────────────────────────────────────
        log.info("▶ Scanning GitHub repos…")
        for repo in github_repos:
            if should_stop(): break
            try:
                server = await scan_github_server(client, repo)
                all_servers.append(server)
                save_server(sb, server, run_id)
                # Send to Cyber-Guardian AI scanner
                if server.source_code:
                    cg_result = await scan_with_cyber_guardian(client, server.source_code, "mcp")
                    if cg_result:
                        save_site_scan(sb, "mcp", cg_result, server)
                    await asyncio.sleep(CG_SCAN_DELAY)
            except Exception as e:
                log.error(f"  Error scanning {repo.get('full_name')}: {e}")

        log.info("▶ Scanning npm packages…")
        for pkg in npm_pkgs:
            if should_stop(): break
            try:
                server = await scan_npm_server(client, pkg)
                all_servers.append(server)
                save_server(sb, server, run_id)
                # Send to Cyber-Guardian AI scanner
                if server.source_code:
                    cg_result = await scan_with_cyber_guardian(client, server.source_code, "mcp")
                    if cg_result:
                        save_site_scan(sb, "mcp", cg_result, server)
                    await asyncio.sleep(CG_SCAN_DELAY)
            except Exception as e:
                log.error(f"  Error scanning {pkg.get('name')}: {e}")

        log.info("▶ Scanning mcp.so servers…")
        for item in mcpso_items:
            if should_stop(): break
            try:
                server = await scan_mcpso_server(client, item)
                if server:
                    all_servers.append(server)
                    save_server(sb, server, run_id)
                    # Send to Cyber-Guardian AI scanner
                    if server.source_code:
                        cg_result = await scan_with_cyber_guardian(client, server.source_code, "mcp")
                        if cg_result:
                            save_site_scan(sb, "mcp", cg_result, server)
                        await asyncio.sleep(CG_SCAN_DELAY)
            except Exception as e:
                log.error(f"  Error scanning mcp.so item: {e}")

    # ── 3. Compute aggregate stats ─────────────────────────────────────
    by_source:    dict[str, int] = {}
    by_risk_level: dict[str, int] = {}
    by_category:   dict[str, int] = {}
    total_malicious = 0

    for s in all_servers:
        by_source[s.source] = by_source.get(s.source, 0) + 1
        by_risk_level[s.risk_level] = by_risk_level.get(s.risk_level, 0) + 1
        if s.risk_level in ("high", "critical"):
            total_malicious += 1
        for t in s.threats:
            key = t.category.value
            by_category[key] = by_category.get(key, 0) + 1

    completed_at = datetime.now(timezone.utc).isoformat()
    stats = {
        "started_at":    started_at,
        "completed_at":  completed_at,
        "total_scanned": len(all_servers),
        "total_malicious": total_malicious,
        "by_source":     by_source,
        "by_risk_level": by_risk_level,
        "by_category":   by_category,
    }
    save_scan_run(sb, run_id, stats)

    log.info("╔══ SCAN COMPLETE ═══════════════════════════════╗")
    log.info(f"║  Total scanned  : {len(all_servers)}")
    log.info(f"║  Malicious (H/C): {total_malicious}")
    log.info(f"║  By risk level  : {json.dumps(by_risk_level)}")
    log.info(f"║  By category    : {json.dumps(by_category)}")
    log.info("╚═════════════════════════════════════════════════╝")
    return stats


async def run_scan():
    run_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.time()
    max_runtime = int(os.environ.get("MAX_RUNTIME_MINUTES", "10")) * 60

    log.info(f"Cyber-Guardian batch scan START run_id={run_id}")
    log.info(f"Scopes: {', '.join(SCAN_SCOPES)} | total limit: {SCAN_LIMIT}")
    if SCAN_SCOPE_LIMITS:
        log.info(f"Scope limits: {json.dumps(SCAN_SCOPE_LIMITS)}")

    def should_stop() -> bool:
        remaining = max_runtime - (time.time() - start_time)
        if remaining <= 0:
            log.warning("Time budget exhausted; stopping gracefully")
            return True
        return False

    def fallback_scope_limit(index: int) -> int:
        base = SCAN_LIMIT // len(SCAN_SCOPES)
        remainder = SCAN_LIMIT % len(SCAN_SCOPES)
        return base + (1 if index < remainder else 0)

    def requested_scope_limit(scope: str, index: int) -> int:
        if SCAN_SCOPE_LIMITS:
            return SCAN_SCOPE_LIMITS.get(scope, 0)
        return fallback_scope_limit(index)

    async def scan_cg_and_save(scope: str, source_code: str, server=None):
        if not source_code:
            return
        cg_result = await scan_with_cyber_guardian(client, source_code, scope)
        if cg_result:
            save_site_scan(sb, scope, cg_result, server)
        await asyncio.sleep(CG_SCAN_DELAY)

    async def scan_github_items(scope: str, repos: list[dict], save_mcp_rows: bool):
        for repo in repos:
            if should_stop():
                break
            try:
                server = await scan_github_server(client, repo)
                server.source = "github" if scope == "mcp" else f"github_{scope}"
                all_servers.append(server)
                if save_mcp_rows:
                    save_server(sb, server, run_id)
                await scan_cg_and_save(scope, server.source_code, server)
            except Exception as e:
                log.error(f"  Error scanning {scope} repo {repo.get('full_name')}: {e}")

    async def scan_npm_items(scope: str, packages: list[dict], save_mcp_rows: bool):
        for pkg in packages:
            if should_stop():
                break
            try:
                server = await scan_npm_server(client, pkg)
                server.source = "npm" if scope == "mcp" else f"npm_{scope}"
                all_servers.append(server)
                if save_mcp_rows:
                    save_server(sb, server, run_id)
                await scan_cg_and_save(scope, server.source_code, server)
            except Exception as e:
                log.error(f"  Error scanning {scope} npm package {pkg.get('name')}: {e}")

    sb = get_supabase()
    all_servers: list[ScannedServer] = []

    async with httpx.AsyncClient(follow_redirects=True) as client:
        remaining_total = SCAN_LIMIT
        for index, scope in enumerate(SCAN_SCOPES):
            requested_limit = requested_scope_limit(scope, index)
            limit = min(requested_limit, remaining_total)
            remaining_total -= limit
            if limit <= 0 or should_stop():
                continue
            log.info(f"Scope {scope}: limit={limit}")

            if scope == "mcp":
                github_limit = max(1, limit // 3)
                npm_limit = max(1, limit // 3)
                mcpso_limit = max(0, limit - github_limit - npm_limit)

                github_repos = await fetch_github_servers(client, github_limit)
                npm_pkgs = await fetch_npm_servers(client, npm_limit)
                mcpso_items = await fetch_mcpso_servers(client, mcpso_limit) if mcpso_limit else []

                log.info(f"  MCP discovered: github={len(github_repos)} npm={len(npm_pkgs)} mcp.so={len(mcpso_items)}")
                await scan_github_items("mcp", github_repos, True)
                await scan_npm_items("mcp", npm_pkgs, True)

                for item in mcpso_items:
                    if should_stop():
                        break
                    try:
                        server = await scan_mcpso_server(client, item)
                        if server:
                            server.source = "mcpso"
                            all_servers.append(server)
                            save_server(sb, server, run_id)
                            await scan_cg_and_save("mcp", server.source_code, server)
                    except Exception as e:
                        log.error(f"  Error scanning mcp.so item: {e}")
            else:
                github_limit = max(1, limit // 2)
                npm_limit = max(0, limit - github_limit)
                github_repos = await fetch_github_scope(client, scope, github_limit)
                npm_pkgs = await fetch_npm_scope(client, scope, npm_limit) if npm_limit else []

                log.info(f"  {scope} discovered: github={len(github_repos)} npm={len(npm_pkgs)}")
                await scan_github_items(scope, github_repos, False)
                await scan_npm_items(scope, npm_pkgs, False)

    by_source: dict[str, int] = {}
    by_risk_level: dict[str, int] = {}
    by_category: dict[str, int] = {}
    total_malicious = 0

    for s in all_servers:
        by_source[s.source] = by_source.get(s.source, 0) + 1
        by_risk_level[s.risk_level] = by_risk_level.get(s.risk_level, 0) + 1
        if s.risk_level in ("high", "critical"):
            total_malicious += 1
        for t in s.threats:
            key = t.category.value
            by_category[key] = by_category.get(key, 0) + 1

    completed_at = datetime.now(timezone.utc).isoformat()
    stats = {
        "started_at": started_at,
        "completed_at": completed_at,
        "total_scanned": len(all_servers),
        "total_malicious": total_malicious,
        "by_source": by_source,
        "by_risk_level": by_risk_level,
        "by_category": by_category,
    }
    save_scan_run(sb, run_id, stats)

    log.info("SCAN COMPLETE")
    log.info(f"  Total scanned  : {len(all_servers)}")
    log.info(f"  Malicious (H/C): {total_malicious}")
    log.info(f"  By source      : {json.dumps(by_source)}")
    log.info(f"  By risk level  : {json.dumps(by_risk_level)}")
    log.info(f"  By category    : {json.dumps(by_category)}")
    return stats


if __name__ == "__main__":
    asyncio.run(run_scan())
