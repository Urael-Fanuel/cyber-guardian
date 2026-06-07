const MAX_SOURCE_CHARS = 150000;
const MAX_SOURCE_FILES = 24;
const MAX_FILE_CHARS = 100000;
const FETCH_TIMEOUT_MS = 12000;

function githubHeaders() {
  const headers = { Accept: "application/vnd.github+json", "User-Agent": "Cyber-Guardian-Source-Resolver" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

function safeSegment(value) {
  return /^[a-z0-9_.-]+$/i.test(String(value || ""));
}

function parseSkillsIlCommand(value) {
  const text = String(value || "").trim();
  const command = text.match(/^npx\s+skills-il\s+add\s+skills-il\/([a-z0-9_.-]+)@([a-z0-9_.-]+)(?:\s|$)/i);
  const skill = text.match(/(?:^|\s)--skill\s+([a-z0-9_.-]+)(?:\s|$)/i);
  if (!command || !skill) return null;
  return {
    provider: "skills_il",
    owner: "skills-il",
    repo: command[1],
    ref: command[2],
    path: skill[1],
    source_url: `https://github.com/skills-il/${command[1]}/tree/${command[2]}`,
  };
}

function parseGithubUrl(value) {
  let url;
  try { url = new URL(String(value || "").trim()); } catch { return null; }
  if (url.protocol !== "https:") return null;
  const parts = url.pathname.split("/").filter(Boolean);

  if (url.hostname === "raw.githubusercontent.com" && parts.length >= 4) {
    const [owner, repo, ref, ...pathParts] = parts;
    if (![owner, repo, ref, ...pathParts].every(safeSegment)) return null;
    return { provider: "github", owner, repo: repo.replace(/\.git$/i, ""), ref, path: pathParts.join("/"), file: true, raw_url: url.toString(), source_url: url.toString() };
  }

  if (url.hostname !== "github.com" || parts.length < 2) return null;
  const [owner, rawRepo, marker, ref, ...pathParts] = parts;
  const repo = String(rawRepo || "").replace(/\.git$/i, "");
  if (!safeSegment(owner) || !safeSegment(repo)) return null;
  if ((marker === "blob" || marker === "raw" || marker === "tree") && ref) {
    if (!safeSegment(ref) || !pathParts.every(safeSegment)) return null;
    return {
      provider: "github", owner, repo, ref, path: pathParts.join("/"), file: marker !== "tree",
      raw_url: marker !== "tree" ? `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${pathParts.join("/")}` : "",
      source_url: url.toString(),
    };
  }
  return { provider: "github", owner, repo, ref: "", path: "", file: false, source_url: `https://github.com/${owner}/${repo}` };
}

function parseSupportedSourceReference(classification) {
  const reference = String(classification?.reference || "").trim();
  return parseSkillsIlCommand(reference) || parseGithubUrl(reference);
}

function usefulSourcePath(path) {
  const value = String(path || "").toLowerCase();
  if (!value || /(^|\/)(node_modules|vendor|dist|build|coverage|\.git|\.next|out)\//.test(value)) return false;
  if (/\.(png|jpe?g|gif|webp|svg|ico|zip|tar|gz|7z|exe|dll|so|dylib|pdf)$/i.test(value)) return false;
  return /\.(js|mjs|cjs|ts|tsx|jsx|py|json|ya?ml|toml|md|sh|bash|zsh|ps1|bat|cmd|go|rs|java|kt|kts|rb|php|c|h|cc|cpp|cs|swift|scala|lua|xml|ini|cfg|conf|env|txt|lock)$/i.test(value);
}

function unsupportedExecutablePath(path) {
  return /\.(exe|dll|so|dylib|wasm|jar|class|zip|tar|gz|7z)$/i.test(String(path || ""));
}

function sourcePathRank(path) {
  const value = String(path || "").toLowerCase();
  let score = 0;
  if (/(skill\.md|package\.json|manifest\.json|requirements\.txt|pyproject\.toml|setup\.py|action\.ya?ml)$/.test(value)) score += 25;
  if (/(mcp|skill|extension|server|tool|agent|workflow|index|main|src)/.test(value)) score += 8;
  if (/\.(js|ts|py|mjs|cjs)$/.test(value)) score += 6;
  return score;
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try { return await fetch(url, { ...options, signal: controller.signal }); }
  finally { clearTimeout(timeout); }
}

async function fetchGithubJson(url) {
  const response = await fetchWithTimeout(url, { headers: githubHeaders() });
  if (!response.ok) throw new Error(`GitHub source lookup failed (${response.status}).`);
  return response.json();
}

async function fetchText(url) {
  const response = await fetchWithTimeout(url, { headers: githubHeaders() });
  if (!response.ok) throw new Error(`GitHub source download failed (${response.status}).`);
  const length = Number(response.headers?.get?.("content-length") || 0);
  if (length > MAX_FILE_CHARS * 2) throw new Error("A source file is too large for automatic scanning.");
  const text = String(await response.text());
  if (text.length > MAX_FILE_CHARS) throw new Error("A source file is too large for a complete automatic scan.");
  return text;
}

async function resolveSupportedSource(classification) {
  const source = parseSupportedSourceReference(classification);
  if (!source) return null;

  if (source.file) {
    const code = await fetchText(source.raw_url);
    if (!code.trim()) throw new Error("The supported source file is empty.");
    return { code, provider: source.provider, source_url: source.source_url, source_owner: source.owner, source_name: `${source.owner}/${source.repo}/${source.path}`, source_ref: source.ref, files: [source.path] };
  }

  const repoApi = `https://api.github.com/repos/${source.owner}/${source.repo}`;
  const repo = source.ref ? null : await fetchGithubJson(repoApi);
  const ref = source.ref || repo?.default_branch || "main";
  const tree = await fetchGithubJson(`${repoApi}/git/trees/${encodeURIComponent(ref)}?recursive=1`);
  const prefix = source.path ? `${source.path.replace(/\/+$/, "")}/` : "";
  const scopedBlobs = (Array.isArray(tree.tree) ? tree.tree : [])
    .filter(item => item.type === "blob" && item.size > 0)
    .filter(item => !prefix || item.path === source.path || item.path.startsWith(prefix) || item.path.includes(`/${prefix}`))
  if (scopedBlobs.some(item => unsupportedExecutablePath(item.path))) {
    throw new Error("The referenced source contains executable or archive files that require a dedicated binary scan.");
  }
  const files = scopedBlobs
    .filter(item => item.size <= MAX_FILE_CHARS)
    .filter(item => usefulSourcePath(item.path))
    .sort((a, b) => sourcePathRank(b.path) - sourcePathRank(a.path) || (a.size || 0) - (b.size || 0));
  if (!files.length) throw new Error("No supported source files were found at the referenced source.");
  if (files.length > MAX_SOURCE_FILES || files.some(item => item.size > MAX_FILE_CHARS)) {
    throw new Error("The referenced source is too large for a complete automatic scan.");
  }

  let code = "";
  const included = [];
  for (const file of files) {
    const text = await fetchText(`https://raw.githubusercontent.com/${source.owner}/${source.repo}/${ref}/${file.path}`);
    const block = `\n\n// Source file: ${file.path}\n${text}`;
    if (code.length + block.length > MAX_SOURCE_CHARS) {
      throw new Error("The referenced source is too large for a complete automatic scan.");
    }
    code += block;
    included.push(file.path);
  }
  if (!code.trim()) throw new Error("The referenced source could not be downloaded safely.");
  return { code: code.trim(), provider: source.provider, source_url: source.source_url, source_owner: source.owner, source_name: `${source.owner}/${source.repo}${source.path ? `/${source.path}` : ""}`, source_ref: ref, files: included };
}

module.exports = { parseSkillsIlCommand, parseGithubUrl, parseSupportedSourceReference, resolveSupportedSource };
