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

function parseNpmCommand(value) {
  const text = String(value || "").trim();
  const match = text.match(/^(?:npx|bunx|npm\s+(?:exec|install|i)|pnpm\s+(?:dlx|add|install)|yarn\s+(?:dlx|add))\s+(?:--?[a-z0-9_.-]+(?:=\S+)?\s+)*((?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)(?:@([a-z0-9_.-]+))?(?:\s|$)/i);
  if (!match || match[1] === "skills-il") return null;
  return { provider: "npm", package_name: match[1], version: match[2] || "", source_url: `https://www.npmjs.com/package/${match[1]}` };
}

function parseNpmReference(value) {
  const text = String(value || "").trim();
  const page = text.match(/^https:\/\/(?:www\.)?npmjs\.com\/package\/((?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)(?:\/v\/([a-z0-9_.-]+))?\/?$/i);
  const reference = text.match(/^((?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+)@([a-z0-9_.-]+)$/i);
  const match = page || reference;
  if (!match) return null;
  return { provider: "npm", package_name: match[1], version: match[2] || "", source_url: `https://www.npmjs.com/package/${match[1]}` };
}

function parsePypiCommand(value) {
  const text = String(value || "").trim();
  const match = text.match(/^(?:pipx?\s+install|python\s+-m\s+pip\s+install|uvx)\s+(?:--?[a-z0-9_.-]+(?:=\S+)?\s+)*([a-z0-9_.-]+)(?:(?:==|@)([a-z0-9_.+-]+))?(?:\s|$)/i);
  if (!match) return null;
  return { provider: "pypi", package_name: match[1], version: match[2] || "", source_url: `https://pypi.org/project/${match[1]}/` };
}

function parsePypiUrl(value) {
  const match = String(value || "").trim().match(/^https:\/\/pypi\.org\/project\/([a-z0-9_.-]+)(?:\/([a-z0-9_.+-]+))?\/?$/i);
  if (!match) return null;
  return { provider: "pypi", package_name: match[1], version: match[2] || "", source_url: `https://pypi.org/project/${match[1]}/` };
}

function parseIdeExtensionReference(value) {
  const text = String(value || "").trim();
  const command = text.match(/^(?:code|code-insiders|codium|cursor)\s+--install-extension\s+([a-z0-9_.-]+)\.([a-z0-9_.-]+)(?:@([a-z0-9_.-]+))?(?:\s|$)/i);
  if (command) return { provider: "open_vsx", publisher: command[1], extension: command[2], version: command[3] || "", source_url: `https://open-vsx.org/extension/${command[1]}/${command[2]}` };

  let url;
  try { url = new URL(text); } catch { return null; }
  if (url.protocol !== "https:") return null;
  if (url.hostname === "open-vsx.org") {
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts[0] === "extension" && safeSegment(parts[1]) && safeSegment(parts[2])) {
      return { provider: "open_vsx", publisher: parts[1], extension: parts[2], version: parts[3] && safeSegment(parts[3]) ? parts[3] : "", source_url: `https://open-vsx.org/extension/${parts[1]}/${parts[2]}` };
    }
  }
  if (url.hostname === "marketplace.visualstudio.com") {
    const id = url.searchParams.get("itemName") || "";
    const match = id.match(/^([a-z0-9_.-]+)\.([a-z0-9_.-]+)$/i);
    if (match) return { provider: "vs_marketplace", publisher: match[1], extension: match[2], version: "", source_url: url.toString() };
  }
  return null;
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
  return parseSkillsIlCommand(reference) || parseNpmCommand(reference) || parsePypiCommand(reference) || parseNpmReference(reference) || parsePypiUrl(reference) || parseIdeExtensionReference(reference) || parseGithubUrl(reference);
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

function trustedArtifactHost(hostname, allowedHosts) {
  return allowedHosts.some(host => hostname === host || (host.startsWith("*.") && hostname.endsWith(host.slice(1))));
}

async function fetchBuffer(url, allowedHost, maxBytes) {
  const allowedHosts = Array.isArray(allowedHost) ? allowedHost : [allowedHost];
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || !trustedArtifactHost(parsed.hostname, allowedHosts)) throw new Error("The package artifact host is not trusted.");
  const response = await fetchWithTimeout(url);
  if (!response.ok) throw new Error(`Package artifact download failed (${response.status}).`);
  if (!trustedArtifactHost(new URL(response.url || url).hostname, allowedHosts)) throw new Error("The package artifact redirected to an untrusted host.");
  const length = Number(response.headers?.get?.("content-length") || 0);
  if (length > maxBytes) throw new Error("The package artifact is too large for a complete automatic scan.");
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxBytes) throw new Error("The package artifact is too large for a complete automatic scan.");
  return bytes;
}

function verifyDigest(bytes, algorithm, expected, encoding = "hex") {
  if (!expected) return;
  const actual = crypto.createHash(algorithm).update(bytes).digest(encoding);
  if (actual !== expected) throw new Error("The downloaded package artifact failed its integrity check.");
}

function extractTarTextFiles(bytes, prefixToStrip = "") {
  const output = [];
  let offset = 0;
  let totalChars = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) break;
    const name = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const prefix = header.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
    const path = `${prefix ? `${prefix}/` : ""}${name}`.replace(/^\.?\//, "");
    const sizeText = header.subarray(124, 136).toString("ascii").replace(/\0.*$/, "").trim();
    const size = parseInt(sizeText || "0", 8);
    const type = header.subarray(156, 157).toString("ascii");
    const start = offset + 512;
    const end = start + size;
    if (!Number.isFinite(size) || size < 0 || end > bytes.length) throw new Error("The package archive is malformed.");
    const cleanPath = prefixToStrip && path.startsWith(prefixToStrip) ? path.slice(prefixToStrip.length) : path;
    if ((type === "" || type === "0" || type === "\0") && usefulSourcePath(cleanPath)) {
      if (unsupportedExecutablePath(cleanPath)) throw new Error("The package contains executable files requiring a dedicated binary scan.");
      if (size > MAX_FILE_CHARS) throw new Error("A package source file is too large for a complete automatic scan.");
      const text = bytes.subarray(start, end).toString("utf8");
      totalChars += text.length;
      if (totalChars > MAX_SOURCE_CHARS || output.length >= MAX_SOURCE_FILES) throw new Error("The package is too large for a complete automatic scan.");
      output.push({ path: cleanPath, text });
    }
    offset = start + Math.ceil(size / 512) * 512;
  }
  if (!output.length) throw new Error("No supported source files were found in the package artifact.");
  return output;
}

function joinedSource(files) {
  return files.map(file => `// Source file: ${file.path}\n${file.text}`).join("\n\n");
}

function extensionVersion(files, fallback) {
  const manifest = files.find(file => /(^|\/)package\.json$/i.test(file.path));
  if (!manifest) return fallback;
  try { return String(JSON.parse(manifest.text)?.version || fallback); }
  catch { return fallback; }
}

function extractZipTextFiles(bytes, prefixToStrip = "") {
  const signature = Buffer.from([0x50, 0x4b, 0x05, 0x06]);
  const eocdOffset = bytes.lastIndexOf(signature);
  if (eocdOffset < 0 || eocdOffset + 22 > bytes.length) throw new Error("The extension package is not a valid VSIX archive.");
  const entryCount = bytes.readUInt16LE(eocdOffset + 10);
  const directoryOffset = bytes.readUInt32LE(eocdOffset + 16);
  if (entryCount > 5000) throw new Error("The extension archive contains too many files.");

  const files = [];
  let cursor = directoryOffset;
  let totalChars = 0;
  for (let index = 0; index < entryCount; index += 1) {
    if (cursor + 46 > bytes.length || bytes.readUInt32LE(cursor) !== 0x02014b50) throw new Error("The extension archive directory is malformed.");
    const method = bytes.readUInt16LE(cursor + 10);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const uncompressedSize = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const archivePath = bytes.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8").replace(/\\/g, "/");
    cursor += 46 + nameLength + extraLength + commentLength;

    if (!archivePath || archivePath.includes("../") || archivePath.startsWith("/") || unsupportedExecutablePath(archivePath)) {
      if (unsupportedExecutablePath(archivePath)) throw new Error("The extension contains executable files requiring a dedicated binary scan.");
      continue;
    }
    const path = prefixToStrip && archivePath.startsWith(prefixToStrip) ? archivePath.slice(prefixToStrip.length) : archivePath;
    if (!usefulSourcePath(path)) continue;
    if (uncompressedSize > MAX_FILE_CHARS || files.length >= MAX_SOURCE_FILES) throw new Error("The extension is too large for a complete automatic scan.");
    if (localOffset + 30 > bytes.length || bytes.readUInt32LE(localOffset) !== 0x04034b50) throw new Error("The extension archive entry is malformed.");
    const localNameLength = bytes.readUInt16LE(localOffset + 26);
    const localExtraLength = bytes.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > bytes.length) throw new Error("The extension archive entry is incomplete.");
    const compressed = bytes.subarray(dataStart, dataEnd);
    let content;
    if (method === 0) content = compressed;
    else if (method === 8) content = zlib.inflateRawSync(compressed, { maxOutputLength: MAX_FILE_CHARS + 1 });
    else throw new Error("The extension archive uses an unsupported compression method.");
    if (content.length !== uncompressedSize || content.length > MAX_FILE_CHARS) throw new Error("The extension archive failed its size verification.");
    const text = content.toString("utf8");
    totalChars += text.length;
    if (totalChars > MAX_SOURCE_CHARS) throw new Error("The extension is too large for a complete automatic scan.");
    files.push({ path, text });
  }
  if (!files.length) throw new Error("No supported source files were found in the extension package.");
  return files;
}

async function resolveOpenVsxExtension(source) {
  const metadataUrl = source.version
    ? `https://open-vsx.org/api/${source.publisher}/${source.extension}/${source.version}`
    : `https://open-vsx.org/api/${source.publisher}/${source.extension}/latest`;
  const response = await fetchWithTimeout(metadataUrl, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(`Open VSX extension lookup failed (${response.status}).`);
  const metadata = await response.json();
  const version = metadata.version;
  const download = metadata?.files?.download;
  if (!version || !download) throw new Error("The requested Open VSX extension package was not found.");
  const bytes = await fetchBuffer(download, ["open-vsx.org", "openvsx.eclipsecontent.org"], 12 * 1024 * 1024);
  const files = extractZipTextFiles(bytes, "extension/");
  const scannedVersion = extensionVersion(files, version);
  return { code: joinedSource(files), provider: "open_vsx", source_url: `https://open-vsx.org/extension/${source.publisher}/${source.extension}/${scannedVersion}`, source_owner: source.publisher, source_name: `${source.publisher}.${source.extension}@${scannedVersion}`, source_ref: scannedVersion, files: files.map(file => file.path) };
}

async function resolveVsMarketplaceExtension(source) {
  const version = source.version || "latest";
  const download = `https://marketplace.visualstudio.com/_apis/public/gallery/publishers/${source.publisher}/vsextensions/${source.extension}/${version}/vspackage`;
  const bytes = await fetchBuffer(download, ["marketplace.visualstudio.com", "*.vsassets.io"], 12 * 1024 * 1024);
  const files = extractZipTextFiles(bytes, "extension/");
  const scannedVersion = extensionVersion(files, version);
  return { code: joinedSource(files), provider: "vs_marketplace", source_url: source.source_url, source_owner: source.publisher, source_name: `${source.publisher}.${source.extension}@${scannedVersion}`, source_ref: scannedVersion, files: files.map(file => file.path) };
}

async function resolveNpmPackage(source) {
  const metadataResponse = await fetchWithTimeout(`https://registry.npmjs.org/${encodeURIComponent(source.package_name)}`, { headers: { Accept: "application/json" } });
  if (!metadataResponse.ok) throw new Error(`npm package lookup failed (${metadataResponse.status}).`);
  const metadata = await metadataResponse.json();
  const version = source.version || metadata?.["dist-tags"]?.latest;
  const release = metadata?.versions?.[version];
  if (!release?.dist?.tarball) throw new Error("The requested npm package version was not found.");
  const bytes = await fetchBuffer(release.dist.tarball, "registry.npmjs.org", 4 * 1024 * 1024);
  if (release.dist.integrity?.startsWith("sha512-")) verifyDigest(bytes, "sha512", release.dist.integrity.slice(7), "base64");
  else verifyDigest(bytes, "sha1", release.dist.shasum);
  const files = extractTarTextFiles(zlib.gunzipSync(bytes), "package/");
  return { code: joinedSource(files), provider: "npm", source_url: `${source.source_url}/v/${version}`, source_owner: String(release.author?.name || ""), source_name: `${source.package_name}@${version}`, source_ref: version, files: files.map(file => file.path) };
}

async function resolvePypiPackage(source) {
  const route = source.version
    ? `${encodeURIComponent(source.package_name)}/${encodeURIComponent(source.version)}`
    : encodeURIComponent(source.package_name);
  const metadataResponse = await fetchWithTimeout(`https://pypi.org/pypi/${route}/json`, { headers: { Accept: "application/json" } });
  if (!metadataResponse.ok) throw new Error(`PyPI package lookup failed (${metadataResponse.status}).`);
  const metadata = await metadataResponse.json();
  const version = metadata?.info?.version;
  const artifact = (metadata?.urls || []).find(item => item.packagetype === "sdist" && String(item.filename || "").endsWith(".tar.gz"));
  if (!artifact?.url) throw new Error("This PyPI release has no supported source distribution to scan.");
  const bytes = await fetchBuffer(artifact.url, "files.pythonhosted.org", 4 * 1024 * 1024);
  verifyDigest(bytes, "sha256", artifact?.digests?.sha256);
  const files = extractTarTextFiles(zlib.gunzipSync(bytes));
  return { code: joinedSource(files), provider: "pypi", source_url: `https://pypi.org/project/${source.package_name}/${version}/`, source_owner: String(metadata?.info?.author || ""), source_name: `${source.package_name}==${version}`, source_ref: version, files: files.map(file => file.path) };
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
  if (source.provider === "npm") return resolveNpmPackage(source);
  if (source.provider === "pypi") return resolvePypiPackage(source);
  if (source.provider === "open_vsx") return resolveOpenVsxExtension(source);
  if (source.provider === "vs_marketplace") return resolveVsMarketplaceExtension(source);

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

module.exports = { parseSkillsIlCommand, parseNpmCommand, parseNpmReference, parsePypiCommand, parsePypiUrl, parseIdeExtensionReference, parseGithubUrl, parseSupportedSourceReference, resolveSupportedSource };
const crypto = require("crypto");
const zlib = require("zlib");
