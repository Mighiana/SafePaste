"use strict";

// Static zero-egress / no-persistence / safe-DOM / CSP checks for production assets.
// Reports rule ids and file:line only; matched source text is never printed.
const fs = require("fs");
const path = require("path");

const EXCLUDED_DIRS = new Set([".git", ".github", ".claude", "node_modules", "history", "tests", "evals", "docs"]);
const PRODUCTION_EXTENSIONS = new Set([".html", ".js", ".mjs", ".cjs", ".css", ".json"]);
const REQUIRED_ASSETS = ["index.html", "app.js", "styles.css", "src/sanitizer.js"];

const NETWORK = [
  ["NET_FETCH", /\bfetch\s*\(/],
  ["NET_XHR", /\bXMLHttpRequest\b/],
  ["NET_WEBSOCKET", /\bWebSocket\b/],
  ["NET_EVENTSOURCE", /\bEventSource\b/],
  ["NET_BEACON", /\bsendBeacon\b/],
  ["NET_WEBRTC", /\bRTC(?:PeerConnection|DataChannel)\b/],
  ["NET_WEBTRANSPORT", /\bWebTransport\b/],
  ["NET_SERVICE_WORKER", /\bserviceWorker\b/],
  ["NET_DYNAMIC_IMPORT", /\bimport\s*\(/],
  ["NET_SRC_ASSIGNMENT", /\.(?:src|srcset|action|formAction|ping)\s*=[^=]/],
  ["NET_NAVIGATION", /\b(?:location\s*\.\s*(?:assign|replace|href)|window\.open)\b/],
  ["NET_CROSS_WINDOW", /\b(?:opener|parent|top)\s*\.\s*postMessage\b/],
  ["NET_FORM_SUBMIT", /\.(?:submit|requestSubmit)\s*\(/]
];
const STORAGE = [
  ["STORE_LOCAL", /\blocalStorage\b/],
  ["STORE_SESSION", /\bsessionStorage\b/],
  ["STORE_INDEXEDDB", /\bindexedDB\b|\bIDB[A-Z]\w*/],
  ["STORE_COOKIE", /\bdocument\s*\.\s*cookie\b|\bcookieStore\b/],
  ["STORE_CACHE", /\bcaches\s*\.|\bCacheStorage\b/],
  ["STORE_FILESYSTEM", /\b(?:navigator\s*\.\s*storage|requestFileSystem|webkitRequestFileSystem|showSaveFilePicker|showDirectoryPicker|openDatabase)\b/]
];
const UNSAFE_DOM = [
  ["DOM_INNER_HTML", /\binnerHTML\b/],
  ["DOM_OUTER_HTML", /\bouterHTML\b/],
  ["DOM_INSERT_HTML", /\binsertAdjacentHTML\b/],
  ["DOM_DOCUMENT_WRITE", /\bdocument\s*\.\s*write(?:ln)?\b/],
  ["DOM_HTML_PARSER", /\b(?:createContextualFragment|DOMParser|srcdoc|setHTMLUnsafe|parseHTMLUnsafe)\b/],
  ["DOM_EVAL", /\beval\s*\(|\bnew\s+Function\b|\bset(?:Timeout|Interval)\s*\(\s*["'`]/],
  ["DOM_INLINE_STYLE_ATTRIBUTE", /setAttribute\s*\(\s*["'](?:style|on\w+)["']/i],
  ["DOM_CONSOLE", /\bconsole\s*\.\s*\w+\s*\(/]
];
const NODE_NETWORK_MODULES = ["http", "https", "http2", "net", "tls", "dgram", "dns", "child_process", "cluster", "inspector", "worker_threads"];
const CLI_RULES = [
  ["CLI_NETWORK_MODULE", new RegExp("\\brequire\\s*\\(\\s*[\"'](?:node:)?(?:" + NODE_NETWORK_MODULES.join("|") + ")[\"']\\s*\\)")],
  ["CLI_NETWORK_API", /\bfetch\s*\(|\bWebSocket\b|\bimport\s*\(/],
  ["CLI_UNSAFE_WRITE", /\b(?:writeFileSync|writeFile|appendFile(?:Sync)?|createWriteStream|copyFile(?:Sync)?|rename(?:Sync)?|symlink(?:Sync)?|truncate(?:Sync)?)\s*\(/],
  ["CLI_NON_EXCLUSIVE_OPEN", /\bopenSync\s*\((?![^)]*["']wx["'])(?![^)]*["']r["'])/],
  ["CLI_EVAL", /\beval\s*\(|\bnew\s+Function\b|\bvm\b\s*\./]
];
const REQUIRED_CSP = {
  "default-src": ["'self'"], "script-src": ["'self'"], "style-src": ["'self'"], "connect-src": ["'none'"],
  "object-src": ["'none'"], "base-uri": ["'none'"], "form-action": ["'none'"], "frame-src": ["'none'"],
  "child-src": ["'none'"], "font-src": ["'none'"], "worker-src": ["'self'"], "img-src": ["'self'"],
  "media-src": ["'none'"], "manifest-src": ["'none'"]
};
// Directives browsers ignore when delivered through <meta>; claiming them in meta would be misleading.
const HEADER_ONLY_CSP = ["frame-ancestors", "report-uri", "report-to", "sandbox"];
const UNSAFE_SOURCES = /^(?:'unsafe-inline'|'unsafe-eval'|'unsafe-hashes'|'wasm-unsafe-eval'|'strict-dynamic'|\*|data:|blob:|filesystem:|https?:|ws:|wss:|.*\..*)$/i;

function walk(root, relative, files) {
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    const child = relative ? relative + "/" + entry.name : entry.name;
    if (entry.isSymbolicLink()) { files.push({ file: child, symlink: true }); continue; }
    if (entry.isDirectory()) { if (!EXCLUDED_DIRS.has(entry.name)) walk(root, child, files); continue; }
    if (PRODUCTION_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) files.push({ file: child });
  }
  return files;
}

function stripJsComments(source) {
  // Blank comments while keeping line numbers; string contents are kept so loaded URLs stay visible.
  let out = "";
  let i = 0;
  let quote = null;
  while (i < source.length) {
    const c = source[i];
    const next = source[i + 1];
    if (quote) {
      out += c;
      if (c === "\\") { out += next || ""; i += 2; continue; }
      if (c === quote || (c === "\n" && quote !== "`")) quote = null;
      i += 1;
      continue;
    }
    if (c === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") { out += " "; i += 1; }
      continue;
    }
    if (c === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end < 0 ? source.length : end + 2;
      out += source.slice(i, stop).replace(/[^\n]/g, " ");
      i = stop;
      continue;
    }
    if (c === "\"" || c === "'" || c === "`") quote = c;
    out += c;
    i += 1;
  }
  return out;
}

function lineOf(source, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (source.charCodeAt(i) === 10) line += 1;
  return line;
}

function scanRules(findings, file, source, rules) {
  for (const [rule, pattern] of rules) {
    const global = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g");
    let match;
    while ((match = global.exec(source))) {
      findings.push({ rule, file, line: lineOf(source, match.index) });
      if (!match[0].length) global.lastIndex += 1;
    }
  }
}

function isLocalReference(value) {
  return !!value && !/^(?:[a-z][a-z0-9+.-]*:|\/\/|\\)/i.test(value) && !/(?:^|\/)\.\.(?:\/|$)/.test(value);
}

function parseCsp(content) {
  const directives = {};
  for (const part of content.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    if (Object.prototype.hasOwnProperty.call(directives, name)) directives[name].duplicate = true;
    else directives[name] = { sources: tokens.slice(1) };
  }
  return directives;
}

function checkHtml(findings, file, source, root) {
  const add = (rule, index) => findings.push({ rule, file, line: lineOf(source, index || 0) });
  const metas = Array.from(source.matchAll(/<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi));
  if (file === "index.html" && metas.length !== 1) add("CSP_META_COUNT", metas[0] && metas[0].index);
  for (const meta of metas) {
    const content = (meta[0].match(/\bcontent\s*=\s*"([^"]*)"/i) || [])[1];
    if (content === undefined) { add("CSP_UNPARSEABLE", meta.index); continue; }
    const firstLoad = source.search(/<(?:script|link|style|img|iframe|object|embed)\b/i);
    if (firstLoad >= 0 && firstLoad < meta.index) add("CSP_AFTER_RESOURCE", meta.index);
    const directives = parseCsp(content);
    for (const name of Object.keys(directives)) {
      if (directives[name].duplicate) add("CSP_DUPLICATE_DIRECTIVE", meta.index);
      if (HEADER_ONLY_CSP.includes(name)) add("CSP_HEADER_ONLY_IN_META", meta.index);
      if (directives[name].sources.some(sourceToken => UNSAFE_SOURCES.test(sourceToken))) add("CSP_UNSAFE_SOURCE", meta.index);
    }
    for (const name of Object.keys(REQUIRED_CSP)) {
      const actual = directives[name] ? directives[name].sources.join(" ") : null;
      if (actual !== REQUIRED_CSP[name].join(" ")) add("CSP_REQUIRED_DIRECTIVE", meta.index);
    }
  }
  for (const match of source.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/.test(match[1]) || match[2].trim()) add("HTML_INLINE_SCRIPT", match.index);
    if (/\btype\s*=\s*["']?module/i.test(match[1])) add("HTML_MODULE_SCRIPT", match.index);
  }
  scanRules(findings, file, source, [
    ["HTML_INLINE_STYLE", /<style\b|\sstyle\s*=/i],
    ["HTML_INLINE_HANDLER", /<[^>]+\son[a-z]+\s*=/i],
    ["HTML_JAVASCRIPT_URL", /javascript\s*:/i],
    ["HTML_EMBEDDING", /<(?:iframe|frame|object|embed|applet|portal|form)\b/i],
    ["HTML_BASE", /<base\b/i],
    ["HTML_REFRESH", /http-equiv\s*=\s*["']?refresh/i],
    ["HTML_PREFETCH", /<link\b[^>]*rel\s*=\s*["']?[^"'>]*(?:preconnect|dns-prefetch|prefetch|prerender|preload|modulepreload|manifest|icon)/i],
    ["HTML_PING", /\sping\s*=/i]
  ]);
  for (const match of source.matchAll(/\s(src|href|srcset|action|formaction|poster|data|background)\s*=\s*["']([^"']*)["']/gi)) {
    const value = match[2].trim();
    if (match[1].toLowerCase() === "href" && value.startsWith("#")) continue;
    if (!isLocalReference(value)) { add("HTML_EXTERNAL_REFERENCE", match.index); continue; }
    if (/^(?:src|href)$/i.test(match[1]) && root && !fs.existsSync(path.join(root, path.dirname(file), value))) add("HTML_MISSING_LOCAL_ASSET", match.index);
  }
}

function checkCss(findings, file, source) {
  scanRules(findings, file, source, [
    ["CSS_IMPORT", /@import\b/i],
    ["CSS_FONT_FACE", /@font-face\b/i],
    ["CSS_URL", /\burl\s*\(/i],
    ["CSS_IMAGE_SET", /\bimage-set\s*\(/i]
  ]);
}

function checkScriptLoaders(findings, file, source) {
  for (const match of source.matchAll(/\b(importScripts|new\s+(?:Shared)?Worker)\s*\(([^)]*)\)/g)) {
    const args = match[2].trim();
    const literals = Array.from(args.matchAll(/^\s*["']([^"']+)["']\s*(?:,|$)/g));
    const valid = /importScripts/.test(match[1])
      ? args.split(",").every(arg => /^\s*["'][^"']+["']\s*$/.test(arg) && isLocalReference(arg.trim().slice(1, -1)))
      : literals.length === 1 && isLocalReference(literals[0][1]) && !/type\s*:\s*["']module/.test(args);
    if (!valid) findings.push({ rule: "JS_NONLOCAL_SCRIPT_LOADER", file, line: lineOf(source, match.index) });
  }
  scanRules(findings, file, source, [["JS_EXTERNAL_URL", /["'`]\s*(?:https?:|wss?:|\/\/[a-z0-9])/i]]);
}

function checkTree(root) {
  const findings = [];
  const files = walk(root, "", []);
  const listed = new Set(files.map(entry => entry.file));
  for (const required of REQUIRED_ASSETS) {
    if (!listed.has(required)) findings.push({ rule: "ASSET_MISSING", file: required, line: 0 });
  }
  for (const entry of files) {
    if (entry.symlink) { findings.push({ rule: "ASSET_SYMLINK", file: entry.file, line: 0 }); continue; }
    const raw = fs.readFileSync(path.join(root, entry.file), "utf8");
    const extension = path.extname(entry.file).toLowerCase();
    if (extension === ".html") checkHtml(findings, entry.file, raw, root);
    else if (extension === ".css") checkCss(findings, entry.file, raw);
    else if (extension === ".json") {
      if (entry.file === "package.json") checkPackage(findings, entry.file, raw);
    } else if (/^(?:cli|bin)\//.test(entry.file)) {
      const source = stripJsComments(raw);
      scanRules(findings, entry.file, source, CLI_RULES);
    } else {
      const source = stripJsComments(raw);
      scanRules(findings, entry.file, source, NETWORK.concat(STORAGE, UNSAFE_DOM));
      checkScriptLoaders(findings, entry.file, source);
    }
  }
  return { files: files.map(entry => entry.file), findings };
}

function checkPackage(findings, file, raw) {
  let data;
  try { data = JSON.parse(raw); } catch (error) { findings.push({ rule: "PACKAGE_INVALID_JSON", file, line: 0 }); return; }
  for (const key of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies", "bundleDependencies"]) {
    if (data[key] && Object.keys(data[key]).length) findings.push({ rule: "PACKAGE_DEPENDENCY", file, line: 0 });
  }
  const scripts = data.scripts || {};
  for (const name of Object.keys(scripts)) {
    if (/^(?:pre|post)?install$|^prepare$|^prepublish/.test(name)) findings.push({ rule: "PACKAGE_INSTALL_SCRIPT", file, line: 0 });
    if (/\b(?:curl|wget|npx|npm\s+(?:i|install|exec)|pnpm|yarn)\b/.test(scripts[name])) findings.push({ rule: "PACKAGE_NETWORK_SCRIPT", file, line: 0 });
  }
}

function main() {
  const index = process.argv.indexOf("--root");
  const root = path.resolve(index > 0 && process.argv[index + 1] ? process.argv[index + 1] : path.join(__dirname, ".."));
  let result;
  try { result = checkTree(root); } catch (error) {
    console.error("FAIL static privacy checks: unable to read production assets (" + (error.code || "ERROR") + ")");
    process.exitCode = 1;
    return;
  }
  for (const finding of result.findings) console.error("FAIL " + finding.rule + " " + finding.file + ":" + finding.line);
  console.log("Scanned " + result.files.length + " production assets: " + result.files.join(", "));
  if (result.findings.length) {
    console.log(result.findings.length + " static privacy/security finding(s); see rule ids above");
    process.exitCode = 1;
  } else {
    console.log("PASS static privacy checks: network APIs, storage/cookies/cache, unsafe DOM, external assets, script loaders, CSP, CLI writes");
  }
}

module.exports = { checkTree, parseCsp, stripJsComments, REQUIRED_CSP, HEADER_ONLY_CSP };
if (require.main === module) main();
