"use strict";

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const { checkTree, stripJsComments, parseCsp } = require("../evals/run-static-privacy-checks");

const repo = path.resolve(__dirname, "..");
const checker = path.join(repo, "evals/run-static-privacy-checks.js");
let passed = 0;
const tests = [];
function test(name, run) { tests.push([name, run]); }

function fixture(mutate) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "safepaste-static-"));
  for (const file of ["index.html", "app.js", "styles.css"]) fs.copyFileSync(path.join(repo, file), path.join(root, file));
  fs.mkdirSync(path.join(root, "src"));
  for (const file of fs.readdirSync(path.join(repo, "src"))) fs.copyFileSync(path.join(repo, "src", file), path.join(root, "src", file));
  if (fs.existsSync(path.join(repo, "cli"))) {
    fs.mkdirSync(path.join(root, "cli"));
    for (const file of fs.readdirSync(path.join(repo, "cli"))) fs.copyFileSync(path.join(repo, "cli", file), path.join(root, "cli", file));
  }
  if (fs.existsSync(path.join(repo, "package.json"))) fs.copyFileSync(path.join(repo, "package.json"), path.join(root, "package.json"));
  try {
    if (mutate) mutate(root);
    return checkTree(root);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}
function append(file, text) { return root => fs.appendFileSync(path.join(root, file), "\n" + text + "\n"); }
function rules(result) { return result.findings.map(finding => finding.rule); }

test("repository production assets pass and are discovered recursively", () => {
  const result = checkTree(repo);
  assert.deepStrictEqual(result.findings, []);
  for (const file of ["index.html", "app.js", "styles.css", "src/sanitizer.js"]) assert(result.files.includes(file), file);
  assert(!result.files.some(file => /^(?:tests|evals|docs|history)\//.test(file)));
  assert.deepStrictEqual(rules(fixture()), []);
});

test("network egress APIs are flagged in nested production JavaScript", () => {
  const cases = {
    NET_FETCH: "fetch('/x');", NET_XHR: "new XMLHttpRequest();", NET_WEBSOCKET: "new WebSocket(u);",
    NET_EVENTSOURCE: "new EventSource(u);", NET_BEACON: "navigator.sendBeacon(u, d);",
    NET_WEBRTC: "new RTCPeerConnection();", NET_SERVICE_WORKER: "navigator.serviceWorker.register('a.js');",
    NET_DYNAMIC_IMPORT: "import('./x.js');", NET_SRC_ASSIGNMENT: "image.src = u;",
    NET_NAVIGATION: "window.open(u);", NET_CROSS_WINDOW: "window.parent.postMessage(d, '*');"
  };
  for (const rule of Object.keys(cases)) {
    assert(rules(fixture(root => {
      fs.mkdirSync(path.join(root, "src/deep/nested"), { recursive: true });
      fs.writeFileSync(path.join(root, "src/deep/nested/extra.js"), cases[rule]);
    })).includes(rule), rule);
  }
});

test("storage, cookies, cache and unsafe DOM sinks are flagged", () => {
  const cases = {
    STORE_LOCAL: "localStorage.setItem('k', v);", STORE_SESSION: "sessionStorage.k = v;",
    STORE_INDEXEDDB: "indexedDB.open('db');", STORE_COOKIE: "document.cookie = v;",
    STORE_CACHE: "caches.open('c');", STORE_FILESYSTEM: "navigator.storage.persist();",
    DOM_INNER_HTML: "el.innerHTML = v;", DOM_OUTER_HTML: "el.outerHTML = v;",
    DOM_INSERT_HTML: "el.insertAdjacentHTML('beforeend', v);", DOM_DOCUMENT_WRITE: "document.write(v);",
    DOM_HTML_PARSER: "new DOMParser();", DOM_EVAL: "eval(v);", DOM_INLINE_STYLE_ATTRIBUTE: "el.setAttribute('style', v);",
    DOM_CONSOLE: "console.log(v);"
  };
  for (const rule of Object.keys(cases)) assert(rules(fixture(append("app.js", cases[rule]))).includes(rule), rule);
});

test("comments are ignored but strings that load remote resources are not", () => {
  assert.deepStrictEqual(rules(fixture(append("app.js", "// fetch(x) innerHTML localStorage\n/* new WebSocket(u) */"))), []);
  assert(stripJsComments("var a = '//'; fetch(a);").includes("fetch(a)"));
  assert(rules(fixture(append("app.js", "var u = 'https://cdn.example.test/x.js';"))).includes("JS_EXTERNAL_URL"));
  assert(rules(fixture(append("app.js", "new Worker('https://cdn.example.test/w.js');"))).includes("JS_NONLOCAL_SCRIPT_LOADER"));
  assert(rules(fixture(append("app.js", "new Worker(url);"))).includes("JS_NONLOCAL_SCRIPT_LOADER"));
  assert(rules(fixture(append("app.js", "new Worker('w.js', { type: 'module' });"))).includes("JS_NONLOCAL_SCRIPT_LOADER"));
  assert(rules(fixture(append("src/sanitizer.js", "importScripts('//cdn.example.test/a.js');"))).includes("JS_NONLOCAL_SCRIPT_LOADER"));
  assert(rules(fixture(append("src/sanitizer.js", "importScripts(name);"))).includes("JS_NONLOCAL_SCRIPT_LOADER"));
});

test("external assets, inline code and embedding in HTML/CSS are flagged", () => {
  const html = (from, to) => root => {
    const file = path.join(root, "index.html");
    fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace(from, to));
  };
  const cases = [
    ["HTML_EXTERNAL_REFERENCE", html("</head>", '<script src="https://cdn.example.test/a.js"></script></head>')],
    ["HTML_EXTERNAL_REFERENCE", html("</head>", '<link rel="stylesheet" href="//fonts.example.test/a.css"></head>')],
    ["HTML_MISSING_LOCAL_ASSET", html("</head>", '<script src="missing.js"></script></head>')],
    ["HTML_INLINE_SCRIPT", html("</body>", "<script>alert(1)</script></body>")],
    ["HTML_INLINE_STYLE", html("</head>", "<style>p{}</style></head>")],
    ["HTML_INLINE_STYLE", html("<body>", '<body style="color:red">')],
    ["HTML_INLINE_HANDLER", html("<body>", '<body onload="x()">')],
    ["HTML_EMBEDDING", html("</body>", '<iframe src="a.html"></iframe></body>')],
    ["HTML_EMBEDDING", html("</body>", '<form action="x"></form></body>')],
    ["HTML_BASE", html("</head>", '<base href="./"></head>')],
    ["HTML_PREFETCH", html("</head>", '<link rel="preconnect" href="x"></head>')],
    ["HTML_JAVASCRIPT_URL", html("</body>", '<a href="javascript:void(0)">x</a></body>')],
    ["HTML_TEXT_FIELD_AUTOCOMPLETE", html("</body>", '<textarea id="extra-log"></textarea></body>')],
    ["HTML_TEXT_FIELD_AUTOCOMPLETE", html("</body>", '<input id="extra-field" type="text"></body>')],
    ["CSS_IMPORT", append("styles.css", "@import 'x.css';")],
    ["CSS_FONT_FACE", append("styles.css", "@font-face { font-family: X; }")],
    ["CSS_URL", append("styles.css", "body { background: url(https://example.test/a.png); }")]
  ];
  for (const [rule, mutate] of cases) assert(rules(fixture(mutate)).includes(rule), rule);
});

test("CSP must be a single early meta with exact restrictive directives and no header-only claims", () => {
  const edit = replace => root => {
    const file = path.join(root, "index.html");
    fs.writeFileSync(file, replace(fs.readFileSync(file, "utf8")));
  };
  const csp = source => source.match(/<meta http-equiv="Content-Security-Policy"[^>]*>/)[0];
  assert(rules(fixture(edit(s => s.replace(csp(s), "")))).includes("CSP_META_COUNT"));
  assert(rules(fixture(edit(s => s.replace(csp(s), csp(s) + csp(s))))).includes("CSP_META_COUNT"));
  assert(rules(fixture(edit(s => s.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")))).includes("CSP_UNSAFE_SOURCE"));
  assert(rules(fixture(edit(s => s.replace("connect-src 'none'", "connect-src 'self'")))).includes("CSP_REQUIRED_DIRECTIVE"));
  assert(rules(fixture(edit(s => s.replace("object-src 'none'; ", "")))).includes("CSP_REQUIRED_DIRECTIVE"));
  assert(rules(fixture(edit(s => s.replace("img-src 'self'", "img-src 'self' https://cdn.example.test")))).includes("CSP_UNSAFE_SOURCE"));
  assert(rules(fixture(edit(s => s.replace("form-action 'none'", "form-action 'none'; frame-ancestors 'none'")))).includes("CSP_HEADER_ONLY_IN_META"));
  assert(rules(fixture(edit(s => s.replace("connect-src 'none'", "connect-src 'none'; connect-src *")))).includes("CSP_DUPLICATE_DIRECTIVE"));
  assert(rules(fixture(edit(s => s.replace(csp(s), "").replace("</head>", csp(s) + "</head>")))).includes("CSP_AFTER_RESOURCE"));
  const directives = parseCsp(fs.readFileSync(path.join(repo, "index.html"), "utf8").match(/content="(default-src[^"]*)"/)[1]);
  assert.deepStrictEqual(directives["connect-src"].sources, ["'none'"]);
  assert.deepStrictEqual(directives["default-src"].sources, ["'self'"]);
});

test("CLI must not use network modules, eval or non-exclusive writes; package has no dependencies", () => {
  const cli = text => root => {
    fs.mkdirSync(path.join(root, "cli"), { recursive: true });
    fs.writeFileSync(path.join(root, "cli/extra.js"), text);
  };
  assert(rules(fixture(cli("require('https');"))).includes("CLI_NETWORK_MODULE"));
  assert(rules(fixture(cli("require(\"node:child_process\");"))).includes("CLI_NETWORK_MODULE"));
  assert(rules(fixture(cli("fs.writeFileSync(p, d);"))).includes("CLI_UNSAFE_WRITE"));
  assert(rules(fixture(cli("fs.openSync(p, 'w');"))).includes("CLI_NON_EXCLUSIVE_OPEN"));
  assert(rules(fixture(cli("fetch(u);"))).includes("CLI_NETWORK_API"));
  assert.deepStrictEqual(rules(fixture(cli("fs.openSync(p, 'wx', 0o600);"))), []);
  const pkg = data => root => fs.writeFileSync(path.join(root, "package.json"), JSON.stringify(data));
  assert(rules(fixture(pkg({ dependencies: { x: "1" } }))).includes("PACKAGE_DEPENDENCY"));
  assert(rules(fixture(pkg({ scripts: { postinstall: "node x" } }))).includes("PACKAGE_INSTALL_SCRIPT"));
  assert(rules(fixture(pkg({ scripts: { test: "npx thing" } }))).includes("PACKAGE_NETWORK_SCRIPT"));
});

test("symlinked production assets and missing required assets fail closed", () => {
  assert(rules(fixture(root => fs.symlinkSync("/etc/hostname", path.join(root, "src/link.js")))).includes("ASSET_SYMLINK"));
  assert(rules(fixture(root => fs.rmSync(path.join(root, "styles.css")))).includes("ASSET_MISSING"));
});

test("command output reports rule ids/locations only, never matched source", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "safepaste-static-cli-"));
  try {
    for (const file of ["index.html", "styles.css"]) fs.copyFileSync(path.join(repo, file), path.join(root, file));
    fs.mkdirSync(path.join(root, "src"));
    fs.copyFileSync(path.join(repo, "src/sanitizer.js"), path.join(root, "src/sanitizer.js"));
    if (fs.existsSync(path.join(repo, "src/worker.js"))) fs.copyFileSync(path.join(repo, "src/worker.js"), path.join(root, "src/worker.js"));
    fs.writeFileSync(path.join(root, "app.js"), "localStorage.setItem('SYNTHETIC_MARKER_VALUE', 1);\n");
    const run = spawnSync(process.execPath, [checker, "--root", root], { encoding: "utf8" });
    assert.strictEqual(run.status, 1);
    assert(/FAIL STORE_LOCAL app\.js:1/.test(run.stderr));
    assert(!(run.stdout + run.stderr).includes("SYNTHETIC_MARKER_VALUE"));
    const clean = spawnSync(process.execPath, [checker], { encoding: "utf8" });
    assert.strictEqual(clean.status, 0, clean.stderr);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

for (const [name, run] of tests) {
  try { run(); passed += 1; console.log("PASS static privacy: " + name); }
  catch (error) { console.error("FAIL static privacy: " + name + "\n" + error.stack); }
}
console.log(passed + "/" + tests.length + " static privacy checker tests passed");
if (passed !== tests.length) process.exitCode = 1;
