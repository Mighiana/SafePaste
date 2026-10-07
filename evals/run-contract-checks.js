"use strict";
// Dependency-free syntax, lint-like and type-contract checks (no TypeScript, no linters).
// 1. Syntax: every tracked .js file passes `node --check`; every tracked .json parses.
// 2. Lint-like: LF endings, no trailing whitespace or tab indentation, final newline,
//    production JS is strict mode with no var/eval/new Function/debugger/console output.
// 3. Contracts: exact key sets and value types of the public engine API, findings, reports,
//    detector catalog, policies, session, legacy sanitize(), worker messages and CLI exports.
// Inputs are synthetic. Usage: node evals/run-contract-checks.js
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const ROOT = path.resolve(__dirname, "..");
const SKIP_DIRS = new Set([".git", "node_modules", "history"]);
const TEXT_EXT = /\.(?:js|json|html|css|md|yml|yaml|sh)$/;
const PRODUCTION_JS = ["src/sanitizer.js", "src/worker.js", "app.js", "bin/safepaste.js"];
const results = [];
function check(name, run) {
  try { const detail = run(); results.push([true, name, detail || ""]); }
  catch (error) { results.push([false, name, error.message]); }
}
function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) { if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out); }
    else if (TEXT_EXT.test(entry.name)) out.push(path.relative(ROOT, path.join(dir, entry.name)).split(path.sep).join("/"));
  }
  return out;
}
const files = walk(ROOT, []).sort();
const read = (file) => fs.readFileSync(path.join(ROOT, file), "utf8");

check("syntax: node --check on every .js file", () => {
  const js = files.filter((f) => f.endsWith(".js"));
  const bad = js.filter((f) => spawnSync(process.execPath, ["--check", path.join(ROOT, f)]).status !== 0);
  if (bad.length) throw new Error("syntax errors: " + bad.join(", "));
  return js.length + " files";
});
check("syntax: every .json file parses", () => {
  const json = files.filter((f) => f.endsWith(".json"));
  for (const f of json) { try { JSON.parse(read(f)); } catch (error) { throw new Error(f + ": " + error.message); } }
  return json.length + " files";
});
check("lint: LF endings, no trailing whitespace, no tab indentation, final newline", () => {
  const problems = [];
  for (const f of files) {
    const text = read(f);
    if (text.includes("\r")) problems.push(f + " CR");
    text.split("\n").forEach((line, i) => {
      if (/[ \t]+$/.test(line)) problems.push(f + ":" + (i + 1) + " trailing whitespace");
      if (/^\t/.test(line)) problems.push(f + ":" + (i + 1) + " tab indentation");
    });
    if (text.length && !text.endsWith("\n")) problems.push(f + " no final newline");
  }
  if (problems.length) throw new Error(problems.slice(0, 10).join("; "));
  return files.length + " text files";
});
check("lint: production JS is strict and avoids var/eval/new Function/debugger/console", () => {
  const problems = [];
  for (const f of PRODUCTION_JS) {
    const code = read(f);
    if (!/["']use strict["'];/.test(code)) problems.push(f + " missing 'use strict'");
    for (const [label, pattern] of [["var", /(^|[^.\w$])var\s/m], ["eval", /\beval\s*\(/], ["new Function", /\bnew\s+Function\b/],
      ["debugger", /\bdebugger\b/], ["console", /\bconsole\.\w+\s*\(/]]) {
      if (pattern.test(code)) problems.push(f + " uses " + label);
    }
  }
  if (problems.length) throw new Error(problems.join("; "));
  return PRODUCTION_JS.length + " files";
});

// Minimal structural type checker: exact keys, primitive types, enums, nested shapes.
function conform(value, spec, where) {
  if (typeof spec === "string") {
    const [type, rule] = spec.split(":");
    const nullable = type.endsWith("?");
    const base = nullable ? type.slice(0, -1) : type;
    if (nullable && value === null) return;
    const ok = base === "integer" ? Number.isInteger(value) : base === "array" ? Array.isArray(value) : typeof value === base;
    if (!ok) throw new Error(where + ": expected " + spec + ", got " + JSON.stringify(value));
    if (rule === "nonneg" && value < 0) throw new Error(where + ": negative");
    if (rule === "positive" && value < 1) throw new Error(where + ": not positive");
    if (rule === "nonempty" && !value.length) throw new Error(where + ": empty");
    return;
  }
  if (Array.isArray(spec)) {
    if (spec.indexOf(value) === -1) throw new Error(where + ": " + JSON.stringify(value) + " not in " + spec.join("|"));
    return;
  }
  if (spec instanceof Map) { // Map(["*", valueSpec]) = record with any keys
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(where + ": expected object");
    for (const key of Object.keys(value)) conform(value[key], spec.get("*"), where + "." + key);
    return;
  }
  if (spec.arrayOf) {
    if (!Array.isArray(value)) throw new Error(where + ": expected array");
    value.forEach((item, i) => conform(item, spec.arrayOf, where + "[" + i + "]"));
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(where + ": expected object");
  const want = Object.keys(spec).sort();
  const have = Object.keys(value).sort();
  if (want.join() !== have.join()) throw new Error(where + ": keys [" + have.join(",") + "] != contract [" + want.join(",") + "]");
  for (const key of want) conform(value[key], spec[key], where + "." + key);
}

check("type checker rejects extra keys, wrong types and unknown enum values", () => {
  const spec = { a: "integer:nonneg", b: ["X", "Y"], c: { arrayOf: "string" }, d: "string?" };
  conform({ a: 1, b: "X", c: ["q"], d: null }, spec, "ok");
  for (const bad of [{ a: 1, b: "X", c: [], d: null, value: "leak" }, { a: -1, b: "X", c: [], d: null }, { a: 1.5, b: "X", c: [], d: null },
    { a: 1, b: "Z", c: [], d: null }, { a: 1, b: "X", c: [1], d: null }, { a: 1, b: "X", c: [] }]) {
    let threw = false;
    try { conform(bad, spec, "bad"); } catch (error) { threw = true; }
    if (!threw) throw new Error("accepted " + JSON.stringify(bad));
  }
});

const engine = require("../src/sanitizer");
const caps = engine.getCapabilities();
const ACTIONS = ["REDACT", "KEEP"];
const SEVERITIES = ["high", "medium", "low", "review"];
const CATEGORIES = engine.inspectDetectors().map((d) => d.category).concat(["COOKIE_VALUE", "SESSION_TOKEN"]);
const LIMITS = { maxInputLength: "integer:positive", maxCandidates: "integer:positive", maxJsonDepth: "integer:positive", maxFields: "integer:positive" };
const POSITION = { line: "integer:positive", column: "integer:positive" };
const FINDING = { id: "string:nonempty", ruleId: "string:nonempty", category: CATEGORIES, control: caps.controls, severity: SEVERITIES,
  reason: "string:nonempty", description: "string:nonempty", certainty: ["deterministic-rule-match"], replacementPolicy: "string:nonempty",
  start: "integer:nonneg", end: "integer:positive", position: POSITION, endPosition: POSITION, replacement: "string:nonempty",
  action: ACTIONS, policyReason: "string:nonempty", networkKind: "string?", allowKeep: "boolean" };
const CONTROL_ACTIONS = new Map([["*", ACTIONS]]);
const POLICY = { name: caps.profiles.concat(["legacy"]), mode: caps.modes, description: "string:nonempty", categories: CONTROL_ACTIONS,
  network: { preserveLoopback: "boolean", preservePrivate: "boolean" }, lockedCategories: { arrayOf: caps.controls },
  networkClassification: "string:nonempty", diagnosticExceptions: "string:nonempty" };
const COUNTS = new Map([["*", { detected: "integer:nonneg", redacted: "integer:nonneg", kept: "integer:nonneg" }]]);
const REPORT = { engineVersion: "integer:positive", profile: POLICY.name, mode: caps.modes, policy: POLICY, format: caps.formats.filter((f) => f !== "auto"),
  parseStatus: "string:nonempty", inputLength: "integer:nonneg", inputLines: "integer:nonneg", totalFindings: "integer:nonneg",
  redacted: "integer:nonneg", kept: "integer:nonneg", categoryCounts: COUNTS, findings: { arrayOf: FINDING },
  networkEgress: ["none"], persistentStorage: ["none"] };
const SAMPLE = [
  "2026-10-07T10:00:00Z level=info password=FakeContract1 user=fakecontract email=fake.contract@example.test",
  "Authorization: Bearer FAKEcontractBearer0000 client_ip=203.0.113.7 mac=00:1a:2b:3c:4d:5e release=1.2.3.4"
].join("\n");
const SECRETS = ["FakeContract1", "fakecontract", "fake.contract@example.test", "FAKEcontractBearer0000", "203.0.113.7", "00:1a:2b:3c:4d:5e"];
function noSecrets(value, where) {
  const json = JSON.stringify(value);
  for (const secret of SECRETS) if (json.includes(secret)) throw new Error(where + " exposes a sensitive sample value");
}
const contracts = [];
function contract(name, run) { contracts.push(name); check("contract: " + name, run); }
contract("module exports", () => {
  conform(Object.fromEntries(Object.keys(engine).map((k) => [k, typeof engine[k]])), {
    sanitize: ["function"], analyze: ["function"], createReview: ["function"], createSession: ["function"], inspectDetectors: ["function"],
    inspectPolicy: ["function"], inspectPolicies: ["function"], getCapabilities: ["function"], isValidIpv4: ["function"],
    isLoopbackIpv4: ["function"], REDACTION_LABELS: ["object"] }, "exports");
  conform(engine.REDACTION_LABELS, new Map([["*", "string:nonempty"]]), "REDACTION_LABELS");
});
contract("getCapabilities()", () => {
  conform(caps, Object.assign({}, LIMITS, { formats: { arrayOf: "string" }, modes: { arrayOf: "string" }, profiles: { arrayOf: "string" },
    controls: { arrayOf: "string" }, actions: { arrayOf: ACTIONS }, lockedCategories: { arrayOf: "string" }, maxOverrides: "integer:positive",
    largeLimits: LIMITS }), "capabilities");
});
contract("inspectDetectors() catalog", () => {
  const catalog = engine.inspectDetectors();
  conform(catalog, { arrayOf: { id: "string:nonempty", category: "string:nonempty", control: caps.controls, severity: SEVERITIES,
    description: "string:nonempty", reason: "string:nonempty", priority: "integer:nonneg", replacement: "string:nonempty",
    replacementPolicy: "string:nonempty", certainty: ["deterministic-rule-match"], contextRequirements: "string:nonempty", allowKeep: "boolean" } }, "detectors");
  const ids = catalog.map((d) => d.id);
  if (new Set(ids).size !== ids.length) throw new Error("duplicate detector ids");
  return catalog.length + " detectors";
});
contract("inspectPolicies() / inspectPolicy()", () => {
  conform(engine.inspectPolicies(), { arrayOf: POLICY }, "policies");
  for (const name of caps.profiles) conform(engine.inspectPolicy({ profile: name }), POLICY, "policy " + name);
});
contract("createReview() findings, report and apply()", () => {
  for (const mode of caps.modes) {
    for (const format of caps.formats) {
      const review = engine.createReview(SAMPLE, { profile: "strict", mode, format });
      conform(Object.fromEntries(Object.keys(review).map((k) => [k, typeof review[k]])),
        { findings: ["object"], report: ["object"], policy: ["object"], apply: ["function"], clear: ["function"] }, "review");
      conform(review.findings, { arrayOf: FINDING }, mode + "/" + format + " findings");
      conform(review.report, REPORT, mode + "/" + format + " report");
      conform(review.policy, POLICY, "review.policy");
      const applied = review.apply();
      conform(applied, { sanitized: "string", findings: { arrayOf: FINDING }, report: REPORT }, "apply()");
      noSecrets(review.findings, "findings"); noSecrets(review.report, "report"); noSecrets(applied.findings, "applied findings");
      for (const f of applied.findings) if (f.end <= f.start || f.end > SAMPLE.length) throw new Error("finding span out of range");
    }
  }
});
contract("createSession() and session.limits", () => {
  for (const limits of [undefined, "large"]) {
    const session = engine.createSession(limits ? { limits } : undefined);
    conform(Object.fromEntries(Object.keys(session).map((k) => [k, typeof session[k]])),
      { limits: ["object"], createReview: ["function"], clear: ["function"] }, "session");
    conform(session.limits, LIMITS, "session.limits");
  }
});
contract("legacy sanitize() result (academic base API, unchanged)", () => {
  conform(engine.sanitize("password=FakeLegacy1 ip 203.0.113.8"), { original: "string", sanitized: "string",
    matches: { arrayOf: { category: "string:nonempty", text: "string", index: "integer:nonneg" } }, categories: { arrayOf: "string" },
    redactionCount: "integer:nonneg" }, "sanitize()");
});
contract("engine errors carry a fixed code and no input text", () => {
  for (const [run, code] of [[() => engine.createReview("x", { profile: "nope" }), null], [() => engine.createSession({ limits: "huge" }), "INVALID_SESSION_OPTIONS"],
    [() => engine.createReview("password=FakeErr1", { profile: "custom", categories: { credentials: "KEEP" } }), "KEEP_FORBIDDEN"]]) {
    try { run(); throw new Error("no error thrown"); }
    catch (error) {
      if (!/^[A-Z][A-Z0-9_]{0,40}$/.test(String(error.code))) throw new Error("uncoded error: " + error.message);
      if (code && error.code !== code) throw new Error("expected " + code + ", got " + error.code);
      if (/FakeErr1/.test(error.message)) throw new Error("error message echoes input");
    }
  }
});
contract("worker message protocol (static)", () => {
  const code = read("src/worker.js");
  const types = new Set(Array.from(code.matchAll(/postMessage\(\{\s*type:\s*"([a-z]+)"/g), (m) => m[1]));
  const expected = ["error", "ready", "result", "status"];
  if (Array.from(types).sort().join() !== expected.join()) throw new Error("worker emits [" + Array.from(types).sort() + "]");
  for (const incoming of ["analyze", "apply", "release"]) if (!code.includes('"' + incoming + '"')) throw new Error("worker ignores " + incoming);
  if (/importScripts\((?!"sanitizer\.js"\))/.test(code)) throw new Error("worker imports something other than sanitizer.js");
});
contract("CLI module exports and exit codes", () => {
  const cli = require("../bin/safepaste.js");
  conform(Object.fromEntries(Object.keys(cli).map((k) => [k, typeof cli[k]])),
    { parseArgs: ["function"], engineOptions: ["function"], EXIT_OK: ["number"], EXIT_FINDINGS: ["number"], EXIT_ERROR: ["number"] }, "cli");
  if (cli.EXIT_OK !== 0 || cli.EXIT_FINDINGS !== 1 || cli.EXIT_ERROR !== 2) throw new Error("exit codes differ from docs/CLI.md");
});
check("corpora: unique ids and synthetic-only flag", () => {
  const seen = new Set();
  let count = 0;
  for (const name of ["true_positive", "false_positive", "ambiguous", "adversarial", "performance"]) {
    const corpus = JSON.parse(read("evals/corpora/" + name + ".json"));
    if (corpus.syntheticOnly !== true) throw new Error(name + " is not marked syntheticOnly");
    for (const item of corpus.cases) { if (seen.has(item.id)) throw new Error("duplicate id " + item.id); seen.add(item.id); count += 1; }
  }
  return count + " cases";
});
check("production detection does not read evals/ or tests/ fixtures", () => {
  const load = /\b(?:require|importScripts|readFileSync|readFile|createReadStream)\s*\(\s*[^)]*(?:evals|tests|corpora|eval_set)/;
  for (const f of PRODUCTION_JS) if (load.test(read(f))) throw new Error(f + " loads test/eval fixtures");
});
check("GitHub Actions workflow runs every test and eval entry point", () => {
  const workflow = ".github/workflows/ci.yml";
  if (!fs.existsSync(path.join(ROOT, workflow))) throw new Error(workflow + " missing");
  const text = read(workflow);
  const entries = files.filter((f) => /^tests\/test-[\w-]+\.js$|^evals\/(?:run-[\w-]+|graders\/[\w-]+)\.js$/.test(f));
  const missing = entries.filter((f) => !text.includes("node " + f));
  if (missing.length) throw new Error("not run in CI: " + missing.join(", "));
  if (/\bnpm\s+(?:install|ci)\b|\byarn\b|\bpnpm\b|curl\s|wget\s/.test(text)) throw new Error("CI installs or downloads something");
  return entries.length + " entry points";
});
check("history/v1 and SPEC_v1.md exist (academic provenance preserved)", () => {
  if (!fs.existsSync(path.join(ROOT, "SPEC_v1.md")) || !fs.existsSync(path.join(ROOT, "history", "v1"))) throw new Error("provenance files missing");
});
check("contract count", () => contracts.length + " API contracts");
module.exports = { conform };
if (require.main === module) {
  let failed = 0;
  for (const [ok, name, detail] of results) { if (!ok) failed += 1; console.log((ok ? "PASS " : "FAIL ") + name + (detail ? " :: " + detail : "")); }
  console.log((results.length - failed) + "/" + results.length + " syntax/lint/contract checks passed");
  process.exitCode = failed ? 1 : 0;
}
