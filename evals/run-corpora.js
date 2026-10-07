"use strict";
// Phase 11 corpus runner. Reads evals/corpora/*.json (synthetic data only) and checks
// them against the shared engine. Corpora are test inputs only; production code never
// reads them. Usage: node evals/run-corpora.js [--only <corpus>] [--markdown]
const fs = require("fs");
const os = require("os");
const path = require("path");
const engine = require("../src/sanitizer");
const { logLines } = require("./run-benchmarks");

const DIR = path.join(__dirname, "corpora");
const NAMES = ["true_positive", "false_positive", "ambiguous", "adversarial", "performance"];
const DEFAULTS = { profile: "strict" };

function load(name) {
  const data = JSON.parse(fs.readFileSync(path.join(DIR, name + ".json"), "utf8"));
  if (data.corpus !== name || data.syntheticOnly !== true || !Array.isArray(data.cases) || !data.cases.length) {
    throw new Error(name + ": invalid corpus header");
  }
  const ids = new Set();
  for (const item of data.cases) {
    if (typeof item.id !== "string" || ids.has(item.id)) throw new Error(name + ": missing or duplicate id " + item.id);
    ids.add(item.id);
  }
  return data.cases;
}

function inputOf(item) { return item.input + (item.append ? item.append.unit.repeat(item.append.count) : ""); }
function review(input, options) { return engine.createReview(input, Object.assign({}, DEFAULTS, options || {})); }
function leaks(applied, values) {
  const metadata = JSON.stringify({ findings: applied.findings, report: applied.report });
  return values.filter((value) => applied.sanitized.includes(value) || metadata.includes(value));
}

const checkers = {
  true_positive(item) {
    const applied = review(inputOf(item), item.options).apply();
    const problems = leaks(applied, item.secrets).map((value) => "leaked synthetic value of length " + value.length);
    const redacted = new Set(applied.findings.filter((f) => f.action === "REDACT").map((f) => f.category));
    for (const category of item.categories) {
      if (!category.split("|").some((name) => redacted.has(name))) problems.push("missing REDACT " + category);
    }
    if (!applied.findings.some((f) => f.action === "REDACT")) problems.push("no REDACT finding");
    return problems;
  },
  false_positive(item) {
    const input = inputOf(item);
    const applied = review(input, item.options).apply();
    const problems = item.preserve.filter((value) => !applied.sanitized.includes(value)).map((value) => "not preserved: " + value);
    if (item.unchanged && applied.sanitized !== input) problems.push("output changed: " + JSON.stringify(applied.sanitized));
    return problems;
  },
  ambiguous(item) {
    const problems = [];
    for (const profile of Object.keys(item.actions)) {
      const current = review(item.input, { profile });
      const finding = current.findings.find((f) => f.category === item.category);
      if (!finding) { problems.push(profile + ": " + item.category + " not detected"); continue; }
      if (!finding.allowKeep) problems.push(profile + ": KEEP not allowed");
      if (finding.action !== item.actions[profile]) problems.push(profile + ": action " + finding.action + " != " + item.actions[profile]);
      const kept = current.apply({ [finding.id]: "KEEP" }).sanitized;
      const redacted = current.apply({ [finding.id]: "REDACT" }).sanitized;
      if (kept === redacted || !redacted.includes(finding.replacement)) problems.push(profile + ": overrides did not change output");
      current.clear();
    }
    return problems;
  },
  adversarial(item) {
    const applied = review(inputOf(item), item.options).apply();
    item.actual = leaks(applied, [item.secret]).length ? "known-miss" : "detected";
    return item.actual === item.status ? [] : ["recorded " + item.status + " but actual " + item.actual];
  },
  performance(item) {
    const g = item.generator;
    const body = g.kind === "logfmt" ? logLines(g.bytes, g.dense) : g.unit.repeat(g.unit ? Math.ceil(g.bytes / g.unit.length) : 0).slice(0, g.bytes);
    const input = (g.prefix || "") + body + (g.suffix || "");
    const session = engine.createSession({ limits: item.limits });
    const started = process.hrtime.bigint();
    let outcome;
    try { outcome = "ok"; item.findings = session.createReview(input, { profile: "strict", format: item.format }).apply().findings.length; }
    catch (error) { if (!error || typeof error.code !== "string") throw error; outcome = error.code; }
    finally { session.clear(); }
    item.ms = Number(process.hrtime.bigint() - started) / 1e6;
    item.bytes = input.length;
    item.outcome = outcome;
    const problems = [];
    if (outcome !== item.expect) problems.push("outcome " + outcome + " != " + item.expect);
    if (item.ms > item.boundMs) problems.push("took " + item.ms.toFixed(1) + " ms > " + item.boundMs + " ms");
    return problems;
  }
};

function main(argv) {
  const onlyIndex = argv.indexOf("--only");
  const names = onlyIndex === -1 ? NAMES : [argv[onlyIndex + 1]];
  if (names.some((name) => NAMES.indexOf(name) === -1)) { console.error("usage: node evals/run-corpora.js [--only <" + NAMES.join("|") + ">] [--markdown]"); return 2; }
  console.log("runtime: node " + process.version + ", " + process.platform + "/" + process.arch + ", " + os.cpus().length + " CPUs");
  let failed = 0;
  let total = 0;
  const rows = [];
  for (const name of names) {
    const cases = load(name);
    let passed = 0;
    for (const item of cases) {
      let problems;
      try { problems = checkers[name](item); } catch (error) { problems = ["threw " + (error.code || error.message)]; }
      const extra = name === "performance" ? " | " + item.outcome + " | " + item.ms.toFixed(1) + " ms | " + item.bytes + " chars" + (item.findings === undefined ? "" : " | " + item.findings + " findings")
        : name === "adversarial" ? " | " + item.actual : "";
      console.log((problems.length ? "FAIL " : "PASS ") + item.id + " | " + (item.title || item.attack) + extra + (problems.length ? " | " + problems.join("; ") : ""));
      if (problems.length) failed += 1; else passed += 1;
      if (name === "adversarial") rows.push(item);
    }
    total += cases.length;
    let summary = name + ": " + passed + "/" + cases.length + " passed";
    if (name === "adversarial") {
      const misses = cases.filter((item) => item.actual === "known-miss").length;
      summary += " (" + (cases.length - misses) + " detected, " + misses + " known misses recorded honestly)";
    }
    console.log(summary);
  }
  if (argv.indexOf("--markdown") !== -1) {
    console.log("\n| ID | ATTACK | EXPECTED | ACTUAL | STATUS |\n| --- | --- | --- | --- | --- |");
    for (const item of rows) {
      console.log("| " + item.id + " | " + item.attack + " | synthetic value redacted | " +
        (item.actual === "detected" ? "redacted" : "value remains visible") + " | " + (item.actual === "detected" ? "PASS" : "KNOWN MISS") + " |");
    }
  }
  console.log((total - failed) + "/" + total + " corpus cases passed");
  return failed ? 1 : 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { load: load, NAMES: NAMES };
