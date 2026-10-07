#!/usr/bin/env sh
set -eu

# Staged-snapshot gate. Never prints possible credential values or matched text.
# 1. Production files: credential patterns block the commit.
# 2. Fixtures (tests/, evals/, docs/, *.md): high-confidence token/key formats
#    must carry an explicit synthetic marker (FAKE, SYNTHETIC, EXAMPLE, TEST...).
# 3. Archived provenance (history/, SPEC_v1.md) must not change.
# 4. The staged static zero-egress checker runs against the staged snapshot.
command -v git >/dev/null 2>&1 || { echo 'SafePaste hook: git required.' >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo 'SafePaste hook: node required.' >&2; exit 1; }
ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"
node <<'NODE'
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");

const MAX_BLOB = 64 * 1024 * 1024;
const PRODUCTION = /(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----|password[ \t]*[:=][ \t]*["']?[^"'\r\n]{8,}|api[_-]?key[ \t]*[:=][ \t]*["']?[A-Za-z0-9_./+=-]{16,})/;
const FIXTURE_TOKENS = /AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|AIza[0-9A-Za-z_-]{35}/g;
const PEM = /-----BEGIN [A-Z ]{0,24}PRIVATE KEY(?: BLOCK)?-----/g;
const SYNTHETIC = /FAKE|SYNTHETIC|EXAMPLE|TEST|DUMMY|SAMPLE|DEMO|PLACEHOLDER|NOT_?A_?REAL|0{8,}/i;

function git(args, options) {
  const result = spawnSync("git", args, Object.assign({ maxBuffer: MAX_BLOB }, options || {}));
  if (result.error || result.status !== 0) {
    console.error("SafePaste hook: git " + args[0] + " failed; commit blocked.");
    process.exit(1);
  }
  return result.stdout;
}

const indexEntries = git(["ls-files", "-s", "-z"], { encoding: "utf8" }).split("\0").filter(Boolean).map(function (line) {
  const tab = line.indexOf("\t");
  const meta = line.slice(0, tab).split(" ");
  return { mode: meta[0], sha: meta[1], stage: meta[2], file: line.slice(tab + 1) };
});
const prefix = indexEntries.some(function (entry) { return entry.file === "SafePaste/index.html"; }) &&
  !indexEntries.some(function (entry) { return entry.file === "index.html"; }) ? "SafePaste/" : "";
const byFile = new Map(indexEntries.map(function (entry) { return [entry.file, entry]; }));
function project(file) { return prefix && file.startsWith(prefix) ? file.slice(prefix.length) : file; }

let blocked = false;
function block(message) { console.error("SafePaste hook: " + message); blocked = true; }

const changed = git(["diff", "--cached", "--name-only", "-z", "--no-renames", "--diff-filter=ACDMRT"], { encoding: "utf8" })
  .split("\0").filter(Boolean);
for (const file of changed) {
  const relative = project(file);
  if (/^history\//.test(relative) || relative === "SPEC_v1.md") {
    block("archived provenance path " + JSON.stringify(file) + " is staged for change; history/ and SPEC_v1.md are read-only.");
  }
}

function fixtureProblem(text) {
  let match;
  FIXTURE_TOKENS.lastIndex = 0;
  while ((match = FIXTURE_TOKENS.exec(text))) {
    if (!SYNTHETIC.test(match[0])) return "non-synthetic token format";
  }
  PEM.lastIndex = 0;
  while ((match = PEM.exec(text))) {
    const body = text.slice(match.index + match[0].length, match.index + match[0].length + 400);
    const runs = body.match(/[A-Za-z0-9+/=]{40,}/g) || [];
    if (runs.some(function (run) { return !SYNTHETIC.test(run); })) return "private-key block with non-synthetic body";
  }
  return null;
}

for (const file of changed) {
  const entry = byFile.get(file);
  if (!entry || entry.mode === "160000") continue;
  const blob = git(["cat-file", "blob", entry.sha]);
  if (blob.subarray(0, 8000).includes(0)) continue;
  const text = blob.toString("utf8");
  const relative = project(file);
  const fixture = /^(?:tests|evals|docs|history)\//.test(relative) || /\.md$/i.test(relative);
  if (fixture) {
    const problem = fixtureProblem(text);
    if (problem) block(problem + " in fixture " + JSON.stringify(file) + "; use an explicit FAKE/SYNTHETIC/EXAMPLE marker.");
  } else if (PRODUCTION.test(text)) {
    block("possible credential in " + JSON.stringify(file) + "; review staged content.");
  }
}

const checker = prefix + "evals/run-static-privacy-checks.js";
const isApp = byFile.has(prefix + "index.html") && byFile.has(prefix + "app.js");
if (isApp && !byFile.has(checker)) {
  block("static privacy checker " + JSON.stringify(checker) + " is missing from the staged snapshot.");
} else if (isApp) {
  const snapshot = fs.mkdtempSync(path.join(os.tmpdir(), "safepaste-hook-"));
  try {
    git(["checkout-index", "--all", "--prefix=" + snapshot + path.sep]);
    const projectRoot = path.join(snapshot, prefix);
    const run = spawnSync(process.execPath, [path.join(projectRoot, checker.slice(prefix.length)), "--root", projectRoot], { encoding: "utf8" });
    if (run.error || run.status !== 0) {
      process.stderr.write(String(run.stderr || ""));
      block("staged static privacy checks failed.");
    }
  } finally {
    fs.rmSync(snapshot, { recursive: true, force: true });
  }
}
process.exitCode = blocked ? 1 : 0;
NODE
