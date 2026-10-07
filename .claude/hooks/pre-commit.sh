#!/usr/bin/env sh
set -eu

# Scan the staged snapshot; never print possible credential values.
command -v git >/dev/null 2>&1 || { echo 'SafePaste hook: git required.' >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo 'SafePaste hook: node required.' >&2; exit 1; }
ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"
node <<'NODE'
"use strict";
const { spawnSync } = require("child_process");
const pattern = '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|password[[:space:]]*[:=][[:space:]]*["\x27]?[^"\x27]{8,}|api[_-]?key[[:space:]]*[:=][[:space:]]*["\x27]?[A-Za-z0-9_./+=-]{16,})';
const files = spawnSync("git", ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"], { encoding: "utf8" });
if (files.error || files.status !== 0) {
  console.error("SafePaste hook: unable to list staged files.");
  process.exit(1);
}
let blocked = false;
for (const file of files.stdout.split("\0").filter(Boolean)) {
  const relative = file.replace(/^SafePaste\//, "");
  if (/^(?:tests|evals|history|docs)\//.test(relative) || /\.md$/i.test(relative)) continue;
  const scan = spawnSync("git", ["grep", "--cached", "-I", "-q", "-E", "-e", pattern, "--", `:(literal)${file}`], { encoding: "utf8" });
  if (scan.error || (scan.status !== 0 && scan.status !== 1)) {
    console.error("SafePaste hook: scan failed; commit blocked.");
    process.exit(1);
  }
  if (scan.status === 0) {
    console.error(`SafePaste hook: possible credential in ${JSON.stringify(file)}; review staged content.`);
    blocked = true;
  }
}
process.exitCode = blocked ? 1 : 0;
NODE
