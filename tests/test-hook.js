"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const hook = path.resolve(__dirname, "../.claude/hooks/pre-commit.sh");
const directory = fs.mkdtempSync(path.join(os.tmpdir(), "safepaste-hook-test-"));
function git(...args) {
  const result = spawnSync("git", args, { cwd: directory, encoding: "utf8" });
  assert.strictEqual(result.status, 0, result.stderr);
}
function scan() {
  return spawnSync("sh", [hook], { cwd: directory, encoding: "utf8" });
}
try {
  git("init", "--quiet");
  fs.mkdirSync(path.join(directory, "src"));
  fs.mkdirSync(path.join(directory, "tests"));
  const synthetic = "xoxb-" + "SYNTHETIC-TEST-ONLY-0000000000";
  const file = "src/space\n[bracket] name.js";
  fs.writeFileSync(path.join(directory, file), `const token = "${synthetic}";`);
  git("add", "--", file);
  const blocked = scan();
  assert.strictEqual(blocked.status, 1);
  assert(!blocked.stderr.includes(synthetic), "hook must not print credential values");
  fs.writeFileSync(path.join(directory, file), "const clean = true;");
  assert.strictEqual(scan().status, 1, "scan staged snapshot, not working tree");
  git("add", "--", file);
  assert.strictEqual(scan().status, 0);
  fs.writeFileSync(path.join(directory, "tests/fixture.js"), synthetic);
  git("add", "tests/fixture.js");
  assert.strictEqual(scan().status, 0, "explicit fixture exclusion");
  const outside = spawnSync("sh", [hook], { cwd: os.tmpdir(), encoding: "utf8" });
  assert.notStrictEqual(outside.status, 0, "fail closed outside a git repository");
  console.log("PASS hook: standalone paths, unusual filenames, staged snapshot, fixture exclusion, no value disclosure, fail closed");
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
