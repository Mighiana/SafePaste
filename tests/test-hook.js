"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
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
  assert.strictEqual(scan().status, 0, "explicit synthetic fixture allowed");
  const realistic = "xox" + "b-" + "1234567890" + "-" + "abcdefghijKLMNOP";
  fs.writeFileSync(path.join(directory, "tests/fixture.js"), "const t = '" + "AIza" + "FAKE_TEST_" + "x".repeat(25) + "';");
  git("add", "tests/fixture.js");
  assert.strictEqual(scan().status, 1, "Google-key-shaped literal in a fixture must block even with a synthetic marker");
  fs.writeFileSync(path.join(directory, "tests/fixture.js"), "const t = '" + realistic + "';");
  git("add", "tests/fixture.js");
  const fixtureBlocked = scan();
  assert.strictEqual(fixtureBlocked.status, 1, "non-synthetic token format in a fixture must block");
  assert(!fixtureBlocked.stderr.includes(realistic), "fixture scan must not print values");
  let body;
  do { body = crypto.randomBytes(60).toString("base64"); } while (/FAKE|SYNTHETIC|EXAMPLE|TEST|DUMMY|SAMPLE|DEMO|PLACEHOLDER|NOT_?A_?REAL|0{8,}/i.test(body));
  const pem = "-----BEGIN " + "PRIVATE KEY-----\n";
  fs.writeFileSync(path.join(directory, "tests/fixture.js"), pem + body + "\n-----END PRIVATE KEY-----\n");
  git("add", "tests/fixture.js");
  const pemBlocked = scan();
  assert.strictEqual(pemBlocked.status, 1, "non-synthetic private-key body in a fixture must block");
  assert(!pemBlocked.stderr.includes(body), "PEM body must not be printed");
  fs.writeFileSync(path.join(directory, "tests/fixture.js"), pem + "FAKEKEYBODYFORTESTSONLY".repeat(3) + "\n-----END PRIVATE KEY-----\n");
  git("add", "tests/fixture.js");
  assert.strictEqual(scan().status, 0, "synthetic PEM fixture allowed");
  for (const protectedFile of ["history/v1/app.js", "SPEC_v1.md"]) {
    fs.mkdirSync(path.join(directory, path.dirname(protectedFile)), { recursive: true });
    fs.writeFileSync(path.join(directory, protectedFile), "archived\n");
    git("add", "--", protectedFile);
    assert.strictEqual(scan().status, 1, "archived provenance change must block: " + protectedFile);
    git("rm", "--cached", "--quiet", "--", protectedFile);
  }
  fs.mkdirSync(path.join(directory, "SafePaste/src"), { recursive: true });
  fs.writeFileSync(path.join(directory, "SafePaste/src/a.js"), "const k = '" + synthetic + "';");
  git("add", "SafePaste/src/a.js");
  assert.strictEqual(scan().status, 1, "nested SafePaste/ production files are scanned");
  git("rm", "--cached", "--quiet", "--", "SafePaste/src/a.js");
  const app = { "index.html": fs.readFileSync(path.resolve(__dirname, "../index.html"), "utf8"),
    "app.js": "(function () { 'use strict'; })();\n", "styles.css": "body { color: #111; }\n",
    "src/sanitizer.js": "(function () { 'use strict'; })();\n" };
  for (const name of Object.keys(app)) {
    fs.mkdirSync(path.dirname(path.join(directory, name)), { recursive: true });
    fs.writeFileSync(path.join(directory, name), app[name]);
    git("add", "--", name);
  }
  assert.strictEqual(scan().status, 1, "app snapshot without the static checker must block");
  fs.mkdirSync(path.join(directory, "evals"), { recursive: true });
  fs.copyFileSync(path.resolve(__dirname, "../evals/run-static-privacy-checks.js"), path.join(directory, "evals/run-static-privacy-checks.js"));
  git("add", "evals/run-static-privacy-checks.js");
  assert.strictEqual(scan().status, 0, "clean staged app snapshot passes static checks");
  fs.writeFileSync(path.join(directory, "app.js"), "fetch('/x');\n");
  assert.strictEqual(scan().status, 0, "unstaged working-tree egress is not part of the snapshot");
  git("add", "app.js");
  const staged = scan();
  assert.strictEqual(staged.status, 1, "staged network API blocks the commit");
  assert(/NET_FETCH app\.js:1/.test(staged.stderr), "rule id and location reported");
  assert(!staged.stderr.includes("fetch('/x')"), "static checks never print matched source");
  const outside = spawnSync("sh", [hook], { cwd: os.tmpdir(), encoding: "utf8" });
  assert.notStrictEqual(outside.status, 0, "fail closed outside a git repository");
  console.log("PASS hook: standalone paths, unusual filenames, staged snapshot, synthetic-only fixtures, protected provenance, nested layout, staged static checks, no value disclosure, fail closed");
} finally {
  fs.rmSync(directory, { recursive: true, force: true });
}
