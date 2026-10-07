"use strict";

// Exercises bin/safepaste.js as a real child process with synthetic input only.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const engine = require("../src/sanitizer");

const BIN = path.resolve(__dirname, "../bin/safepaste.js");
const SECRET = "SyntheticCliPassword_FAKE";
const LOG = [
  "2026-10-07T10:00:00Z level=info msg=login email=cli.user@example.test client_ip=192.168.10.20",
  "2026-10-07T10:00:01Z level=warn msg=retry password=" + SECRET + " request_id=req-cli-0001",
  "2026-10-07T10:00:02Z level=info msg=done release=1.2.3.4 user=cli.user@example.test"
].join("\n") + "\n";
const CLEAN = "level=info msg=healthy request_id=req-cli-0002 release=1.2.3.4\n";
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "safepaste-cli-test-"));
let passed = 0;
const tests = [];
function test(name, run) { tests.push([name, run]); }
function cli(args, input) {
  const result = spawnSync(process.execPath, [BIN].concat(args), { input: input === undefined ? "" : input, maxBuffer: 64 * 1048576 });
  return { code: result.status, stdout: result.stdout.toString("utf8"), stderr: result.stderr.toString("utf8") };
}
function tmp(name) { return path.join(dir, name); }
function write(name, text) { fs.writeFileSync(tmp(name), text); return tmp(name); }
function noLeak(text) {
  assert(!text.includes(SECRET), "secret leaked");
  assert(!text.includes("cli.user@example.test"), "email leaked");
  assert(!text.includes("192.168.10.20"), "ip leaked");
}
function expected(input, options) {
  const session = engine.createSession({ limits: "large" });
  const result = session.createReview(input, options).apply();
  session.clear();
  return result;
}

test("stdin and file input use the shared engine and match its exact output", () => {
  const viaStdin = cli([], LOG);
  const file = write("server.log", LOG);
  const viaFile = cli([file]);
  const reference = expected(LOG, { profile: "strict", mode: "redaction", format: "auto" });
  assert.strictEqual(viaStdin.code, 0);
  assert.strictEqual(viaFile.code, 0);
  assert.strictEqual(viaStdin.stdout, reference.sanitized);
  assert.strictEqual(viaFile.stdout, reference.sanitized);
  assert(viaStdin.stdout.includes("request_id=req-cli-0001") && viaStdin.stdout.includes("release=1.2.3.4"));
  noLeak(viaStdin.stdout + viaStdin.stderr);
  assert(/findings=4 redacted=4 kept=0/.test(viaStdin.stderr));
  assert.strictEqual(cli(["-"], LOG).stdout, reference.sanitized);
  assert.strictEqual(fs.readFileSync(file, "utf8"), LOG, "source untouched");
});

test("profiles and pseudonymization mode match the engine", () => {
  for (const profile of ["strict", "support", "incident", "custom"]) {
    for (const mode of ["redaction", "pseudonymization"]) {
      const out = cli(["--profile", profile, "--mode=" + mode], LOG);
      assert.strictEqual(out.code, 0, profile + "/" + mode);
      assert.strictEqual(out.stdout, expected(LOG, { profile, mode, format: "auto" }).sanitized, profile + "/" + mode);
      assert(!out.stdout.includes(SECRET));
    }
  }
  const pseudo = cli(["--mode", "pseudonymization"], LOG).stdout;
  assert.strictEqual(pseudo.split("[EMAIL_1]").length - 1, 2, "same email -> same pseudonym");
  assert(pseudo.includes("[REDACTED_PASSWORD]"), "secrets still fully redacted");
  const support = cli(["--profile", "support"], LOG).stdout;
  assert(support.includes("192.168.10.20"), "support keeps RFC1918 by policy");
  const text = cli(["--format", "text"], CLEAN);
  assert.strictEqual(text.stdout, expected(CLEAN, { profile: "strict", mode: "redaction", format: "text" }).sanitized);
});

test("--check exits 1 only for effective redactions, never for KEEP-by-policy findings", () => {
  const dirty = cli(["--check"], LOG);
  assert.strictEqual(dirty.code, 1);
  assert.strictEqual(dirty.stdout, "", "check prints no sanitized text");
  assert(dirty.stderr.includes("check FAILED: 4 finding(s)"));
  noLeak(dirty.stderr);
  const clean = cli(["--check", write("clean.log", CLEAN)]);
  assert.strictEqual(clean.code, 0);
  assert(clean.stderr.includes("check passed"));
  const ipOnly = "client_ip=192.168.10.20 local=127.0.0.1\n";
  assert.strictEqual(cli(["--check"], ipOnly).code, 1, "strict redacts private/loopback");
  const kept = cli(["--check", "--profile", "support"], ipOnly);
  assert.strictEqual(kept.code, 0, "support keeps them: detected but not redactable");
  assert(/findings=2 redacted=0 kept=2/.test(kept.stderr));
  const custom = cli(["--check", "--profile", "custom", "--category", "email=KEEP"], "contact cli.user@example.test\n");
  assert.strictEqual(custom.code, 0);
  assert.strictEqual(cli(["--check", "--profile", "custom", "--category", "email=redact"], "contact cli.user@example.test\n").code, 1);
  assert.strictEqual(cli(["--check", "--profile", "custom", "--preserve-private"], ipOnly).code, 1, "loopback still redacted");
  assert.strictEqual(cli(["--check", "--profile", "custom", "--preserve-private", "--preserve-loopback"], ipOnly).code, 0);
  assert.strictEqual(cli(["--check", "-q"], LOG).stderr, "");
});

test("--output and --report create new private files; report is metadata-only", () => {
  const output = tmp("out/../server.sanitized.log");
  const report = tmp("privacy-report.json");
  const run = cli(["--output", output, "--report", report], LOG);
  assert.strictEqual(run.code, 0);
  assert.strictEqual(run.stdout, "", "explicit output replaces stdout");
  assert.strictEqual(fs.readFileSync(tmp("server.sanitized.log"), "utf8"), expected(LOG, { profile: "strict", mode: "redaction", format: "auto" }).sanitized);
  const raw = fs.readFileSync(report, "utf8");
  noLeak(raw);
  const data = JSON.parse(raw);
  assert.strictEqual(data.networkEgress, "none");
  assert.strictEqual(data.persistentStorage, "none");
  assert.strictEqual(data.totalFindings, 4);
  assert.strictEqual(data.profile, "strict");
  if (process.platform !== "win32") {
    assert.strictEqual(fs.statSync(report).mode & 0o777, 0o600);
    assert.strictEqual(fs.statSync(tmp("server.sanitized.log")).mode & 0o777, 0o600);
  }
  const checked = cli(["--check", "--report", tmp("check-report.json")], LOG);
  assert.strictEqual(checked.code, 1);
  assert(fs.existsSync(tmp("check-report.json")), "check can still emit a report for CI artifacts");
});

test("never overwrites existing files or the source, and rolls back partial artifacts", () => {
  const source = write("source.log", LOG);
  const existing = write("existing.log", "keep me\n");
  let run = cli([source, "--output", source]);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("OUTPUT_CONFLICT"));
  run = cli([source, "--output", path.join(dir, ".", "source.log")]);
  assert.strictEqual(run.code, 2);
  assert.strictEqual(fs.readFileSync(source, "utf8"), LOG);
  run = cli([source, "--report", existing]);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("EEXIST"));
  assert.strictEqual(fs.readFileSync(existing, "utf8"), "keep me\n");
  run = cli([source, "--output", tmp("same.json"), "--report", tmp("same.json")]);
  assert.strictEqual(run.code, 2);
  assert(!fs.existsSync(tmp("same.json")));
  const partial = tmp("partial.log");
  run = cli([source, "--output", partial, "--report", existing]);
  assert.strictEqual(run.code, 2);
  assert(!fs.existsSync(partial), "output removed when report cannot be created");
  run = cli([source, "--output", partial, "--report", tmp("missing-dir/report.json")]);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("ENOENT"));
  assert(!fs.existsSync(partial));
  noLeak(run.stderr);
  if (process.platform !== "win32") {
    fs.symlinkSync(tmp("link-target.log"), tmp("dangling-link.log"));
    run = cli([source, "--output", tmp("dangling-link.log")]);
    assert.strictEqual(run.code, 2, "exclusive create refuses symlinks");
    assert(!fs.existsSync(tmp("link-target.log")));
  }
});

test("usage errors exit 2 with fixed codes and never echo input", () => {
  const cases = [
    [["--bogus"], "UNKNOWN_OPTION"],
    [["--profile"], "MISSING_VALUE"],
    [["--profile", "strict", "--profile", "support"], "DUPLICATE_OPTION"],
    [["--profile", "nope"], "UNKNOWN_PROFILE"],
    [["--mode", "anonymize"], "UNKNOWN_MODE"],
    [["--format", "xml"], "UNKNOWN_FORMAT"],
    [["--category", "email=KEEP"], "CUSTOM_ONLY"],
    [["--profile", "custom", "--category", "credentials=KEEP"], "KEEP"],
    [["--profile", "custom", "--category", "email=MAYBE"], "INVALID_ACTION"],
    [["--profile", "custom", "--category", "email"], "INVALID_CATEGORY_ARG"],
    [["--check=yes"], "UNEXPECTED_VALUE"],
    [["a.log", "b.log"], "TOO_MANY_INPUTS"],
    [["-" + SECRET], "UNKNOWN_OPTION (unrecognised argument)"]
  ];
  for (const [args, code] of cases) {
    const run = cli(args, LOG);
    assert.strictEqual(run.code, 2, args.join(" "));
    assert.strictEqual(run.stdout, "", args.join(" "));
    assert(run.stderr.startsWith("safepaste: error "), args.join(" ") + ": " + run.stderr);
    assert(run.stderr.includes(code), args.join(" ") + ": " + run.stderr);
    noLeak(run.stderr);
  }
  const help = cli(["--help"]);
  assert.strictEqual(help.code, 0);
  assert(help.stdout.includes("Exit codes:") && help.stdout.includes("--check"));
  assert(/^safepaste \d+\.\d+\.\d+\n$/.test(cli(["--version"]).stdout));
});

test("I/O, encoding, size and engine limits fail closed with exit 2 and no output", () => {
  let run = cli([tmp("does-not-exist.log")]);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("ENOENT"));
  run = cli([dir]);
  assert.strictEqual(run.code, 2);
  assert(/NOT_A_FILE|EISDIR/.test(run.stderr));
  run = cli(["--output", tmp("bad-utf8.out")], Buffer.from([0x70, 0x3d, 0xff, 0xfe, 0x0a]));
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("INVALID_ENCODING"));
  assert(!fs.existsSync(tmp("bad-utf8.out")));
  const huge = tmp("huge.log");
  fs.closeSync(fs.openSync(huge, "w"));
  fs.truncateSync(huge, 16 * 1048576 + 1);
  run = cli([huge, "--output", tmp("huge.out")]);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("INPUT_LIMIT"));
  assert(!fs.existsSync(tmp("huge.out")));
  run = cli([], Buffer.alloc(16 * 1048576 + 1, 0x61));
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("INPUT_LIMIT"));
  assert.strictEqual(run.stdout, "");
  const dense = Array.from({ length: 100001 }, (_, i) => "u" + i + "@example.test").join("\n");
  run = cli(["--output", tmp("dense.out"), "--report", tmp("dense.json")], dense);
  assert.strictEqual(run.code, 2);
  assert(run.stderr.includes("FINDING_LIMIT"));
  assert(!run.stderr.includes("@example.test"));
  assert(!fs.existsSync(tmp("dense.out")) && !fs.existsSync(tmp("dense.json")), "no partial artifacts");
});

test("multi-megabyte input above the browser fallback limit works through the large tier", () => {
  const line = "level=info msg=ok request_id=req-cli-0003 user=bulk@example.test\n";
  const big = line.repeat(Math.ceil(3 * 1048576 / line.length));
  const run = cli(["--check", "-q", "--format", "text"], big);
  assert.strictEqual(run.code, 1);
  const out = cli(["-q"], big);
  assert.strictEqual(out.code, 0);
  assert(!out.stdout.includes("bulk@example.test"));
  assert.strictEqual(out.stdout.length, big.length - (big.split("bulk@example.test").length - 1) * ("bulk@example.test".length - "[REDACTED_EMAIL]".length));
});

test("CLI source stays dependency-free and local-only", () => {
  const source = fs.readFileSync(BIN, "utf8");
  const required = Array.from(source.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g), match => match[1]).sort();
  assert.deepStrictEqual(required, ["../src/sanitizer", "fs", "path"]);
  assert(!fs.existsSync(path.resolve(__dirname, "../package.json")), "EV-034: no dependency manifest");
  assert(source.startsWith("#!/usr/bin/env node\n"));
});

for (const [name, run] of tests) {
  try { run(); passed += 1; console.log("PASS cli: " + name); }
  catch (error) { console.log("FAIL cli: " + name); console.log(error && error.stack ? error.stack : error); }
}
fs.rmSync(dir, { recursive: true, force: true });
console.log(passed + "/" + tests.length + " CLI checks passed");
process.exitCode = passed === tests.length ? 0 : 1;
