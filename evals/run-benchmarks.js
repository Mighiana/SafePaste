"use strict";

// Local, synthetic-only performance and ReDoS benchmarks for the shared engine.
// Usage: node evals/run-benchmarks.js [--full] [--write <new-file.md>]
// Default (quick) mode runs pathological inputs plus 1 MiB sparse/dense cases and
// enforces generous time bounds. --full adds 10/25/50 MiB. --write refuses to
// overwrite an existing file.
const fs = require("fs");
const os = require("os");
const engine = require("../src/sanitizer");

const MiB = 1048576;
const PATHOLOGICAL_BOUND_MS = 5000;
const SIZE_BOUND_MS_PER_MIB = 1500;

function repeatTo(size, unit) {
  return unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
}

function logLines(size, dense) {
  const parts = [];
  let length = 0;
  for (let i = 0; length < size; i += 1) {
    const line = dense
      ? "level=info user=demo" + i + " email=demo" + i + "@example.test ip=10.0." + (i % 250) + "." + (i % 200) + " msg=ok\n"
      : i % 200 === 0
        ? "level=warn request_id=req-" + i + " email=demo" + i + "@example.test status=500 latency_ms=12\n"
        : "level=info request_id=req-" + i + " msg=\"GET /api/v1/items?page=" + (i % 9) + " 200\" latency_ms=" + (i % 97) + " release=1.2.3\n";
    parts.push(line);
    length += line.length;
  }
  return parts.join("").slice(0, size);
}

function pathological() {
  const size = 1900000;
  return [
    ["repeated a", repeatTo(size, "a")],
    ["repeated colons", repeatTo(size, ":")],
    ["hex-colon runs", repeatTo(size, "ab:")],
    ["dotted numerics", repeatTo(size, "1.2.3.4.5.")],
    ["malformed bearer", repeatTo(size, "Authorization: Bearer ")],
    ["unterminated quotes", repeatTo(size, "password=\"")],
    ["deep JSON strings", "{\"a\":" + repeatTo(size - 10, "\"\\\\u0041\\\\n\",") + "1}"],
    ["one long line", "token=" + repeatTo(size, "Z9")],
    ["unicode separators", repeatTo(size, "user\u2028=\u00a0d\u00e9mo\u200b@\uFF20example.test ")],
    ["PEM-like block", "-----BEGIN PRIVATE KEY-----\n" + repeatTo(size, "FAKEPEMBODYFORTESTSONLY0000000000000000000000000000000000000000\n")],
    ["credential URLs", repeatTo(size, "https://demo:FAKE@h.example.test/ ")],
    ["email-like runs", repeatTo(size, "a@b.")]
  ];
}

function run(input, options, limits) {
  const session = engine.createSession({ limits: limits });
  const start = process.hrtime.bigint();
  let outcome;
  try {
    const review = session.createReview(input, options);
    const applied = review.apply();
    outcome = { ok: true, findings: applied.findings.length };
  } catch (error) {
    if (!error || typeof error.code !== "string") throw new Error("Uncoded engine failure");
    outcome = { ok: false, code: error.code };
  } finally {
    session.clear();
  }
  outcome.ms = Number(process.hrtime.bigint() - start) / 1e6;
  return outcome;
}

function label(outcome) {
  return outcome.ok ? "ok, " + outcome.findings + " findings" : "fail-closed " + outcome.code;
}

function main(argv) {
  const full = argv.includes("--full");
  const writeAt = argv.indexOf("--write");
  const target = writeAt === -1 ? null : argv[writeAt + 1];
  if (writeAt !== -1 && !target) throw new Error("--write needs a new file path");
  const rows = [];
  const failures = [];
  pathological().forEach(function (entry) {
    ["text", "auto"].forEach(function (format) {
      const outcome = run(entry[1], { profile: "strict", format: format }, "standard");
      rows.push(["pathological", entry[0], format, "standard", (entry[1].length / MiB).toFixed(2), outcome]);
      if (outcome.ms > PATHOLOGICAL_BOUND_MS) failures.push(entry[0] + " " + format);
    });
  });
  (full ? [1, 10, 16, 25, 50] : [1]).forEach(function (mib) {
    [false, true].forEach(function (dense) {
      const input = logLines(mib * MiB, dense);
      ["text", "auto"].forEach(function (format) {
        ["standard", "large"].forEach(function (limits) {
          const outcome = run(input, { profile: "strict", format: format }, limits);
          rows.push([dense ? "dense" : "sparse", "synthetic logfmt", format, limits, String(mib), outcome]);
          if (outcome.ms > SIZE_BOUND_MS_PER_MIB * Math.max(1, mib)) failures.push(mib + " MiB " + format + " " + limits);
        });
      });
    });
  });
  const lines = [
    "| Kind | Input | Format | Limits | MiB | Outcome | ms |",
    "| --- | --- | --- | --- | --- | --- | --- |"
  ].concat(rows.map(function (row) {
    return "| " + row.slice(0, 5).join(" | ") + " | " + label(row[5]) + " | " + row[5].ms.toFixed(0) + " |";
  }));
  const header = "Node " + process.version + ", " + os.platform() + "/" + os.arch() + ", " + os.cpus().length +
    " CPU, engine-only (no DOM), single run per case, " + (full ? "full" : "quick") + " mode.";
  const report = header + "\n\n" + lines.join("\n") + "\n";
  process.stdout.write(report);
  if (target) {
    const fd = fs.openSync(target, "wx");
    try { fs.writeSync(fd, report); } finally { fs.closeSync(fd); }
  }
  if (failures.length) {
    process.stderr.write("FAIL benchmark bounds: " + failures.join(", ") + "\n");
    return 1;
  }
  process.stdout.write("PASS benchmarks: " + rows.length + " cases within bounds (pathological <= " +
    PATHOLOGICAL_BOUND_MS + " ms; sized <= " + SIZE_BOUND_MS_PER_MIB + " ms/MiB)\n");
  return 0;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));
module.exports = { logLines: logLines, pathological: pathological, run: run };
