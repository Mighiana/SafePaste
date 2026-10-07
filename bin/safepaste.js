#!/usr/bin/env node
/* SafePaste CLI: local only. Uses the same engine as the browser (src/sanitizer.js).
   No network modules, no persistence, exclusive-create output files only. */
"use strict";

const fs = require("fs");
const path = require("path");
const engine = require("../src/sanitizer");
// No package.json on purpose: EV-034 keeps the repository free of dependency manifests.
const VERSION = "0.10.0";

const EXIT_OK = 0;
const EXIT_FINDINGS = 1;
const EXIT_ERROR = 2;
const capabilities = engine.getCapabilities();
const MAX_BYTES = capabilities.largeLimits.maxInputLength;
const ACTIONS = capabilities.actions;

const USAGE = [
  "Usage: safepaste [file|-] [options]",
  "",
  "Reads a log from <file> or stdin, sanitizes it locally and writes the result",
  "to stdout (or --output). Nothing is sent over the network or stored.",
  "",
  "Options:",
  "  --profile <name>        strict (default) | support | incident | custom",
  "  --mode <name>           redaction (default) | pseudonymization",
  "  --format <name>         auto (default) | text | json | env | headers | logfmt",
  "  --category <c>=<A>      custom only, repeatable; c in credentials,tokens,secrets,",
  "                          email,usernames,paths,network; A in REDACT|KEEP",
  "  --preserve-loopback     custom only: keep loopback network addresses",
  "  --preserve-private      custom only: keep private network addresses",
  "  --check                 do not print sanitized text; exit 1 if any finding",
  "                          would be redacted under the active policy",
  "  -o, --output <file>     write sanitized text to a NEW file (never overwrites)",
  "  --report <file>         write metadata-only privacy report JSON to a NEW file",
  "  -q, --quiet             no summary on stderr",
  "  -h, --help              show this help",
  "  --version               show version",
  "",
  "Exit codes:",
  "  0  success; with --check: no redactable findings (KEEP-by-policy ignored)",
  "  1  --check only: at least one finding is redacted by the active policy",
  "  2  usage, input/output or processing error (no output files are left behind)",
  "",
  "Input limit: " + MAX_BYTES + " bytes (16 MiB). Larger input fails closed."
].join("\n");

function CliError(code, detail) {
  this.code = code;
  this.detail = detail || "";
}

function usage(code, detail) { return new CliError(code, detail); }

function parseArgs(argv) {
  const args = { file: null, profile: null, mode: null, format: null, categories: null,
    preserveLoopback: false, preservePrivate: false, check: false, output: null, report: null,
    quiet: false, help: false, version: false };
  const seen = new Set();
  const valued = { "--profile": "profile", "--mode": "mode", "--format": "format",
    "--output": "output", "-o": "output", "--report": "report" };
  const flags = { "--check": "check", "--quiet": "quiet", "-q": "quiet", "--help": "help", "-h": "help",
    "--version": "version", "--preserve-loopback": "preserveLoopback", "--preserve-private": "preservePrivate" };
  let positionalOnly = false;
  for (let index = 0; index < argv.length; index += 1) {
    let arg = argv[index];
    let inline = null;
    if (!positionalOnly && arg === "--") { positionalOnly = true; continue; }
    if (!positionalOnly && /^--[a-z-]+=/.test(arg)) {
      inline = arg.slice(arg.indexOf("=") + 1);
      arg = arg.slice(0, arg.indexOf("="));
    }
    if (!positionalOnly && (Object.prototype.hasOwnProperty.call(valued, arg) || arg === "--category")) {
      const value = inline !== null ? inline : argv[++index];
      if (value === undefined || value === "") throw usage("MISSING_VALUE", arg);
      if (arg === "--category") {
        const match = /^([a-z]+)=([A-Za-z]+)$/.exec(value);
        if (!match) throw usage("INVALID_CATEGORY_ARG", arg);
        args.categories = args.categories || {};
        if (Object.prototype.hasOwnProperty.call(args.categories, match[1])) throw usage("DUPLICATE_OPTION", arg);
        args.categories[match[1]] = match[2].toUpperCase();
        continue;
      }
      const key = valued[arg];
      if (seen.has(key)) throw usage("DUPLICATE_OPTION", arg);
      seen.add(key);
      args[key] = value;
    } else if (!positionalOnly && Object.prototype.hasOwnProperty.call(flags, arg)) {
      if (inline !== null) throw usage("UNEXPECTED_VALUE", arg);
      args[flags[arg]] = true;
    } else if (!positionalOnly && arg.length > 1 && arg[0] === "-") {
      throw usage("UNKNOWN_OPTION", /^--?[a-z][a-z-]{0,30}$/.test(arg) ? arg : "unrecognised argument");
    } else {
      if (args.file !== null) throw usage("TOO_MANY_INPUTS");
      args.file = arg;
    }
  }
  return args;
}

function engineOptions(args) {
  const options = { profile: args.profile || "strict", mode: args.mode || "redaction", format: args.format || "auto" };
  if (args.categories) {
    Object.keys(args.categories).forEach(function (name) {
      if (ACTIONS.indexOf(args.categories[name]) === -1) throw usage("INVALID_ACTION", "--category");
    });
    options.categories = args.categories;
  }
  if (args.preserveLoopback || args.preservePrivate) {
    options.network = { preserveLoopback: args.preserveLoopback, preservePrivate: args.preservePrivate };
  }
  return options;
}

function decode(buffer) {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(buffer);
  } catch (error) {
    throw new CliError("INVALID_ENCODING", "input is not valid UTF-8");
  }
}

function readFileInput(file) {
  let fd;
  try { fd = fs.openSync(file, "r"); } catch (error) { throw ioError(error, "input"); }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new CliError("NOT_A_FILE", "input");
    if (stat.size > MAX_BYTES) throw new CliError("INPUT_LIMIT", "input is " + stat.size + " bytes; limit " + MAX_BYTES);
    const chunks = [];
    let total = 0;
    const chunk = Buffer.allocUnsafe(1048576);
    for (;;) {
      const read = fs.readSync(fd, chunk, 0, chunk.length, null);
      if (read === 0) break;
      total += read;
      if (total > MAX_BYTES) throw new CliError("INPUT_LIMIT", "input grew beyond " + MAX_BYTES + " bytes");
      chunks.push(Buffer.from(chunk.subarray(0, read)));
    }
    return Buffer.concat(chunks, total);
  } catch (error) {
    throw error instanceof CliError ? error : ioError(error, "input");
  } finally {
    fs.closeSync(fd);
  }
}

function readStdin() {
  return new Promise(function (resolve, reject) {
    const chunks = [];
    let total = 0;
    let done = false;
    process.stdin.on("data", function (chunk) {
      if (done) return;
      total += chunk.length;
      if (total > MAX_BYTES) {
        done = true;
        chunks.length = 0;
        process.stdin.destroy();
        reject(new CliError("INPUT_LIMIT", "stdin exceeds " + MAX_BYTES + " bytes"));
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on("end", function () { if (!done) { done = true; resolve(Buffer.concat(chunks, total)); } });
    process.stdin.on("error", function (error) { if (!done) { done = true; reject(ioError(error, "stdin")); } });
  });
}

function ioError(error, what) {
  const code = error && typeof error.code === "string" && /^E[A-Z0-9]{1,20}$/.test(error.code) ? error.code : "IO_ERROR";
  return new CliError(code, what);
}

function writeExclusive(target, text, created) {
  let fd;
  try { fd = fs.openSync(target, "wx", 0o600); } catch (error) { throw ioError(error, target); }
  created.push(target);
  try {
    const data = Buffer.from(text, "utf8");
    let offset = 0;
    while (offset < data.length) offset += fs.writeSync(fd, data, offset, data.length - offset);
    fs.fsyncSync(fd);
  } catch (error) {
    throw ioError(error, target);
  } finally {
    fs.closeSync(fd);
  }
}

function rollback(created) {
  created.forEach(function (target) { try { fs.unlinkSync(target); } catch (error) { /* already gone */ } });
}

function summary(report, check) {
  const counts = Object.keys(report.categoryCounts).filter(function (name) {
    return report.categoryCounts[name].detected > 0;
  }).map(function (name) {
    const count = report.categoryCounts[name];
    return name + " " + count.redacted + "/" + count.detected;
  });
  const lines = ["safepaste: profile=" + report.profile + " mode=" + report.mode + " format=" + report.format +
    " lines=" + report.inputLines + " findings=" + report.totalFindings + " redacted=" + report.redacted +
    " kept=" + report.kept + (counts.length ? " (redacted/detected: " + counts.join(", ") + ")" : "")];
  if (check) lines.push("safepaste: check " + (report.redacted > 0 ? "FAILED: " + report.redacted +
    " finding(s) would be redacted" : "passed: no redactable findings"));
  lines.push("safepaste: local only; network egress none; human review still required.");
  return lines.join("\n") + "\n";
}

async function main(argv) {
  const args = parseArgs(argv);
  if (args.help) { process.stdout.write(USAGE + "\n"); return EXIT_OK; }
  if (args.version) { process.stdout.write("safepaste " + VERSION + "\n"); return EXIT_OK; }
  const options = engineOptions(args);
  const fromStdin = args.file === null || args.file === "-";
  if (fromStdin && process.stdin.isTTY) throw usage("NO_INPUT", "pass a file or pipe a log on stdin");
  const targets = [args.output, args.report].filter(Boolean).map(function (target) { return path.resolve(target); });
  if (targets.length === 2 && targets[0] === targets[1]) throw usage("OUTPUT_CONFLICT", "--output and --report");
  if (!fromStdin && targets.indexOf(path.resolve(args.file)) !== -1) throw usage("OUTPUT_CONFLICT", "output equals input");

  const text = decode(fromStdin ? await readStdin() : readFileInput(args.file));
  const session = engine.createSession({ limits: "large" });
  let result;
  try {
    const review = session.createReview(text, options);
    result = review.apply();
    review.clear();
  } finally {
    session.clear();
  }

  const created = [];
  try {
    if (args.output) writeExclusive(args.output, result.sanitized, created);
    if (args.report) writeExclusive(args.report, JSON.stringify(result.report, null, 2) + "\n", created);
  } catch (error) {
    rollback(created);
    throw error;
  }
  if (!args.check && !args.output) process.stdout.write(result.sanitized);
  if (!args.quiet) process.stderr.write(summary(result.report, args.check));
  return args.check && result.report.redacted > 0 ? EXIT_FINDINGS : EXIT_OK;
}

function safeCode(error) {
  const code = error && typeof error.code === "string" ? error.code : "";
  return /^[A-Z][A-Z0-9_]{0,40}$/.test(code) ? code : "PROCESSING_ERROR";
}

if (require.main === module) {
  main(process.argv.slice(2)).then(function (code) {
    process.exitCode = code;
  }, function (error) {
    // Only fixed codes and caller-supplied paths/option names; never input text or raw messages.
    const detail = error instanceof CliError && error.detail ? " (" + error.detail + ")" : "";
    process.stderr.write("safepaste: error " + safeCode(error) + detail + "\n" +
      (error instanceof CliError && /^(?:MISSING_VALUE|UNKNOWN_OPTION|TOO_MANY_INPUTS|DUPLICATE_OPTION|UNEXPECTED_VALUE|INVALID_CATEGORY_ARG|NO_INPUT|OUTPUT_CONFLICT)$/.test(error.code)
        ? "Run 'safepaste --help' for usage.\n" : ""));
    process.exitCode = EXIT_ERROR;
  });
}

module.exports = { parseArgs, engineOptions, EXIT_OK, EXIT_FINDINGS, EXIT_ERROR };
