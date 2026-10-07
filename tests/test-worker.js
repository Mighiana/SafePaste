"use strict";

// Runs the real src/worker.js in a vm context behind a manually pumped mock Worker,
// so job ids, stale replies, cancellation, Clear and fallback are deterministic.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { buildHarness } = require("./ui-harness");

const workerSource = fs.readFileSync(path.resolve(__dirname, "../src/worker.js"), "utf8");
const engineSource = fs.readFileSync(path.resolve(__dirname, "../src/sanitizer.js"), "utf8");
const MiB = 1048576;
let passed = 0;
const tests = [];
function test(name, run) { tests.push([name, run]); }

function workerKit(options = {}) {
  const instances = [];
  class MockWorker {
    constructor(url) {
      if (options.throws) throw new Error("SecurityError");
      assert.strictEqual(url, "src/worker.js");
      this.terminated = false;
      this.inbox = [];
      this.outbox = [];
      instances.push(this);
      const scope = { postMessage: message => this.outbox.push(structuredClone(message)) };
      scope.self = scope;
      scope.importScripts = function (name) {
        assert.strictEqual(name, "sanitizer.js");
        vm.runInContext(engineSource, scope, { filename: "sanitizer.js" });
      };
      vm.createContext(scope);
      vm.runInContext(workerSource, scope, { filename: "worker.js" });
      this.scope = scope;
    }
    postMessage(message) {
      assert(!this.terminated, "posted to terminated worker");
      this.inbox.push(structuredClone(message));
    }
    terminate() { this.terminated = true; }
    // Deliver queued page -> worker messages, then worker -> page replies.
    pump() {
      while (this.inbox.length) this.scope.onmessage({ data: this.inbox.shift() });
      while (this.outbox.length && !this.terminated) {
        const message = this.outbox.shift();
        if (this.onmessage) this.onmessage({ data: message });
      }
    }
  }
  return { Worker: MockWorker, instances, live: () => instances[instances.length - 1] };
}

async function setInput(h, value) {
  h.elements["input-text"].value = value;
  await h.elements["input-text"].dispatch("input");
}

async function start(h, value, profile) {
  if (profile) {
    h.elements["profile-select"].value = profile;
    await h.elements["profile-select"].dispatch("change");
  }
  await setInput(h, value);
  await h.elements["sanitize-button"].dispatch("click");
}

function ready() {
  const kit = workerKit();
  const h = buildHarness({ Worker: kit.Worker });
  kit.live().pump();
  return { kit, h };
}

const sample = "email=worker@example.test password=SyntheticWorkerPassword client_ip=192.168.1.20";

test("worker result matches synchronous engine output and announces the large limit", async () => {
  const { kit, h } = ready();
  assert(h.elements["engine-status"].textContent.includes("local worker · 16 MiB"));
  await start(h, sample, "strict");
  assert(!h.elements["cancel-button"].hidden, "cancel visible while busy");
  assert(h.elements["copy-button"].disabled && h.elements["download-report"].disabled);
  assert.strictEqual(h.elements["output-text"].value, "");
  kit.live().pump();
  const sync = buildHarness();
  await start(sync, sample, "strict");
  assert.strictEqual(h.elements["output-text"].value, sync.elements["output-text"].value);
  assert(!h.elements["output-text"].value.includes("SyntheticWorkerPassword"));
  assert(h.elements["cancel-button"].hidden);
  assert(!h.elements["copy-button"].disabled && !h.elements["download-report"].disabled);
  assert.strictEqual(h.elements["preview-panel"].textContent, sync.elements["preview-panel"].textContent);
});

test("cancel terminates the worker, drops its reply and restarts a fresh worker", async () => {
  const { kit, h } = ready();
  await start(h, sample, "strict");
  const first = kit.live();
  await h.elements["cancel-button"].dispatch("click");
  assert(first.terminated);
  assert.strictEqual(kit.instances.length, 2);
  first.terminated = false;
  first.pump();
  assert.strictEqual(h.elements["output-text"].value, "");
  assert(h.elements["status-message"].textContent.includes("cancelled"));
  assert(h.elements["copy-button"].disabled);
  assert(h.elements["engine-status"].textContent.includes("local worker"));
});

test("input edits and Clear invalidate in-flight jobs; stale job ids are ignored", async () => {
  const { kit, h } = ready();
  await start(h, sample, "strict");
  const first = kit.live();
  await setInput(h, sample + " changed");
  assert(first.terminated, "edit while busy terminates");
  await h.elements["sanitize-button"].dispatch("click");
  const second = kit.live();
  second.outbox.push({ type: "result", job: 1, result: { sanitized: "STALE", findings: [], report: {} }, masked: "STALE" });
  second.pump();
  assert(!h.elements["output-text"].value.includes("STALE"));
  assert(h.elements["output-text"].value.includes("changed"));
  await start(h, sample, "strict");
  await h.elements["clear-button"].dispatch("click");
  assert(kit.live().inbox.length === 0 && kit.instances.length >= 4);
  assert.strictEqual(h.elements["output-text"].value, "");
});

test("worker owns the pseudonym session: stable across reviews, reset by Clear", async () => {
  const { kit, h } = ready();
  h.elements["mode-select"].value = "pseudonymization";
  await h.elements["mode-select"].dispatch("change");
  await start(h, "user one@example.test", "strict");
  kit.live().pump();
  assert(h.elements["output-text"].value.includes("[EMAIL_1]"));
  await start(h, "user two@example.test then one@example.test", "strict");
  kit.live().pump();
  assert.strictEqual(h.elements["output-text"].value, "user [EMAIL_2] then [EMAIL_1]");
  await h.elements["clear-button"].dispatch("click");
  await start(h, "user two@example.test", "strict");
  kit.live().pump();
  assert.strictEqual(h.elements["output-text"].value, "user [EMAIL_1]");
});

test("review decisions round-trip through the worker and pause exports while pending", async () => {
  const { kit, h } = ready();
  await start(h, "contact keep@example.test", "strict");
  kit.live().pump();
  const select = require("./ui-harness").descendants(h.elements["findings-list"]).find(node => node.tagName === "SELECT");
  select.value = "KEEP";
  await select.dispatch("change");
  assert(h.elements["copy-button"].disabled, "exports paused while decision pending");
  kit.live().pump();
  assert.strictEqual(h.elements["output-text"].value, "contact keep@example.test");
  assert(!h.elements["copy-button"].disabled);
  assert(!h.elements["preview-panel"].textContent.includes("keep@example.test"));
});

test("worker errors carry only fixed codes and fail closed without output", async () => {
  const { kit, h } = ready();
  const worker = kit.live();
  worker.scope.onmessage({ data: { type: "analyze", job: 9, input: 42 } });
  worker.scope.onmessage({ data: { type: "apply", job: 10, overrides: {} } });
  worker.scope.onmessage({ data: { type: "analyze", job: 11, input: "a".repeat(10), options: { profile: "nope" } } });
  const errors = worker.outbox.splice(0).filter(message => message.type === "error");
  assert.deepStrictEqual(errors.map(message => Object.keys(message).sort().join()), ["code,job,type", "code,job,type", "code,job,type"]);
  assert.deepStrictEqual(errors.map(message => message.code).slice(0, 2), ["INVALID_INPUT", "REVIEW_CLEARED"]);
  assert(/^[A-Z_]+$/.test(errors[2].code));
  await start(h, "secret=SyntheticSecretValue", "strict");
  const job = worker.inbox[worker.inbox.length - 1].job;
  worker.inbox.length = 0;
  worker.outbox.push({ type: "error", job, code: "<img src=x> SyntheticSecretValue" });
  worker.pump();
  assert(h.elements["status-message"].textContent.includes("WORKER_ERROR"));
  assert(!h.elements["status-message"].textContent.includes("SyntheticSecretValue"));
  assert.strictEqual(h.elements["output-text"].value, "");
  assert(h.elements["copy-button"].disabled);
});

test("worker crash or blocked construction falls back to synchronous engine with 2 MiB limit", async () => {
  const { kit, h } = ready();
  await start(h, sample, "strict");
  kit.live().onerror({ preventDefault() {} });
  assert(h.elements["engine-status"].textContent.includes("synchronous fallback · 2 MiB"));
  assert(h.elements["status-message"].textContent.includes("WORKER_UNAVAILABLE"));
  assert.strictEqual(h.elements["output-text"].value, "");
  await h.elements["sanitize-button"].dispatch("click");
  assert(!h.elements["output-text"].value.includes("SyntheticWorkerPassword"));
  assert(h.elements["output-text"].value.includes("[REDACTED_"));
  const blocked = buildHarness({ Worker: workerKit({ throws: true }).Worker });
  assert(blocked.elements["engine-status"].textContent.includes("synchronous fallback"));
  await start(blocked, "x".repeat(2 * MiB + 1), "strict");
  assert(blocked.elements["status-message"].textContent.includes("INPUT_LIMIT"));
  assert(blocked.elements["status-message"].textContent.includes("synchronous fallback"));
});

test("worker accepts inputs above the fallback limit and rejects files above 16 MiB before reading", async () => {
  const { kit, h } = ready();
  const big = ("level=info msg=ok request_id=req-1\n").repeat(Math.ceil(3 * MiB / 35));
  await start(h, big + "email=big@example.test", "strict");
  kit.live().pump();
  assert(h.elements["output-text"].value.endsWith("email=[REDACTED_EMAIL]"));
  h.elements["file-input"].files = [{ name: "huge.log", type: "text/plain", size: 16 * MiB + 1 }];
  await h.elements["file-input"].dispatch("change");
  assert.strictEqual(h.readers.length, 0);
  assert(h.elements["status-message"].textContent.includes("No file was read"));
  await start(h, "y".repeat(16 * MiB + 1), "strict");
  assert(h.elements["status-message"].textContent.includes("INPUT_LIMIT"));
  assert.deepStrictEqual(kit.live().inbox.map(message => message.type), ["release"], "over-limit input never posted to the worker");
});

test("preview and gutter DOM are bounded with a visible notice; exports stay complete", async () => {
  const h = buildHarness();
  const lines = Array.from({ length: 12000 }, (_, i) => "user" + i + "@example.test");
  await start(h, lines.join("\n"), "strict");
  const output = h.elements["output-text"].value;
  assert.strictEqual(output.split("\n").length, 12000);
  h.elements["preview-tab"].dispatch && await h.elements["preview-tab"].dispatch("click");
  const preview = h.elements["preview-panel"];
  const bars = require("./ui-harness").descendants(preview).filter(node => node.className === "redaction-bar");
  assert.strictEqual(bars.length, 5000);
  assert(preview.textContent.includes("Preview display limit reached after line 5000 of 12000"));
  const gutter = h.elements["output-gutter"].textContent.split("\n");
  assert.strictEqual(gutter.length, 10001);
  assert.strictEqual(gutter[gutter.length - 1], "…");
});

(async function () {
  for (const [name, run] of tests) {
    try { await run(); passed += 1; console.log("PASS worker: " + name); }
    catch (error) { console.log("FAIL worker: " + name); console.log(error && error.stack ? error.stack : error); }
  }
  console.log(passed + "/" + tests.length + " worker checks passed");
  process.exitCode = passed === tests.length ? 0 : 1;
})();
