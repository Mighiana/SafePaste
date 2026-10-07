"use strict";
const assert = require("assert");
const engine = require("../src/sanitizer");
const { buildHarness, descendants } = require("./ui-harness");
const options = { profile: "strict", mode: "pseudonymization" };
const tests = [];
function test(name, run) { tests.push([name, run]); }
// All values are synthetic, never real credentials or personal data.
test("same/different values and categories are stable across session reviews", () => {
  const session = engine.createSession();
  const first = session.createReview("a@example.test b@example.test a@example.test user=alice /home/alice/x 192.0.2.1", options);
  assert.strictEqual(first.apply().sanitized, "[EMAIL_1] [EMAIL_2] [EMAIL_1] user=[USERNAME_1] /home/[PATH_1]/x [IP_1]");
  first.clear();
  const second = session.createReview("b@example.test c@example.test 192.0.2.1", options);
  assert.strictEqual(second.apply().sanitized, "[EMAIL_2] [EMAIL_3] [IP_1]");
  session.clear();
  assert.throws(() => second.apply(), /REVIEW_CLEARED/);
  assert.strictEqual(session.createReview("b@example.test", options).apply().sanitized, "[EMAIL_1]");
});
test("JSON Unicode escapes and decoded identities share mappings without metadata values", () => {
  const session = engine.createSession();
  const source = '{"a":"a\\u0040example.test","b":"a@example.test","username":"\\u00e9lodie"}';
  const review = session.createReview(source, options);
  assert.deepStrictEqual(JSON.parse(review.apply().sanitized), { a: "[EMAIL_1]", b: "[EMAIL_1]", username: "[USERNAME_1]" });
  assert.strictEqual(session.createReview('{"user":"élodie"}', options).apply().sanitized, '{"user":"[USERNAME_1]"}');
  for (const value of ["a@example.test", "élodie", "u00e9lodie"]) assert(!JSON.stringify(review).includes(value));
});
test("high-risk credentials fully redact and KEEP remains forbidden", () => {
  const review = engine.createReview('password=SYNTHETIC_VALUE secret=SYNTHETIC_SECRET Authorization: Basic SYNTHETIC_AUTH_TOKEN', options);
  assert(!review.apply().sanitized.includes("SYNTHETIC"));
  assert(review.findings.every(f => !f.allowKeep && f.replacement.startsWith("[REDACTED_")));
  review.findings.forEach(f => assert.throws(() => review.apply({ [f.id]: "KEEP" }), /KEEP_FORBIDDEN/));
});
test("existing markers reserve namespaces, stay idempotent and cannot hide embedded secrets", () => {
  const source = '{"email":"[EMAIL_1]","a":"a@example.test","password":"SYNTHETIC[EMAIL_1]SECRET"}';
  const first = engine.createReview(source, options).apply().sanitized;
  assert(first.includes('"a":"[EMAIL_2]"'));
  assert(!first.includes("SYNTHETIC"));
  assert.strictEqual(engine.createReview(first, options).apply().sanitized, first);
  const escaped = '{"marker":"\\u005bEMAIL_1]","email":"a@example.test"}';
  assert(engine.createReview(escaped, options).apply().sanitized.includes('[EMAIL_2]'));
  const redacted = engine.sanitize('{"password":"SYNTHETIC","user":"alice"}').sanitized;
  assert.strictEqual(engine.sanitize(redacted).sanitized, redacted);
});
test("generated stable/injective properties, deterministic apply, reset and unknown mode", () => {
  const source = Array.from({ length: 100 }, (_, i) => `person${i}@example.test`).join(" ");
  const session = engine.createSession();
  const review = session.createReview(source + " " + source, options);
  const markers = review.apply().sanitized.split(" ");
  assert.strictEqual(new Set(markers).size, 100);
  assert.deepStrictEqual(markers.slice(0, 100), markers.slice(100));
  assert.strictEqual(review.apply().sanitized, review.apply().sanitized);
  assert.strictEqual(review.report.mode, "pseudonymization");
  session.clear();
  assert.strictEqual(session.createReview("person99@example.test", options).apply().sanitized, "[EMAIL_1]");
  assert.throws(() => engine.createReview("", { mode: "remote" }), /UNKNOWN_MODE/);
});
test("UI mode invalidates exports, Copy is final text, KEEP Preview stays masked, Clear/reload reset", async () => {
  const h = buildHarness();
  const e = h.elements;
  e["mode-select"].value = "pseudonymization";
  await e["mode-select"].dispatch("change");
  e["input-text"].value = "a@example.test b@example.test";
  await e["input-text"].dispatch("input");
  await e["sanitize-button"].dispatch("click");
  assert.strictEqual(e["output-text"].value, "[EMAIL_1] [EMAIL_2]");
  await e["copy-button"].dispatch("click");
  assert.strictEqual(h.copied(), "[EMAIL_1] [EMAIL_2]");
  const keep = descendants(e["findings-list"]).find(node => node.tagName === "SELECT");
  keep.value = "KEEP";
  await keep.dispatch("change");
  await e["preview-tab"].dispatch("click");
  assert(!e["preview-panel"].textContent.includes("a@example.test"));
  assert.strictEqual(e["output-text"].value, "");
  await e["copy-button"].dispatch("click");
  assert.strictEqual(h.copied(), "a@example.test [EMAIL_2]");
  e["mode-select"].value = "redaction";
  await e["mode-select"].dispatch("change");
  assert(e["copy-button"].disabled && e["download-log"].disabled && e["download-report"].disabled);
  await e["clear-button"].dispatch("click");
  e["mode-select"].value = "pseudonymization";
  e["input-text"].value = "b@example.test";
  await e["sanitize-button"].dispatch("click");
  await e["sanitized-tab"].dispatch("click");
  assert.strictEqual(e["output-text"].value, "[EMAIL_1]");
  const fresh = buildHarness();
  fresh.elements["mode-select"].value = "pseudonymization";
  fresh.elements["input-text"].value = "b@example.test";
  await fresh.elements["sanitize-button"].dispatch("click");
  assert.strictEqual(fresh.elements["output-text"].value, "[EMAIL_1]");
});
(async () => {
  for (const [name, run] of tests) { await run(); console.log("PASS pseudonyms: " + name); }
  console.log(`${tests.length}/${tests.length} pseudonym checks passed`);
})().catch(error => { console.error(error); process.exitCode = 1; });
