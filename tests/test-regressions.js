"use strict";
// Focused regressions for engine false negatives found while building the phase 11 corpora.
// All values are synthetic test data.
const assert = require("assert");
const engine = require("../src/sanitizer");
const tests = [];
function test(name, run) { tests.push([name, run]); }
function sanitized(input, options) { return engine.createReview(input, options || { profile: "strict" }).apply().sanitized; }
function hidden(input, secret, options) {
  const output = sanitized(input, options);
  assert(!output.includes(secret), JSON.stringify(input) + " leaked in " + JSON.stringify(output));
  return output;
}

test("escaped quotes cannot split a quoted credential (was: partial leak of the remainder)", () => {
  for (const format of ["auto", "text", "env", "logfmt"]) {
    assert.strictEqual(hidden('password="FakeA\\"PassTail"', "PassTail", { format }), 'password="[REDACTED_PASSWORD]"');
  }
  hidden('{"password":"FakeA\\"PassTail"}\n{"a":1}', "PassTail");
  hidden('INFO body={"secret":"FakeA\\"PassTail"} done', "PassTail");
  hidden('password="FakeA\\\\"', "FakeA");
});

test("embedded / NDJSON / truncated JSON pairs with spaces are redacted (was: full leak)", () => {
  assert.strictEqual(hidden('INFO body={"password":"Fake Pass 123"} done', "Fake Pass"),
    'INFO body={"password":"[REDACTED_PASSWORD]"} done');
  assert.strictEqual(hidden('{"password":"Fake Pass 1"}\n{"password":"Fake Pass 2"}', "Fake Pass"),
    '{"password":"[REDACTED_PASSWORD]"}\n{"password":"[REDACTED_PASSWORD]"}');
  assert.strictEqual(hidden('{"a":{"password":"Fake Pass 123"', "Fake Pass"), '{"a":{"password":"[REDACTED_PASSWORD]"');
  const review = engine.createReview('{"a":{"pass\\u0077ord":"Fake Pass","user":"alice"', { profile: "strict" });
  assert.strictEqual(review.report.parseStatus, "malformed-json-fallback");
  assert.strictEqual(review.apply().sanitized, '{"a":{"pass\\u0077ord":"[REDACTED_PASSWORD]","user":"[REDACTED_USERNAME]"');
  // Unknown keys and invalid strings under them neither redact context nor swallow later pairs.
  assert.strictEqual(sanitized('{"msg":"bad \\x escape","password":"Fake Pass"} {"request_id":"req 1"'),
    '{"msg":"bad \\x escape","password":"[REDACTED_PASSWORD]"} {"request_id":"req 1"');
  // Explicit text format keeps only the original text detectors (documented known miss).
  assert(sanitized('INFO {"password":"Fake Pass 123"}', { format: "text" }).includes("Fake Pass 123"));
});

test("unterminated quoted credential values cover the rest of the line (was: full leak)", () => {
  for (const format of ["auto", "text", "env", "logfmt"]) {
    assert.strictEqual(hidden('level=info password="FakePass123\nnext=1', "FakePass123", { format }),
      'level=info password="[REDACTED_PASSWORD]\nnext=1');
    hidden("secret='FakeSecret1", "FakeSecret1", { format });
    hidden('api_key="FakeKey1234567890', "FakeKey1234567890", { format });
  }
  hidden('{"note":"x","session_id":"FAKEsession123', "FAKEsession123");
  // Unterminated values under unclassified keys are not swallowed and later fields still parse.
  assert.strictEqual(sanitized('msg="unterminated session_id=FAKEsession123'), 'msg="unterminated session_id=[REDACTED_SESSION_TOKEN]');
});

test("a Windows drive path on its own line is not parsed as an HTTP header (was: path username leak)", () => {
  for (const input of ["C:\\Users\\alice\\AppData", "C:\\Users\\alice\\x\nD:\\Users\\bob\\y", "c:/Users/alice\nC:\\Users\\alice\\x"]) {
    const review = engine.createReview(input, { profile: "strict" });
    assert.notStrictEqual(review.report.format, "headers");
    assert(!review.apply().sanitized.includes("alice"));
  }
  assert(!engine.sanitize("C:\\Users\\alice\\AppData").sanitized.includes("alice"), "legacy API");
  // Real header blocks still parse as headers.
  const headers = engine.createReview("Host: example.test\nX-Api-Key: FakeKey12345678", { profile: "strict" });
  assert.strictEqual(headers.report.format, "headers");
  assert.strictEqual(headers.apply().sanitized, "Host: example.test\nX-Api-Key: [REDACTED_HEADER_CREDENTIAL]");
});

test("new lexical paths stay bounded on pathological inputs", () => {
  const size = 1900000;
  const repeat = (unit) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size);
  for (const input of [repeat('"a":"'), repeat('x "password":"Fake\n'), "password=" + repeat("\\"),
    'password="' + repeat('\\"'), '"' + repeat("a"), repeat('"\\'), repeat('"' + "k".repeat(127) + '":')]) {
    for (const format of ["auto", "text"]) {
      const started = Date.now();
      try { engine.createSession({ limits: "large" }).createReview(input, { format }).apply(); }
      catch (error) { assert(/^(?:FIELD_LIMIT|FINDING_LIMIT)$/.test(error.code), String(error.code)); }
      assert(Date.now() - started < 5000, "bounded");
    }
  }
});

test("report engineVersion reflects the detection change", () => {
  assert.strictEqual(engine.createReview("x").report.engineVersion, 8);
});

let failed = 0;
for (const [name, run] of tests) {
  try { run(); console.log("PASS " + name); }
  catch (error) { failed += 1; console.log("FAIL " + name + "\n  " + error.message); }
}
console.log((tests.length - failed) + "/" + tests.length + " regression tests passed");
process.exitCode = failed ? 1 : 0;
