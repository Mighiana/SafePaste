"use strict";
const assert = require("assert");
const engine = require("../src/sanitizer");
let count = 0;
function test(name, run) { run(); count += 1; console.log("PASS " + name); }
test("source spans and CRLF/CR/Unicode columns", function () {
  const input = "☃ diagnostic\r\npassword=FakeValue123\ruser=alice\n198.51.100.1";
  const findings = engine.analyze(input).findings;
  assert.deepStrictEqual(findings.map(f => [input.slice(f.start, f.end), f.position.line, f.position.column]),
    [["FakeValue123", 2, 10], ["alice", 3, 6], ["198.51.100.1", 4, 1]]);
  assert.strictEqual(findings[2].start, input.indexOf("198.51"));
});
test("overlap uses strongest rule over original source exactly once", function () {
  const input = "password=alice@example.test Authorization: Bearer FakeToken123456789";
  const result = engine.createReview(input).apply();
  assert.strictEqual(result.findings.length, 2);
  assert.strictEqual(result.sanitized, "password=[REDACTED_PASSWORD] Authorization: [REDACTED_AUTHORIZATION_HEADER]");
});
test("metadata and report contain no originals or raw field names", function () {
  const analysis = engine.analyze("privatecustomer=alice@example.test\nsecret=FakeSecret123");
  const json = JSON.stringify(analysis);
  ["alice@example.test", "FakeSecret123", "privatecustomer"].forEach(value => assert(!json.includes(value)));
  assert(analysis.findings.every(f => !Object.prototype.hasOwnProperty.call(f, "text")));
  assert(Object.isFrozen(analysis.findings[0]));
});
test("markers are not rescanned and repeated apply is deterministic", function () {
  const review = engine.createReview("secret=FakeSecret123 198.51.100.1");
  assert.deepStrictEqual(review.apply(), review.apply());
  assert.strictEqual(engine.sanitize(review.apply().sanitized).sanitized, review.apply().sanitized);
});
test("detector catalog inspectable and immutable", function () {
  const catalog = engine.inspectDetectors();
  assert.strictEqual(catalog.length, 12);
  catalog.forEach(d => assert(d.id && d.reason && d.contextRequirements && d.replacementPolicy && Object.isFrozen(d)));
  assert.strictEqual(catalog.find(d => d.category === "PASSWORD").allowKeep, false);
});
test("bounded inputs fail closed without returning partial output", function () {
  assert.throws(() => engine.createReview("x".repeat(engine.getCapabilities().maxInputLength + 1)), e => e.code === "INPUT_LIMIT");
});
test("clear disables retained source application", function () {
  const review = engine.createReview("secret=FakeSecret123");
  review.clear(); review.clear();
  assert.throws(() => review.apply(), e => e.code === "REVIEW_CLEARED");
});
test("legacy IPv4 opt-out stays scoped", function () {
  const result = engine.sanitize("user=alice password=Fake123 198.51.100.1", { redactIpAddresses: false });
  assert(result.sanitized.includes("198.51.100.1"));
  assert(!result.sanitized.includes("alice") && !result.sanitized.includes("Fake123"));
});
test("malformed JWT runs scan boundedly and valid embedded JWTs retain markers", function () {
  const hostile = "eyJFAKETEST-".repeat(40000);
  assert.strictEqual(engine.sanitize(hostile, { format: "text" }).sanitized, hostile);
  const jwt = "eyJFAKETEST00.eyJFAKETEST00.FAKETEST00";
  assert.strictEqual(engine.sanitize("prefix-" + jwt + ".suffix").sanitized, "prefix-[REDACTED_JWT].suffix");
  assert.strictEqual(engine.sanitize(jwt + "- end").sanitized, "[REDACTED_JWT]- end");
  const previousSyntax = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
  for (const prefix of ["", "prefix-", "prefix.", "_", "-"]) {
    for (const header of ["eyJFAKETEST00", "eyJFAKETEST00-", "notjwt", "eyJshort"]) {
      for (const payload of ["eyJFAKETEST00", "bad", "eyJFAKETEST00-"]) {
        for (const suffix of ["", "-", ".more", " end"]) {
          const input = prefix + header + "." + payload + ".FAKETEST00" + suffix;
          assert.strictEqual(engine.sanitize(input, { format: "text" }).sanitized, input.replace(previousSyntax, "[REDACTED_JWT]"));
        }
      }
    }
  }
});
console.log(`${count}/${count} core tests passed`);
