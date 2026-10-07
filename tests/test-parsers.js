"use strict";
const assert = require("assert");
const engine = require("../src/sanitizer");
let count = 0;
function test(name, run) { run(); count += 1; console.log("PASS " + name); }
function apply(input, options) { return engine.createReview(input, options).apply(); }
test("JSON layout, duplicate keys, nested arrays and diagnostic fields", function () {
  const input = '{\n "username": "alice", "client_ip": "192.168.1.20",\n "release": "1.2.3.4", "request_id": "1.2.3.4", "trace_id":"5.6.7.8",\n "items":[{"password":"Fake123"}],"username":"bob"\n}';
  const result = apply(input);
  assert.strictEqual(result.report.format, "json");
  assert.strictEqual(result.findings.length, 4);
  const parsed = JSON.parse(result.sanitized);
  assert.strictEqual(parsed.username, "[REDACTED_USERNAME]");
  assert.strictEqual(parsed.client_ip, "[REDACTED_IP_ADDRESS]");
  assert.strictEqual(parsed.release, "1.2.3.4");
  assert.strictEqual(parsed.request_id, "1.2.3.4");
  assert.strictEqual(parsed.trace_id, "5.6.7.8");
  assert.strictEqual(result.sanitized.split("\n").length, input.split("\n").length);
  assert(result.sanitized.includes(' "username": "[REDACTED_USERNAME]", "client_ip":'));
});
test("escaped JSON keys and arbitrary password string characters", function () {
  const input = String.raw`{"pass\u0077ord":"Fake \"quoted\"\nsecret","api\u005fkey":"Fake-API-123456789"}`;
  const result = apply(input);
  assert.deepStrictEqual(JSON.parse(result.sanitized), { password: "[REDACTED_PASSWORD]", api_key: "[REDACTED_API_KEY]" });
  assert(result.sanitized.includes(String.raw`"pass\u0077ord"`));
  assert.strictEqual(input.slice(result.findings[0].start, result.findings[0].end), String.raw`Fake \"quoted\"\nsecret`);
});
test("escaped email source mapping, including escaped at sign and dot", function () {
  const input = String.raw`{"message":"☃ \uD83D\uDE00 alice\u0040example\u002etest ok"}`;
  const result = apply(input);
  assert.strictEqual(JSON.parse(result.sanitized).message, "☃ 😀 [REDACTED_EMAIL] ok");
  const finding = result.findings[0];
  assert.strictEqual(input.slice(finding.start, finding.end), String.raw`alice\u0040example\u002etest`);
  assert.strictEqual(finding.position.column, finding.start + 1);
});
test("escaped Windows JSON paths replace only username", function () {
  const input = JSON.stringify({ path: "C:\\Users\\Users\\logs\\debug.txt" });
  const result = apply(input);
  assert.strictEqual(JSON.parse(result.sanitized).path, "C:\\Users\\[REDACTED_USERNAME]\\logs\\debug.txt");
  assert.strictEqual(input.slice(result.findings[0].start, result.findings[0].end), "Users");
});
test("JSON numeric credentials use quoted replacements and remain valid", function () {
  const input = '{ "password":123456, "secret":true, "username":null, "count":42 }';
  assert.deepStrictEqual(JSON.parse(apply(input).sanitized), {
    password: "[REDACTED_PASSWORD]", secret: "[REDACTED_SECRET]", username: null, count: 42
  });
});
test("JSON top-level strings and sensitive object keys", function () {
  assert.strictEqual(JSON.parse(apply('"alice@example.test"').sanitized), "[REDACTED_EMAIL]");
  assert.deepStrictEqual(JSON.parse(apply('{"alice@example.test":"ok"}').sanitized), { "[REDACTED_EMAIL]": "ok" });
});
test("env export, comments, single quotes, double quotes, and PWD", function () {
  const input = "# synthetic only\nexport PASSWORD='fake long secret' # note\nAPI_KEY=FakeCredential12345\nPWD=/workspace/project\nrelease=1.2.3.4";
  const result = apply(input);
  assert.strictEqual(result.report.format, "env");
  assert.strictEqual(result.sanitized, "# synthetic only\nexport PASSWORD='[REDACTED_PASSWORD]' # note\nAPI_KEY=[REDACTED_API_KEY]\nPWD=/workspace/project\nrelease=1.2.3.4");
});
test("explicit env supports unquoted space-containing values", function () {
  assert.strictEqual(apply("PASSWORD=fake long value  # comment", { format: "env" }).sanitized, "PASSWORD=[REDACTED_PASSWORD]  # comment");
});
test("HTTP headers preserve line separators and redact authorization", function () {
  const result = apply("Authorization: Basic FakeBasic12345==\r\nX-Email: alice@example.test\r\nX-Trace: abc-123");
  assert.strictEqual(result.report.format, "headers");
  assert.strictEqual(result.sanitized, "Authorization: [REDACTED_AUTHORIZATION_HEADER]\r\nX-Email: [REDACTED_EMAIL]\r\nX-Trace: abc-123");
});
test("logfmt escaped quotes and explicit fields preserve layout", function () {
  const input = String.raw`time=ok password="Fake \"secret\" here" user=alice request_id=1.2.3.4 client_ip=198.51.100.1`;
  const result = apply(input, { format: "logfmt" });
  assert.strictEqual(result.sanitized, 'time=ok password="[REDACTED_PASSWORD]" user=[REDACTED_USERNAME] request_id=1.2.3.4 client_ip=[REDACTED_IP_ADDRESS]');
  assert(!JSON.stringify(result.report).includes("Fake"));
});
test("mixed plain text and assignment does not swallow bearer token", function () {
  assert.strictEqual(apply("auth=Bearer FakeToken123456789").sanitized, "auth=[REDACTED_BEARER_TOKEN]");
  assert(apply("user=alice@example.test").sanitized.includes("[REDACTED_EMAIL]"));
});
test("diagnostic contexts suppress only network findings, never credentials", function () {
  const result = apply('{"request_id":"alice@example.test", "build_id":"AKIA0000000000000000", "release":"192.168.1.1"}');
  assert.strictEqual(result.findings.length, 2);
  assert(result.sanitized.includes('"release":"192.168.1.1"'));
});
test("malformed JSON returns honest fallback metadata, never error excerpts", function () {
  const result = apply('{"password":"Fake123",');
  assert.strictEqual(result.report.parseStatus, "malformed-json-fallback");
  assert(result.sanitized.includes("[REDACTED_PASSWORD]"));
  assert(!JSON.stringify(result.report).includes("Fake123"));
});
test("explicit plain text and unknown-format validation", function () {
  assert.strictEqual(apply("plain diagnostic text", { format: "text" }).report.format, "text");
  assert.throws(() => apply("hello", { format: "yaml" }), e => e.code === "UNKNOWN_FORMAT");
});
test("depth bound and field bound fail closed", function () {
  const max = engine.getCapabilities().maxJsonDepth;
  assert.doesNotThrow(() => apply("[".repeat(max) + "0" + "]".repeat(max)));
  assert.throws(() => apply("[".repeat(max + 1) + "0" + "]".repeat(max + 1)), e => e.code === "DEPTH_LIMIT");
  const pairs = Array(engine.getCapabilities().maxFields / 2 + 1).fill('"a":0').join(",");
  assert.throws(() => apply("{" + pairs + "}"), e => e.code === "FIELD_LIMIT");
});
test("generated escaping variants produce original-source spans", function () {
  for (let index = 0; index < 18; index += 1) {
    const email = "alice@example.test";
    const escaped = Array.from(email, (c, i) => i === index ? "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0") : c).join("");
    const input = '{"message":"' + escaped + '"}';
    const result = apply(input);
    assert.strictEqual(JSON.parse(result.sanitized).message, "[REDACTED_EMAIL]");
    assert.strictEqual(input.slice(result.findings[0].start, result.findings[0].end), escaped);
  }
});
console.log(`${count}/${count} parser tests passed`);
