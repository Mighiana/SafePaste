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

test("secret-suffix keys are detected in free text, not only in parsed fields (was: leak inside markup/prose)", () => {
  // explicitCategory() already treated DB_PASSWORD etc. as credentials in env/logfmt units, but the
  // text rules used \bpassword\b, which never matches after "_", so text-format input leaked them.
  for (const [input, secret] of [["<!--DB_PASSWORD=FakePwHidden1-->", "FakePwHidden1"],
    ["run -MY_DB_PASSWORD=FakePwHidden2 ok", "FakePwHidden2"], ["<b>APP_SECRET=FakeSecretHidden3</b>", "FakeSecretHidden3"],
    ["<b>STRIPE_API_KEY=FAKEkeyHidden4444</b>", "FAKEkeyHidden4444"], ["<i>GH_AUTH_TOKEN: FAKEtokHidden5</i>", "FAKEtokHidden5"]]) {
    for (const format of ["auto", "text"]) hidden(input, secret, { profile: "strict", format });
  }
  // Unsuffixed / unrelated keys are unchanged.
  assert.strictEqual(sanitized("<b>AUTH_TOKEN=keepme1</b>"), "<b>AUTH_TOKEN=keepme1</b>");
  assert.strictEqual(sanitized("<b>password_hint=x1 policy</b>"), "<b>password_hint=x1 policy</b>");
});

test("a username followed by markup or punctuation is still redacted (was: full leak)", () => {
  assert.strictEqual(sanitized("<b>username=fakeuserR1</b>"), "<b>username=[REDACTED_USERNAME]</b>");
  assert.strictEqual(sanitized("username=fakeuserR2)"), "username=[REDACTED_USERNAME])");
  assert.strictEqual(sanitized("level=info user=fakeuserR3!"), "level=info user=[REDACTED_USERNAME]!");
  assert.strictEqual(sanitized("javascript:/*username=fakeuserR4*/"), "javascript:/*username=[REDACTED_USERNAME]*/");
  assert.strictEqual(sanitized('{"username":"fakeuserR5</b>"}'), '{"username":"[REDACTED_USERNAME]</b>"}');
  // Markers and non-identity values stay untouched.
  assert.strictEqual(sanitized("user=[REDACTED_USERNAME]) a=1"), "user=[REDACTED_USERNAME]) a=1");
  assert.strictEqual(sanitized("user=alice:pw x=1"), "user=alice:pw x=1");
});

test("output that starts with a marker is not re-sniffed as JSON (was: second pass swallowed context)", () => {
  const input = "-----BEGIN PRIVATE KEY-----\nFAKEKEYSYNTHETICabc\n-----END PRIVATE KEY-----\n" +
    "Authorization: Bearer FAKEbearerSYNTHETIC123 request_id=req-1\nlevel=info x=1";
  const once = sanitized(input);
  assert.strictEqual(once, "[REDACTED_PRIVATE_KEY]\nAuthorization: [REDACTED_AUTHORIZATION_HEADER] request_id=req-1\nlevel=info x=1");
  const second = engine.createReview(once, { profile: "strict" });
  assert.notStrictEqual(second.report.format, "json");
  assert.strictEqual(second.apply().sanitized, once);
  // Real JSON (and malformed JSON) is still sniffed as before.
  assert.strictEqual(engine.createReview('["a"]').report.format, "json");
  assert.strictEqual(engine.createReview('[INFO] password=FakeP1').report.parseStatus, "malformed-json-fallback");
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

test("network controls name every address class they change (was: labels said IPv4 only)", () => {
  const html = require("fs").readFileSync(require("path").join(__dirname, "..", "index.html"), "utf8");
  const label = id => {
    const match = html.match(new RegExp('<label><input id="' + id + '"[^>]*>([^<]*)</label>'));
    assert(match, id + " label");
    return match[1];
  };
  const classes = { IP_ADDRESS: "IPv4", IPV6_ADDRESS: "IPv6", MAC_ADDRESS: "MAC" };
  const network = engine.inspectDetectors().filter(detector => detector.control === "network");
  assert.deepStrictEqual(network.map(detector => detector.category).sort(), Object.keys(classes).sort());
  const input = "a=10.1.2.3 b=fd12:3456:789a::1 c=aa:bb:cc:dd:ee:ff d=127.0.0.1 e=::1";
  const kept = sanitized(input, { profile: "custom", categories: { network: "KEEP" } });
  const legacyOff = sanitized(input, { redactIpAddresses: false });
  const help = html.match(/<span class="toggle-help">([^<]*)<\/span>/)[1];
  for (const detector of network) {
    assert(label("category-network").includes(classes[detector.category]), classes[detector.category]);
    assert(help.includes(classes[detector.category]) || detector.category === "IP_ADDRESS", "legacy help " + detector.category);
  }
  assert.strictEqual(kept, input);
  assert.strictEqual(legacyOff, input);
  const loopback = sanitized(input, { profile: "custom", network: { preserveLoopback: true } });
  assert(loopback.includes("d=127.0.0.1") && loopback.includes("e=::1"));
  assert(label("preserve-loopback").includes("127/8") && label("preserve-loopback").includes("::1") && help.includes("::1"));
  const privateKept = sanitized(input, { profile: "custom", network: { preservePrivate: true } });
  assert(privateKept.includes("a=10.1.2.3") && privateKept.includes("b=fd12:3456:789a::1"));
  assert(label("preserve-private").includes("RFC1918") && label("preserve-private").includes("fc00::/7"));
});

let failed = 0;
for (const [name, run] of tests) {
  try { run(); console.log("PASS " + name); }
  catch (error) { failed += 1; console.log("FAIL " + name + "\n  " + error.message); }
}
console.log((tests.length - failed) + "/" + tests.length + " regression tests passed");
process.exitCode = failed ? 1 : 0;
