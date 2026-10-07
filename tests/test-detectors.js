"use strict";
const assert = require("assert");
const engine = require("../src/sanitizer");
const tests = [];
function test(name, run) { tests.push([name, run]); }
// Every value below is synthetic test-only data (FAKE/example.test/documentation ranges), never real.
const strict = { profile: "strict" };
function out(text, options) { return engine.createReview(text, options || strict).apply().sanitized; }
function cats(text, options) { return engine.createReview(text, options || strict).findings.map(f => f.category); }
function legacy(text) { return engine.sanitize(text).sanitized; }
const GH = "ghp_" + "FAKE".repeat(9);
const GH_PAT = "github_pat_" + "F".repeat(22) + "_" + "A".repeat(59);
const GOOGLE = "AIza" + "FAKE_test-".repeat(3) + "FAKEX";
const BASIC = Buffer.from("fakeuser:fakepass").toString("base64");

test("GitHub and Google tokens require exact prefix and length", () => {
  assert.strictEqual(out("t " + GH + " " + GH_PAT), "t [REDACTED_GITHUB_TOKEN] [REDACTED_GITHUB_TOKEN]");
  assert.strictEqual(out("key " + GOOGLE + "."), "key [REDACTED_GOOGLE_API_KEY].");
  for (const near of ["ghp_" + "F".repeat(35), "ghp_" + "F".repeat(37), "ghx_" + "F".repeat(36), "AIza" + "F".repeat(34), "AIza" + "F".repeat(36)]) {
    assert.ok(!cats("v " + near).some(c => c === "GITHUB_TOKEN" || c === "GOOGLE_API_KEY"), near.slice(0, 4));
  }
});
test("Azure connection keys and explicit AWS secret fields redact only the value", () => {
  const azure = "DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey=RkFLRV9LRVlfVEVTVA==;EndpointSuffix=core.windows.net";
  assert.strictEqual(out(azure), "DefaultEndpointsProtocol=https;AccountName=fakeacct;AccountKey=[REDACTED_CLOUD_CREDENTIAL];EndpointSuffix=core.windows.net");
  assert.strictEqual(out("Endpoint=sb://fake.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=RkFLRV9TQVNfS0VZ"),
    "Endpoint=sb://fake.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccessKey=[REDACTED_CLOUD_CREDENTIAL]");
  assert.strictEqual(out("aws_secret_access_key = FAKEfakeFAKEfake1234/abcd"), "aws_secret_access_key = [REDACTED_CLOUD_CREDENTIAL]");
});
test("credential-bearing URLs redact userinfo; plain user@host stays legacy behavior", () => {
  assert.strictEqual(out("postgres://fakeuser:FakePass123@db.example.test:5432/app"), "postgres://[REDACTED_URL_CREDENTIALS]@db.example.test:5432/app");
  assert.strictEqual(legacy("mysql://fakeuser:FakePass123@db.example.test/app"), "mysql://[REDACTED_URL_CREDENTIALS]@db.example.test/app");
  const db = out("mongodb+srv://fakeuser:FakePass123@cluster.example.test/app?retryWrites=true");
  assert.ok(!/FakePass123|fakeuser/.test(db) && db.includes("[REDACTED_URL_CREDENTIALS]") && db.includes("retryWrites=true"));
  assert.ok(!out("redis://:FakePass123@cache.example.test:6379").includes("FakePass123"));
  const json = out('{"url":"postgres://fakeuser:Fake\\u0050ass1@db.example.test/x"}');
  assert.ok(!/Fake\\u0050ass1|FakePass1/.test(json) && JSON.parse(json).url.startsWith("postgres://[REDACTED_URL_CREDENTIALS]"));
});
test("JDBC/ODBC structured passwords redact; bare PWD paths keep legacy path handling", () => {
  assert.strictEqual(out("Driver={ODBC Driver 18};Server=db.example.test;Uid=fakeuser;Pwd={Fake;Pass};Encrypt=yes"),
    "Driver={ODBC Driver 18};Server=db.example.test;Uid=[REDACTED_USERNAME];Pwd={[REDACTED_PASSWORD]};Encrypt=yes");
  assert.strictEqual(out("Server=db;Database=app;User Id=fakeuser;Password=Fake Pass 1;"), "Server=db;Database=app;User Id=[REDACTED_USERNAME];Password=[REDACTED_PASSWORD];");
  assert.strictEqual(out("jdbc:oracle:thin:fakeuser/FakePass123@db.example.test:1521/XE").indexOf("FakePass123"), -1);
  assert.ok(!/FakePass123|fakeuser/.test(out("jdbc:sqlserver://db.example.test:1433;databaseName=app;user=fakeuser;password=FakePass123")));
  assert.strictEqual(legacy("PWD=/home/alice/project"), "PWD=/home/[REDACTED_USERNAME]/project");
  assert.strictEqual(out("PWD=/var/tmp/build"), "PWD=/var/tmp/build");
  assert.strictEqual(out("cd PWD; pwd=ok"), "cd PWD; pwd=ok");
});
test("private-key blocks redact whole block; unclosed block redacts to end; overlaps collapse", () => {
  const block = "-----BEGIN RSA PRIVATE KEY-----\nMIIFAKE password=FakePass1 " + GH + "\nFAKE\n-----END RSA PRIVATE KEY-----";
  const review = engine.createReview("before\n" + block + "\nafter", strict);
  assert.strictEqual(review.apply().sanitized, "before\n[REDACTED_PRIVATE_KEY]\nafter");
  assert.deepStrictEqual(review.findings.map(f => f.category), ["PRIVATE_KEY"]);
  assert.strictEqual(out("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEDATA\nnever closed 192.0.2.1"), "[REDACTED_PRIVATE_KEY]");
  assert.deepStrictEqual(JSON.parse(out('{"k":"-----BEGIN PRIVATE KEY-----\\nFAKE","b":"keep"}')), { k: "[REDACTED_PRIVATE_KEY]", b: "keep" });
  assert.strictEqual(out("-----BEGIN ENCRYPTED PRIVATE KEY-----\nA\n-----END ENCRYPTED PRIVATE KEY-----\n-----BEGIN EC PRIVATE KEY-----\nB\n-----END EC PRIVATE KEY-----"),
    "[REDACTED_PRIVATE_KEY]\n[REDACTED_PRIVATE_KEY]");
  assert.strictEqual(out("-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----"), "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----");
});
test("explicit session, cookie and header credentials redact values only", () => {
  assert.strictEqual(out("Cookie: sessionid=FAKEsess123; theme=dark"), "Cookie: sessionid=[REDACTED_SESSION_TOKEN]; theme=[REDACTED_COOKIE]");
  assert.strictEqual(out("Set-Cookie: sid=FAKE123abc; Path=/; HttpOnly"), "Set-Cookie: sid=[REDACTED_COOKIE]; Path=/; HttpOnly");
  // X-Api-Key keeps the higher-priority legacy API_KEY marker; other explicit headers use HEADER_CREDENTIAL.
  assert.strictEqual(out("X-Api-Key: FAKE-key-123456\nx-csrf-token=FAKEcsrf9876\nX-Auth-Token: FAKEauth5678"),
    "X-Api-Key: [REDACTED_API_KEY]\nx-csrf-token=[REDACTED_HEADER_CREDENTIAL]\nX-Auth-Token: [REDACTED_HEADER_CREDENTIAL]");
  assert.deepStrictEqual(JSON.parse(out('{"session_id":"FAKEsess123abc","Cookie":"a=FAKE1x; b=FAKE2y"}')),
    { session_id: "[REDACTED_SESSION_TOKEN]", Cookie: "a=[REDACTED_COOKIE]; b=[REDACTED_COOKIE]" });
  assert.strictEqual(out("session: started for worker"), "session: started for worker");
  assert.strictEqual(out("session_timeout=3600 session=closed"), "session_timeout=3600 session=closed");
});
test("Basic credentials require decodable printable user:password", () => {
  assert.strictEqual(out("proxy said Basic " + BASIC + " done"), "proxy said Basic [REDACTED_BASIC_CREDENTIALS] done");
  assert.strictEqual(out("Authorization: Basic " + BASIC), "Authorization: [REDACTED_AUTHORIZATION_HEADER]");
  assert.strictEqual(out("Proxy-Authorization: basic " + BASIC).indexOf(BASIC), -1);
  assert.strictEqual(out("Basic auth enabled for BasicConfig"), "Basic auth enabled for BasicConfig");
  assert.strictEqual(out("Basic " + Buffer.from("nocolonhere").toString("base64")), "Basic " + Buffer.from("nocolonhere").toString("base64"));
});
test("webhook URLs redact secret paths; URL secret query params redact values only", () => {
  assert.strictEqual(out("https://hooks.slack.com/services/TFAKE000/BFAKE000/FAKEFAKEFAKEFAKE"), "https://hooks.slack.com/services/[REDACTED_WEBHOOK_SECRET]");
  assert.strictEqual(out("https://discord.com/api/webhooks/000000/FAKE_TOKEN_abc"), "https://discord.com/api/webhooks/[REDACTED_WEBHOOK_SECRET]");
  assert.strictEqual(out("https://fake.webhook.office.com/webhookb2/FAKE-0000-guid/IncomingWebhook/FAKE"), "https://fake.webhook.office.com/webhookb2/[REDACTED_WEBHOOK_SECRET]");
  assert.strictEqual(out("GET https://api.example.test/v1/items?id=5&token=FAKEtok123&page=2"), "GET https://api.example.test/v1/items?id=5&token=[REDACTED_URL_SECRET]&page=2");
  assert.strictEqual(out("https://hooks.slack.com/docs/page"), "https://hooks.slack.com/docs/page");
  assert.strictEqual(out("https://example.test/a?id=1&page=2"), "https://example.test/a?id=1&page=2");
});
test("validated IPv6 forms and network policy classes", () => {
  assert.strictEqual(out("client 2001:db8::1 via [2001:db8::2]:8443 and http://[fe80::1%eth0]/ ::ffff:192.0.2.9"),
    "client [REDACTED_IPV6_ADDRESS] via [[REDACTED_IPV6_ADDRESS]]:8443 and http://[[REDACTED_IPV6_ADDRESS]]/ [REDACTED_IPV6_ADDRESS]");
  assert.strictEqual(out("2001:0db8:0000:0000:0000:ff00:0042:8329"), "[REDACTED_IPV6_ADDRESS]");
  const kinds = engine.createReview("::1 fd12:3456::9 fe80::1 ::ffff:192.168.1.20 2001:db8::1", strict).findings.map(f => f.networkKind);
  assert.deepStrictEqual(kinds, ["loopback", "unique-local", "link-local", "private", "other"]);
  assert.strictEqual(legacy("loopback ::1 then 2001:db8::1"), "loopback ::1 then [REDACTED_IPV6_ADDRESS]");
  assert.strictEqual(out("::1 fd12:3456::9 ::ffff:192.168.1.20 2001:db8::1", { profile: "support" }), "::1 fd12:3456::9 ::ffff:192.168.1.20 [REDACTED_IPV6_ADDRESS]");
  assert.strictEqual(out("2001:db8::1 00:1a:2b:3c:4d:5e", { profile: "incident" }), "2001:db8::1 00:1a:2b:3c:4d:5e");
  assert.strictEqual(engine.sanitize("2001:db8::1", { redactIpAddresses: false }).sanitized, "2001:db8::1");
});
test("malformed IPv6, versions, times, Rust/C++ scopes and IDs are preserved", () => {
  const keep = ["2001:db8:::1", "1:2:3:4:5:6:7:8:9", "12345::1", "2001:db8::g1", "std::io::Error Foo::bar dead::beef", "at 10:22:33.123",
    "ts 2026-10-07T10:22:33Z", "version 1:2:3", "v2:1:0", "release=2001:db8::1", "request_id=ab:cd:ef:01:23:45", "build_id=fe80::1",
    "build 10:20:30:40:50:60", "sha a1b2:c3d4", "::", "uuid 123e4567-e89b-12d3-a456-426614174000"];
  for (const text of keep) assert.strictEqual(out(text), text, text);
});
test("MAC addresses with one consistent separator", () => {
  assert.strictEqual(out("mac 00:1a:2b:3c:4d:5e and 00-1A-2B-3C-4D-5E"), "mac [REDACTED_MAC_ADDRESS] and [REDACTED_MAC_ADDRESS]");
  for (const text of ["00:1a-2b:3c:4d:5e", "00:1a:2b:3c:4d", "00:1a:2b:3c:4d:5e:6f", "0a-1b-2c-3d-4e-5f-6a"]) {
    assert.ok(!cats(text).includes("MAC_ADDRESS"), text);
  }
});
test("pseudonymization covers IPv6/MAC; secrets stay fully redacted; reruns are idempotent", () => {
  const session = engine.createSession();
  const options = { profile: "strict", mode: "pseudonymization" };
  const first = session.createReview("2001:db8::1 2001:DB8:0::1 fd00::5 00:1a:2b:3c:4d:5e 00-1A-2B-3C-4D-5E " + GH, options).apply().sanitized;
  assert.strictEqual(first, "[IPV6_1] [IPV6_1] [IPV6_2] [MAC_1] [MAC_1] [REDACTED_GITHUB_TOKEN]");
  assert.strictEqual(session.createReview(first, options).apply().sanitized, first);
  const sample = "Cookie: sid=FAKE1abc\npostgres://fakeuser:FakePass123@db.example.test/app\n" + "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----";
  const once = out(sample);
  assert.strictEqual(out(once), once);
  assert.strictEqual(legacy(once), once);
});
test("new credential categories are locked; findings and report never carry raw values", () => {
  const raw = ["FakePass123", GH, GOOGLE, BASIC, "FAKEsess123", "2001:db8::1", "00:1a:2b:3c:4d:5e", "FAKEFAKEFAKEFAKE"];
  const text = "postgres://fakeuser:FakePass123@db.example.test/x " + GH + " " + GOOGLE + " Basic " + BASIC +
    " Cookie: sid=FAKEsess123\n2001:db8::1 00:1a:2b:3c:4d:5e https://hooks.slack.com/services/T0/B0/FAKEFAKEFAKEFAKE";
  const review = engine.createReview(text, strict);
  const serialized = JSON.stringify({ findings: review.findings, report: review.report, analysis: engine.analyze(text, strict) });
  raw.forEach(value => assert.ok(!serialized.includes(value), "leak"));
  review.findings.filter(f => f.control !== "network").forEach(f => assert.strictEqual(f.allowKeep, false, f.category));
  const ids = review.findings.filter(f => f.control !== "network").map(f => f.id);
  ids.forEach(id => assert.throws(() => review.apply({ [id]: "KEEP" })));
  const applied = review.apply().sanitized;
  raw.forEach(value => assert.ok(!applied.includes(value), "output leak"));
});
test("adversarial bounded inputs complete without catastrophic backtracking", () => {
  const inputs = [":".repeat(200000), "a:".repeat(200000), "Basic " + "A".repeat(1000000), "Cookie: " + "a=b;".repeat(20000),
    "Server=x;" + "k=v;".repeat(150000), "-----BEGIN PRIVATE KEY-----\n".repeat(20000), "https://" + "a:".repeat(100000) + "@x",
    "jdbc:x:" + ";password=a".repeat(100000), "aa-".repeat(300000), "2001:db8::1 ".repeat(50000), "Driver={" + "}}".repeat(300000)];
  for (const text of inputs) {
    const started = Date.now();
    engine.createReview(text, strict).apply();
    assert.ok(Date.now() - started < 5000, "slow input " + text.slice(0, 12));
  }
});

let failed = 0;
for (const [name, run] of tests) {
  try { run(); console.log("PASS " + name); } catch (error) { failed += 1; console.log("FAIL " + name + ": " + error.message); }
}
console.log((tests.length - failed) + "/" + tests.length + " phase-7 detector tests passed");
process.exit(failed ? 1 : 0);
