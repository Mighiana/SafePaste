"use strict";
const assert = require("assert");
const engine = require("../src/sanitizer");
let count = 0;
function test(name, run) { run(); count += 1; console.log("PASS " + name); }
const networkInput = "127.0.0.1 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.2 198.51.100.1";
function review(profile, input = networkInput, extra = {}) {
  return engine.createReview(input, Object.assign({ profile: profile }, extra));
}
test("profiles are explicit, inspectable and deeply immutable", function () {
  const policies = engine.inspectPolicies();
  assert.deepStrictEqual(policies.map(p => p.name), ["strict", "support", "incident", "custom"]);
  policies.forEach(p => {
    assert(Object.isFrozen(p) && Object.isFrozen(p.categories) && Object.isFrozen(p.network));
    assert.deepStrictEqual(p.lockedCategories, ["credentials", "tokens", "secrets"]);
    assert.strictEqual(p.categories.credentials, "REDACT");
  });
  assert.strictEqual(engine.inspectPolicy().name, "legacy");
  assert(Object.isFrozen(engine.getCapabilities().formats));
});
test("legacy loopback behavior and scoped IPv4 opt-out remain unchanged", function () {
  assert.strictEqual(engine.sanitize("127.1.2.3").sanitized, "127.1.2.3");
  assert.strictEqual(engine.analyze("127.1.2.3").findings.length, 0);
  assert.strictEqual(engine.sanitize(networkInput, { redactIpAddresses: false }).redactionCount, 0);
  assert.strictEqual(engine.analyze(networkInput, { redactIpAddresses: false }).findings.length, 0);
});
test("strict redacts supported IPv4 including loopback", function () {
  const result = review("strict").apply();
  assert.strictEqual(result.report.redacted, 6);
  assert.strictEqual(result.report.kept, 0);
  assert(!result.sanitized.includes("127.0.0.1"));
  assert.deepStrictEqual(result.findings.map(f => f.networkKind), ["loopback", "private", "private", "private", "private", "other"]);
});
test("support preserves only RFC1918 private and loopback network contexts", function () {
  const result = review("support").apply();
  assert.strictEqual(result.report.totalFindings, 6);
  assert.strictEqual(result.report.kept, 5);
  assert.strictEqual(result.report.redacted, 1);
  assert.strictEqual(result.sanitized, "127.0.0.1 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.2 [REDACTED_IP_ADDRESS]");
  const boundary = review("support", "172.15.255.255 172.32.0.0 192.169.1.1 169.254.1.1").apply();
  assert.strictEqual(boundary.report.redacted, 4);
});
test("incident preserves network evidence but redacts credentials and identities", function () {
  const result = review("incident", "password=Fake123\nuser=alice\ncontact=alice@example.test\nclient_ip=198.51.100.1").apply();
  assert.strictEqual(result.report.redacted, 3);
  assert.strictEqual(result.report.kept, 1);
  assert(result.sanitized.includes("198.51.100.1"));
  assert(!result.sanitized.includes("Fake123") && !result.sanitized.includes("alice"));
});
test("custom safe defaults match strict and independent controls work", function () {
  assert.strictEqual(review("custom").apply().sanitized, review("strict").apply().sanitized);
  const result = review("custom", "user=alice email=alice@example.test path=/home/alice/log client_ip=198.51.100.1", {
    categories: { usernames: "KEEP", email: "KEEP", paths: "KEEP", network: "KEEP" }
  }).apply();
  assert.strictEqual(result.report.redacted, 0);
  assert.strictEqual(result.report.kept, 4);
  assert(result.sanitized.includes("alice"));
});
test("custom network exceptions are independent and visible", function () {
  const custom = review("custom", networkInput, { network: { preserveLoopback: true } });
  assert.strictEqual(custom.policy.network.preserveLoopback, true);
  assert.strictEqual(custom.policy.network.preservePrivate, false);
  assert.strictEqual(custom.apply().report.kept, 1);
  const privateOnly = review("custom", networkInput, { network: { preservePrivate: true } });
  assert.strictEqual(privateOnly.apply().report.kept, 4);
});
test("locked high-risk categories cannot be disabled", function () {
  ["credentials", "tokens", "secrets"].forEach(control => {
    assert.throws(() => review("custom", "", { categories: { [control]: "KEEP" } }), e => e.code === "KEEP_FORBIDDEN");
  });
});
test("ambiguous network override is deterministic and does not mutate defaults", function () {
  const session = review("strict", "Firmware 1.2.3.4 installed. user=alice");
  const id = session.findings[0].id;
  const override = { [id]: "KEEP" };
  assert(session.apply(override).sanitized.includes("1.2.3.4"));
  assert(!session.apply().sanitized.includes("1.2.3.4"));
  assert.deepStrictEqual(session.apply(override), session.apply(override));
  assert.strictEqual(session.findings[0].action, "REDACT");
  assert.strictEqual(session.apply(override).report.kept, 1);
});
test("preserved findings can be explicitly redacted", function () {
  const session = review("support", "client_ip=127.0.0.1");
  assert.strictEqual(session.findings[0].action, "KEEP");
  const result = session.apply({ [session.findings[0].id]: "REDACT" });
  assert.strictEqual(result.sanitized, "client_ip=[REDACTED_IP_ADDRESS]");
  assert.strictEqual(result.report.redacted, 1);
  assert.strictEqual(result.findings[0].policyReason, "human-override");
});
test("identity/email/path finding overrides supported without echoing raw values", function () {
  const input = "user=alice contact=alice@example.test path=/home/alice/log";
  const session = review("strict", input);
  const overrides = Object.fromEntries(session.findings.map(f => [f.id, "KEEP"]));
  const result = session.apply(overrides);
  assert.strictEqual(result.sanitized, input);
  assert(!JSON.stringify(result.report).includes("alice"));
  assert(!JSON.stringify(result.findings).includes("example.test"));
});
test("all detected high-risk secret types reject individual KEEP", function () {
  const input = "Authorization: Bearer FakeToken123456789\nBearer FakeToken123456789\neyJFAKETEST00.eyJFAKETEST00.FAKETEST00\nAKIA0000000000000000\nxoxb-SYNTHETIC-TEST-ONLY-0000000000\napi_key=FakeCredential12345\nsecret=Fake123\npassword=Fake123";
  const session = review("strict", input);
  assert.strictEqual(session.findings.length, 8);
  session.findings.forEach(f => {
    assert.strictEqual(f.allowKeep, false);
    assert.throws(() => session.apply({ [f.id]: "KEEP" }), e => e.code === "KEEP_FORBIDDEN");
  });
});
test("credential overlap remains locked even when email/network are preserved", function () {
  const session = review("custom", '{"password":"alice@example.test 198.51.100.1"}', { categories: { email: "KEEP", network: "KEEP" } });
  assert.strictEqual(session.findings.length, 1);
  assert.strictEqual(session.findings[0].category, "PASSWORD");
  assert.throws(() => session.apply({ "finding-1": "KEEP" }), e => e.code === "KEEP_FORBIDDEN");
  assert.strictEqual(JSON.parse(session.apply().sanitized).password, "[REDACTED_PASSWORD]");
});
test("JSON escaped network values classify safely and keep original encoding", function () {
  const input = String.raw`{"ip":"10\u002e1.2.3","username":"alice"}`;
  const session = review("support", input);
  assert.strictEqual(session.findings[0].networkKind, "private");
  assert(session.apply().sanitized.includes(String.raw`10\u002e1.2.3`));
  const result = session.apply({ "finding-1": "REDACT" });
  assert.strictEqual(JSON.parse(result.sanitized).ip, "[REDACTED_IP_ADDRESS]");
});
test("profiles retain diagnostic exceptions without suppressing secret rules", function () {
  engine.getCapabilities().profiles.forEach(profile => {
    const result = review(profile, '{"release":"1.2.3.4","request_id":"AKIA0000000000000000","client_ip":"198.51.100.1"}').apply();
    assert(result.sanitized.includes('"release":"1.2.3.4"'));
    assert(!result.sanitized.includes("AKIA0000000000000000"));
  });
});
test("invalid/unknown policy inputs fail closed with value-free errors", function () {
  [ [{profile:"typo"}, "UNKNOWN_PROFILE"], [{profile:""}, "UNKNOWN_PROFILE"], [{profile:"strict",redactIpAddresses:false}, "AMBIGUOUS_POLICY"],
    [{profile:"support",categories:{}}, "CUSTOM_ONLY"], [{profile:"custom",categories:{cloud:"KEEP"}}, "UNKNOWN_CATEGORY"],
    [{profile:"custom",categories:{email:false}}, "INVALID_ACTION"], [{profile:"custom",network:{private:true}}, "INVALID_NETWORK_POLICY"],
    [{profile:"custom",network:{preserveLoopback:"yes"}}, "INVALID_NETWORK_POLICY"], [{profiles:"strict"}, "UNKNOWN_OPTION"],
    [{profile:"strict",format:""}, "UNKNOWN_FORMAT"], [[], "INVALID_OPTIONS"], [{profile:"custom",categories:[]}, "INVALID_CATEGORIES"]
  ].forEach(([options, code]) => assert.throws(() => engine.createReview("FakeSecret123", options), e => e.code === code && !e.message.includes("FakeSecret123")));
});
test("unknown IDs, invalid override actions and injected shapes are rejected", function () {
  const session = review("strict", "user=alice");
  assert.throws(() => session.apply({ "finding-999": "KEEP" }), e => e.code === "UNKNOWN_FINDING");
  assert.throws(() => session.apply({ "finding-1": "replace with arbitrary secret" }), e => e.code === "INVALID_ACTION");
  assert.throws(() => session.apply(["KEEP"]), e => e.code === "INVALID_OVERRIDES");
  assert.throws(() => session.apply(JSON.parse('{"__proto__":"KEEP"}')), e => e.code === "UNKNOWN_FINDING");
  assert.throws(() => session.apply(Object.create({ "finding-1": "KEEP" })), e => e.code === "INVALID_OVERRIDES");
  assert.strictEqual(session.apply().report.redacted, 1);
});
test("report counts and action metadata reflect final overrides without original text", function () {
  const session = review("support", "user=alice ip=10.1.2.3 secret=FakeSecret123");
  const result = session.apply({ "finding-1": "KEEP", "finding-2": "REDACT" });
  assert.strictEqual(result.report.totalFindings, 3);
  assert.strictEqual(result.report.redacted, 2);
  assert.strictEqual(result.report.kept, 1);
  assert.deepStrictEqual(result.report.categoryCounts.network, { detected: 1, redacted: 1, kept: 0 });
  assert.strictEqual(result.report.networkEgress, "none");
  assert.strictEqual(result.report.persistentStorage, "none");
  ["alice", "10.1.2.3", "FakeSecret123"].forEach(value => assert(!JSON.stringify(result.report).includes(value)));
  assert(Object.isFrozen(result.report.categoryCounts.network));
});
test("legacy result with explicit profile counts only actual redactions", function () {
  const result = engine.sanitize("10.1.2.3 user=alice", { profile: "support" });
  assert.strictEqual(result.redactionCount, 1);
  assert.deepStrictEqual(result.categories, ["USERNAME"]);
  assert.strictEqual(result.matches[0].text, "alice");
});
test("finding count bound fails without partial output", function () {
  const input = "a@b.test ".repeat(engine.getCapabilities().maxCandidates + 1);
  assert.throws(() => review("strict", input, { format: "text" }), e => e.code === "FINDING_LIMIT");
});
test("override count bound and clear fail without output", function () {
  const session = review("strict", "user=alice");
  const overrides = Object.fromEntries(Array.from({ length: engine.getCapabilities().maxOverrides + 1 }, (_, i) => [String(i), "KEEP"]));
  assert.throws(() => session.apply(overrides), e => e.code === "OVERRIDE_LIMIT");
  session.clear();
  assert.throws(() => session.apply({}), e => e.code === "REVIEW_CLEARED");
});
test("plain options/overrides accept other JS realms without accepting custom prototypes", function () {
  const vm = require("vm");
  const options = vm.runInNewContext("({profile:'custom', categories:{network:'KEEP'}})");
  const session = engine.createReview("user=alice 198.51.100.1", options);
  assert.strictEqual(session.apply().report.kept, 1);
  assert.strictEqual(session.apply(vm.runInNewContext("({'finding-1':'KEEP'})")).report.kept, 2);
  assert.throws(() => session.apply(vm.runInNewContext("[]")), e => e.code === "INVALID_OVERRIDES");
  const disguised = Object.create(Object.assign(Object.create(null), { constructor: Object, profile: "incident" }));
  assert.throws(() => engine.createReview("", disguised), e => e.code === "INVALID_OPTIONS");
});
console.log(`${count}/${count} policy tests passed`);
