"use strict";
// Generated, deterministic property tests (no dependencies). A seeded PRNG builds synthetic
// logs from known secret and context fragments; every property is checked on every sample.
// All values are synthetic (FAKE/EXAMPLE markers, example.test / documentation ranges).
const assert = require("assert");
const engine = require("../src/sanitizer");

const SEED = Number(process.env.SAFEPASTE_PROPERTY_SEED || 20261007);
const SAMPLES = Number(process.env.SAFEPASTE_PROPERTY_SAMPLES || 160);
function prng(seed) {
  let state = seed >>> 0;
  return function () {
    state = (state + 0x6D2B79F5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const ALNUM = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
function make(rand) {
  const int = (n) => Math.floor(rand() * n);
  const pick = (list) => list[int(list.length)];
  const word = (n) => Array.from({ length: n }, () => ALNUM[int(ALNUM.length)]).join("");
  return { int, pick, word };
}

// Each secret fragment: text to embed, the exact synthetic values that must disappear, a JSON form.
const SECRET_KINDS = {
  password: (g) => { const v = "FakePw" + g.word(10); return { text: g.pick(["password=", "passwd: ", "Password = ", "DB_PASSWORD="]) + v, values: [v], key: "password", value: v }; },
  spacedJsonPassword: (g) => { const v = "Fake " + g.word(5) + " " + g.word(5); return { text: '{"password":' + JSON.stringify(v) + "}", values: [v], key: "password", value: v }; },
  secret: (g) => { const v = "FakeSecret" + g.word(10); return { text: "secret=" + v, values: [v], key: "secret", value: v }; },
  apiKey: (g) => { const v = "FAKEkey" + g.word(16); return { text: g.pick(["api_key=", "access_token=", "client_secret: "]) + v, values: [v], key: "api_key", value: v }; },
  bearer: (g) => { const v = "FAKEbearer" + g.word(20); return { text: "Authorization: Bearer " + v, values: [v], key: "authorization", value: "Bearer " + v }; },
  headerKey: (g) => { const v = "FAKEhdr" + g.word(14); return { text: "X-Api-Key: " + v, values: [v], key: "x-api-key", value: v }; },
  urlCredential: (g) => { const v = "FakeDb" + g.word(10); return { text: g.pick(["postgres", "mysql", "redis", "mongodb+srv"]) + "://svc:" + v + "@db.example.test:5432/app", values: [v], key: "dsn", value: "postgres://svc:" + v + "@db.example.test/app" }; },
  connectionString: (g) => { const v = "FakeCs" + g.word(10); return { text: "Server=db.example.test;Database=app;User Id=svc;Password=" + v + ";", values: [v], key: "conn", value: "Server=db.example.test;Database=app;Password=" + v + ";" }; },
  jdbc: (g) => { const v = "FakeJdbc" + g.word(8); return { text: "jdbc:postgresql://db.example.test:5432/app?user=svc&password=" + v, values: [v], key: "jdbc", value: "jdbc:postgresql://db.example.test/app?password=" + v }; },
  awsKey: (g) => { const v = "AKIAFAKE" + g.word(12).toUpperCase().replace(/[^A-Z2-9]/g, "Q"); return { text: "key " + v, values: [v], key: "aws_access_key_id", value: v }; },
  github: (g) => { const v = "ghp_FAKE" + g.word(32); return { text: "token " + v, values: [v], key: "note", value: "gh " + v }; },
  privateKey: (g) => {
    const body = ["FAKEKEY" + g.word(50), "SYNTHETIC" + g.word(48)];
    const type = g.pick(["PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY", "EC PRIVATE KEY"]);
    const block = "-----BEGIN " + type + "-----\n" + body.join("\n") + "\n-----END " + type + "-----";
    return { text: block, values: body, key: "key", value: block, block: true };
  },
  cookie: (g) => { const v = "FAKEsid" + g.word(14); return { text: "Cookie: theme=dark; sessionid=" + v, values: [v], key: "session_id", value: v }; },
  email: (g, pool) => { const v = pool.email; return { text: "user email " + v, values: [v], key: "email", value: v, reviewable: "EMAIL" }; },
  username: (g, pool) => { const v = pool.user; return { text: "username=" + v, values: [v], key: "username", value: v, reviewable: "USERNAME" }; },
  ipv4: (g, pool) => { const v = pool.ipv4; return { text: "client " + v + " connected", values: [v], key: "client_ip", value: v, reviewable: "IP_ADDRESS" }; },
  ipv6: (g, pool) => { const v = pool.ipv6; return { text: "peer " + v + " reset", values: [v], key: "peer", value: v, reviewable: "IPV6_ADDRESS" }; },
  mac: (g, pool) => { const v = pool.mac; return { text: "mac " + v + " up", values: [v], key: "mac", value: v, reviewable: "MAC_ADDRESS" }; }
};
const CONTEXT = [
  (g) => "request_id=req-" + g.int(99999), (g) => "status=" + g.pick([200, 404, 500, 503]),
  (g) => "latency_ms=" + g.int(900), (g) => "release=1." + g.int(9) + "." + g.int(9) + "." + g.int(9),
  () => "path=/var/log/app/server.log", (g) => "trace_id=" + g.word(12).toLowerCase(),
  () => "GET /api/v1/items", (g) => "build_id=2026.10." + g.int(30)
];
function pools(g, n) {
  return Array.from({ length: n }, (_, i) => ({
    email: "person" + i + "." + g.word(4).toLowerCase() + "@example.test",
    user: "fakeuser" + i + g.word(3).toLowerCase(),
    ipv4: "203.0.113." + (i + 1),
    ipv6: "2001:db8::" + (i + 1).toString(16) + ":" + g.int(65535).toString(16),
    mac: ["00", "1a", "2b", "3c", "4d", (i + 16).toString(16).padStart(2, "0")].join(g.pick([":", "-"]))
  }));
}

function sample(rand, options) {
  const g = make(rand);
  const people = pools(g, 4);
  const kinds = Object.keys(SECRET_KINDS).filter((kind) => !options || !options.only || options.only.indexOf(kind) !== -1);
  const lines = [];
  const secrets = [];
  const context = [];
  const count = 1 + g.int(6);
  for (let i = 0; i < count; i += 1) {
    const parts = [];
    const kind = g.pick(kinds);
    const secret = SECRET_KINDS[kind](g, g.pick(people));
    secret.kind = kind;
    secrets.push(secret);
    if (!secret.block && g.int(2)) { const c = g.pick(CONTEXT)(g); context.push(c); parts.push("level=info " + c); }
    parts.push(secret.text);
    if (!secret.block && g.int(2)) { const c = g.pick(CONTEXT)(g); context.push(c); parts.push(c); }
    lines.push(parts.join(" "));
  }
  return { input: lines.join(g.int(5) === 0 ? "\r\n" : "\n"), secrets, context };
}

const PROFILES = [{ profile: "strict" }, { profile: "support" }, { profile: "incident" },
  { profile: "custom", categories: { email: "REDACT", usernames: "REDACT", paths: "REDACT", network: "REDACT" } }];
const tests = [];
function test(name, run) { tests.push([name, run]); }
function forSamples(seedOffset, run, options) {
  const rand = prng(SEED + seedOffset);
  for (let i = 0; i < SAMPLES; i += 1) {
    const s = sample(rand, options);
    try { run(s, i); }
    catch (error) { error.message = "seed " + (SEED + seedOffset) + " sample " + i + ": " + error.message; throw error; }
  }
}
function mustHide(text, values, label) {
  for (const value of values) assert(!text.includes(value), label + " contains a synthetic secret (" + value.length + " chars)");
}
function lineColumn(source, index) {
  let line = 1; let start = 0;
  for (let i = 0; i < index; i += 1) {
    if (source[i] === "\n" || (source[i] === "\r" && source[i + 1] !== "\n")) { line += 1; start = i + 1; }
  }
  return { line, column: index - start + 1 };
}

test("high-risk secrets are gone from output and metadata in every profile and mode", () => {
  forSamples(1, (s) => {
    for (const profile of PROFILES) for (const mode of ["redaction", "pseudonymization"]) {
      const review = engine.createReview(s.input, Object.assign({ mode }, profile));
      const applied = review.apply();
      const highRisk = s.secrets.filter((secret) => !secret.reviewable);
      for (const secret of highRisk) mustHide(applied.sanitized, secret.values, profile.profile + "/" + mode + " output");
      mustHide(JSON.stringify({ findings: applied.findings, report: applied.report, policy: review.policy }),
        [].concat.apply([], s.secrets.map((secret) => secret.values)), "metadata");
      if (profile.profile === "strict" || profile.profile === "custom") {
        for (const secret of s.secrets) mustHide(applied.sanitized, secret.values, profile.profile + " output");
      }
    }
  });
});

test("findings are sorted, non-overlapping, positioned on original spans and rebuild the output", () => {
  forSamples(2, (s) => {
    const review = engine.createReview(s.input, { profile: "strict" });
    const applied = review.apply();
    let cursor = 0; const pieces = [];
    for (const f of applied.findings) {
      assert(f.start >= cursor && f.end > f.start && f.end <= s.input.length, "ordered non-overlapping span");
      assert.deepStrictEqual(f.position, lineColumn(s.input, f.start), "line/column of start");
      assert(/^"?\[[A-Z0-9_]+\]"?$/.test(f.replacement), "marker-only replacement");
      pieces.push(s.input.slice(cursor, f.start), f.action === "REDACT" ? f.replacement : s.input.slice(f.start, f.end));
      cursor = f.end;
    }
    pieces.push(s.input.slice(cursor));
    assert.strictEqual(pieces.join(""), applied.sanitized);
  });
});

test("fixed policy is deterministic across independent reviews and sessions", () => {
  forSamples(3, (s) => {
    for (const mode of ["redaction", "pseudonymization"]) {
      const a = engine.createSession().createReview(s.input, { profile: "support", mode }).apply();
      const b = engine.createSession().createReview(s.input, { profile: "support", mode }).apply();
      assert.strictEqual(a.sanitized, b.sanitized);
      assert.deepStrictEqual(a.findings, b.findings);
    }
  });
});

test("preserved diagnostic context is unchanged", () => {
  forSamples(4, (s) => {
    for (const profile of PROFILES) {
      const output = engine.createReview(s.input, profile).apply().sanitized;
      for (const c of s.context) assert(output.includes(c), profile.profile + " lost context " + JSON.stringify(c));
    }
  });
});

test("sanitizing twice is idempotent and never corrupts markers", () => {
  forSamples(5, (s) => {
    for (const profile of PROFILES) for (const mode of ["redaction", "pseudonymization"]) {
      const options = Object.assign({ mode }, profile);
      const once = engine.createSession().createReview(s.input, options).apply().sanitized;
      const twice = engine.createSession().createReview(once, options).apply().sanitized;
      assert.strictEqual(twice, once, profile.profile + "/" + mode);
      assert(!/\[(?:REDACTED_)?[A-Z0-9_]*\[/.test(once), "nested marker");
    }
  });
});

test("pseudonyms are a stable, injective function of value within a session; clear resets numbering", () => {
  forSamples(6, (s) => {
    const session = engine.createSession();
    const options = { profile: "strict", mode: "pseudonymization" };
    const review = session.createReview(s.input, options);
    const byValue = new Map(); const byMarker = new Map();
    for (const f of review.apply().findings) {
      if (!f.allowKeep) { assert(f.replacement.startsWith("[REDACTED_"), "high-risk never pseudonymized"); continue; }
      const value = s.input.slice(f.start, f.end);
      assert(/^\[[A-Z0-9]+_[1-9][0-9]*\]$/.test(f.replacement), "pseudonym marker syntax");
      if (byValue.has(value)) assert.strictEqual(byValue.get(value), f.replacement, "same value, same pseudonym");
      if (byMarker.has(f.replacement)) assert.strictEqual(byMarker.get(f.replacement), value, "different values, different pseudonyms");
      byValue.set(value, f.replacement); byMarker.set(f.replacement, value);
    }
    // A second review in the same session reuses the mapping.
    const again = session.createReview(s.input, options).apply();
    assert.strictEqual(again.sanitized, review.apply().sanitized);
    session.clear();
    assert.throws(() => review.apply(), /REVIEW_CLEARED/);
    const fresh = session.createReview(s.input, options).apply().findings.filter((f) => f.allowKeep);
    if (fresh.length) assert(/_1\]$/.test(fresh[0].replacement), "numbering restarts at 1 after clear");
  }, { only: ["email", "username", "ipv4", "ipv6", "mac", "password"] });
});

test("custom category flags and locked controls are honoured for every finding", () => {
  const controls = ["email", "usernames", "paths", "network"];
  const rand = prng(SEED + 7);
  forSamples(7, (s) => {
    const categories = {};
    for (const control of controls) categories[control] = rand() < 0.5 ? "KEEP" : "REDACT";
    const network = { preservePrivate: rand() < 0.5, preserveLoopback: rand() < 0.5 };
    const review = engine.createReview(s.input, { profile: "custom", categories, network });
    for (const f of review.findings) {
      if (["credentials", "tokens", "secrets"].indexOf(f.control) !== -1) {
        assert.strictEqual(f.action, "REDACT"); assert.strictEqual(f.allowKeep, false);
        assert.throws(() => review.apply({ [f.id]: "KEEP" }), /KEEP_FORBIDDEN/);
      } else {
        assert.strictEqual(f.action, categories[f.control], f.category + " follows custom flag");
      }
    }
    for (const locked of ["credentials", "tokens", "secrets"]) {
      assert.throws(() => engine.createReview("x", { profile: "custom", categories: { [locked]: "KEEP" } }), /KEEP_FORBIDDEN|INVALID/);
    }
  });
});

test("JSON documents with escapes stay valid JSON and hide decoded and escaped secret forms", () => {
  const rand = prng(SEED + 8);
  const g = make(rand);
  const nasty = ['"', "\\", "\n", "\t", "\u00e9", "\u2028", "<", "&", "\u0000", "🔒"];
  for (let i = 0; i < SAMPLES; i += 1) {
    const secret = "Fake" + g.pick(nasty) + g.word(6) + g.pick(nasty) + g.word(4);
    const key = g.pick(["password", "secret", "client_secret", "DB_PASSWORD", "aws_secret_access_key"]);
    const doc = { level: "info", request_id: "req-" + i, nested: { [key]: secret, list: [1, true, null, "release 1.2.3"] } };
    const text = JSON.stringify(g.int(2) ? doc : [doc], null, g.int(3));
    const keyed = g.int(2) ? text.replace('"' + key + '"', '"' + key.split("").map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("") + '"') : text;
    const output = engine.createReview(keyed, { profile: "strict" }).apply().sanitized;
    const parsed = JSON.parse(output);
    assert(!output.includes(JSON.stringify(secret).slice(1, -1)), "escaped secret visible (sample " + i + ")");
    assert(!JSON.stringify(parsed).includes(JSON.stringify(secret).slice(1, -1)), "decoded secret visible (sample " + i + ")");
    assert(output.includes('"request_id":') && output.includes("req-" + i), "context kept");
  }
});

test("hostile markup around secrets does not shield them and replacements are inert text", () => {
  const wrappers = [(t) => "<script>" + t + "</script>", (t) => '"><img src=x onerror="' + t + '">',
    (t) => "<!--" + t + "-->", (t) => "<svg><title>" + t + "</title></svg>", (t) => "javascript:/*" + t + "*/"];
  forSamples(9, (s) => {
    const hostile = s.input.split(/\r?\n/).map((line, i) => wrappers[i % wrappers.length](line)).join("\n");
    const applied = engine.createReview(hostile, { profile: "strict" }).apply();
    for (const secret of s.secrets) {
      if (secret.block) continue; // a PEM block split by markup on one line is a different shape
      mustHide(applied.sanitized, secret.values, "hostile output");
    }
    for (const f of applied.findings) assert(!/[<>]/.test(f.replacement + f.reason + f.description), "metadata stays inert");
  }, { only: ["password", "secret", "apiKey", "headerKey", "urlCredential", "github", "email", "username", "ipv4", "ipv6", "mac", "awsKey", "connectionString"] });
});

test("truncated / malformed nested logs fail closed or hide every fully contained secret", () => {
  const rand = prng(SEED + 10);
  const g = make(rand);
  for (let i = 0; i < SAMPLES; i += 1) {
    const v1 = "FakePw" + g.word(10); const v2 = "Fake " + g.word(4) + " " + g.word(4); const v3 = "FakeSecret" + g.word(8);
    const doc = JSON.stringify({ a: { b: [{ password: v1 }, { c: { secret: v3 } }], msg: "x" }, user: { password: v2 } });
    const cut = 1 + g.int(doc.length - 1);
    const truncated = doc.slice(0, cut) + g.pick(["", "\n", "}", "]]", "\nlevel=info"]);
    let output;
    try { output = engine.createReview(truncated, { profile: "strict" }).apply().sanitized; }
    catch (error) { assert(/^[A-Z][A-Z0-9_]+$/.test(String(error.code)), "coded failure"); continue; }
    for (const value of [v1, v2, v3]) {
      const at = truncated.indexOf(value);
      if (at !== -1) assert(!output.includes(value), "cut " + cut + " leaked a fully present secret");
    }
  }
});

test("network identifiers: IPv6 forms, MAC styles and policy classes are consistent", () => {
  const cases = [["::1", "loopback"], ["fe80::1%eth0", "link-local"], ["fd00:1234::5", "unique-local"], ["2001:db8::7", "other"], ["::ffff:10.0.0.9", "private"]];
  for (const [value, kind] of cases) {
    for (const wrap of [(v) => "addr " + v, (v) => "http://[" + v.replace("%", "%25") + "]:8080/x", (v) => '{"peer":"' + v + '"}']) {
      const input = wrap(value);
      const strict = engine.createReview(input, { profile: "strict" });
      assert(strict.findings.some((f) => f.control === "network"), kind + " detected in " + input);
      assert(!strict.apply().sanitized.includes(value.split("%")[0]), kind + " redacted under strict");
      const support = engine.createReview(input, { profile: "support" }).apply();
      const kept = support.findings.filter((f) => f.control === "network").every((f) => f.action === "KEEP");
      if (["loopback", "unique-local", "private"].indexOf(kind) !== -1) assert(kept, kind + " kept by support");
      if (kind === "other") assert(!kept, "documentation/global address redacted by support");
    }
  }
  for (const mac of ["00:1a:2b:3c:4d:5e", "00-1A-2B-3C-4D-5E"]) assert(engine.createReview("mac " + mac, { profile: "strict" }).findings.some((f) => f.category === "MAC_ADDRESS"));
  for (const notMac of ["00:11:22:33:44:55", "00:1a-2b:3c:4d:5e", "12:30:45"]) assert(!engine.createReview("x " + notMac, { profile: "strict" }).findings.some((f) => f.category === "MAC_ADDRESS"), notMac);
});

function main() {
  let failed = 0;
  for (const [name, run] of tests) {
    try { run(); console.log("PASS " + name); }
    catch (error) { failed += 1; console.log("FAIL " + name + "\n  " + error.message); }
  }
  console.log((tests.length - failed) + "/" + tests.length + " property tests passed (seed " + SEED + ", " + SAMPLES + " samples per property)");
  return failed ? 1 : 0;
}
if (require.main === module) process.exitCode = main();
module.exports = { prng: prng, sample: sample };
