"use strict";
// Phase 11 extended red-team suite against the current engine API (createReview / profiles).
// The legacy suite (evals/run-red-team.js, 15 cases on the legacy sanitize() API) is unchanged.
// Every value below is synthetic test data. STATUS is computed, never asserted by hand:
//   PASS        every "hidden" value is gone and every "preserved" value is still present
//   KNOWN MISS  the case is documented as a miss and at least one hidden value still survives
//   FAIL        the actual result differs from the documented expectation in either direction
// Usage: node evals/run-red-team-extended.js [--markdown]
const engine = require("../src/sanitizer");

const strict = { profile: "strict" };
const cases = [
  // Secret formatting variations
  { id: "RT-X01", attack: "single, double and backtick quotes", input: "password='FakeRtq1' secret=\"FakeRtq2\" api_key=`FAKErtq3key000000`", hidden: ["FakeRtq1", "FakeRtq2", "FAKErtq3key000000"], expected: "All three quoted values redacted" },
  { id: "RT-X02", attack: "colon vs equals, spaces around separator", input: "password: FakeRtc1\npassword=FakeRtc2\npassword : FakeRtc3", hidden: ["FakeRtc1", "FakeRtc2", "FakeRtc3"], expected: "Every separator style redacted" },
  { id: "RT-X03", attack: "mixed-case key and tab separators", input: "PassWord\t=\tFakeTabPw1", hidden: ["FakeTabPw1"], expected: "Key match is case-insensitive; tabs allowed" },
  { id: "RT-X04", attack: "token punctuation and wrapping parentheses", input: "token: ghp_FAKErtpUNCT0000000000000000000000000. (ghp_FAKErtpUNCT0000000000000000000000001)", hidden: ["ghp_FAKErtpUNCT0000000000000000000000000", "ghp_FAKErtpUNCT0000000000000000000000001"], preserved: [". (", ")"], expected: "GitHub tokens redacted, punctuation kept" },
  { id: "RT-X05", attack: "bearer token followed by a comma", input: "auth=Bearer FAKErtBearer000000000, retry=1", hidden: ["FAKErtBearer000000000"], preserved: ["retry=1"], expected: "Bearer value redacted, later field kept" },
  { id: "RT-X06", attack: "very long credential value (5,000 chars)", input: "password=" + "F".repeat(5000) + " ok=1", hidden: ["F".repeat(40)], preserved: ["ok=1"], expected: "Whole value redacted, no truncation leak" },
  // JSON escaping and nested structures
  { id: "RT-X07", attack: "credential inside a JSON-encoded string", input: '{"msg":"{\\"password\\":\\"FakeNested1\\"}"}', hidden: ["FakeNested1"], expected: "Escaped inner pair redacted" },
  { id: "RT-X08", attack: "unicode-escaped JSON key", input: '{"pass\\u0077ord":"FakeEsc1","request_id":"req-x08"}', hidden: ["FakeEsc1"], preserved: ["req-x08"], expected: "Decoded key classified; request id kept" },
  { id: "RT-X09", attack: "marker text planted before a real secret in JSON", input: '{"note":"[REDACTED_PASSWORD]","password":"FakeJ1"}', hidden: ["FakeJ1"], expected: "Planted marker does not shield the real value" },
  { id: "RT-X10", attack: "secret appended to a spoofed marker", input: "password=[REDACTED_PASSWORD]FakeTail99", hidden: ["FakeTail99"], expected: "Spoofed marker prefix does not shield the tail" },
  { id: "RT-X11", attack: "YAML-style indented block", input: "db:\n  password: FakeYaml1\n  user: fakeyamluser", hidden: ["FakeYaml1", "fakeyamluser"], expected: "Indented key: value redacted (no YAML parser)" },
  { id: "RT-X12", attack: "malformed NDJSON with truncated last line", input: '{"password":"Fake Nd 1"}\n{"api_key":"FAKEndjson00000002"', hidden: ["Fake Nd 1", "FAKEndjson00000002"], expected: "Fallback lexes both pairs" },
  // Headers
  { id: "RT-X13", attack: "CRLF header block", input: "Host: a.test\r\nAuthorization: Bearer FAKErtCRLF0000000\r\nX-Api-Key: FAKErtCRLFkey000\r\n", hidden: ["FAKErtCRLF0000000", "FAKErtCRLFkey000"], preserved: ["Host: a.test"], expected: "Both credential headers redacted" },
  { id: "RT-X14", attack: "folded (continuation-line) Authorization header", input: "Authorization:\n  Bearer FAKErtFold00000000", hidden: ["FAKErtFold00000000"], expected: "Continuation value redacted" },
  { id: "RT-X15", attack: "Cookie and Set-Cookie values", input: "Cookie: session=FAKEcookieSess000; theme=dark\nSet-Cookie: sid=FAKEsetCookie0000; Path=/; HttpOnly", hidden: ["FAKEcookieSess000", "FAKEsetCookie0000"], preserved: ["Path=/; HttpOnly"], expected: "Cookie values redacted, attributes kept" },
  // Embedded credentials and connection secrets
  { id: "RT-X16", attack: "credentials embedded in a database URL", input: "postgres://fakeu:FakePgPw1@db.test/app", hidden: ["FakePgPw1"], preserved: ["@db.test/app"], expected: "userinfo redacted, host kept" },
  { id: "RT-X17", attack: "credential in a URL query string", input: "https://h.test/cb?password=FakeQp1&x=1", hidden: ["FakeQp1"], expected: "Query password redacted" },
  { id: "RT-X18", attack: "ADO.NET connection string", input: "Server=db.test;User Id=fakeado;Password=FakeAdoPw1;", hidden: ["FakeAdoPw1"], expected: "Password segment redacted" },
  { id: "RT-X19", attack: "webhook URL secret path", input: "https://hooks.slack.com/services/TFAKE0000/BFAKE0000/FAKEwebhookSecret000000", hidden: ["FAKEwebhookSecret000000"], expected: "Webhook secret redacted" },
  // Unicode separators
  { id: "RT-X20", attack: "NBSP and ideographic-space separators", input: "password\u00a0=\u00a0FakeNbsp1\npassword\u3000=\u3000FakeIdeo1", hidden: ["FakeNbsp1", "FakeIdeo1"], expected: "Unicode spaces treated as whitespace" },
  { id: "RT-X21", attack: "U+2028 line separator after a value", input: "password=FakeLs1\u2028next=1", hidden: ["FakeLs1"], expected: "Value ends at the separator and is redacted" },
  { id: "RT-X22", attack: "full-width equals sign", input: "password\uff1dFakeFullW1", hidden: ["FakeFullW1"], status: "known-miss", expected: "Redacted", note: "Only ASCII : and = are separators" },
  { id: "RT-X23", attack: "zero-width space inside the key", input: "pass\u200bword=FakeZw1", hidden: ["FakeZw1"], status: "known-miss", expected: "Redacted", note: "Keys are matched literally" },
  // Renamed / unrecognized fields
  { id: "RT-X24", attack: "renamed field pwd=", input: "pwd=FakeRen1", hidden: ["FakeRen1"], status: "known-miss", expected: "Redacted", note: "pwd is not a credential key (PWD is a path variable)" },
  { id: "RT-X25", attack: "renamed field passphrase=", input: "passphrase=FakeRen2", hidden: ["FakeRen2"], status: "known-miss", expected: "Redacted", note: "Unlisted key name" },
  { id: "RT-X26", attack: "bare token= with a non-token-shaped value", input: "token=FakeRen3", hidden: ["FakeRen3"], status: "known-miss", expected: "Redacted", note: "Bare token key is not classified" },
  { id: "RT-X27", attack: "XML element instead of key=value", input: "<password>FakeXml1</password>", hidden: ["FakeXml1"], status: "known-miss", expected: "Redacted", note: "No XML parsing" },
  { id: "RT-X28", attack: "prefixed key inside an HTML comment", input: "<!--APP_DB_PASSWORD=FakeHc1-->", hidden: ["FakeHc1"], expected: "Suffix key recognised in text (phase 11 fix)" },
  // Private key blocks
  { id: "RT-X29", attack: "OpenSSH private key block", input: "pre\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAFAKE\nFAKEline2\n-----END OPENSSH PRIVATE KEY-----\npost", hidden: ["b3BlbnNzaC1rZXktdjEAAAAAFAKE", "FAKEline2", "BEGIN OPENSSH"], preserved: ["pre\n", "\npost"], expected: "Whole block replaced" },
  { id: "RT-X30", attack: "unterminated private key block", input: "-----BEGIN PRIVATE KEY-----\nFAKEunterminatedKEYdata\nmore", hidden: ["FAKEunterminatedKEYdata", "more"], expected: "Fail closed to end of input" },
  { id: "RT-X31", attack: "lowercase PEM header", input: "-----begin private key-----\nFAKElowerPEM\n-----end private key-----", hidden: ["FAKElowerPEM"], status: "known-miss", expected: "Redacted", note: "PEM labels are matched case-sensitively" },
  { id: "RT-X32", attack: "public key and certificate are not secrets", input: "-----BEGIN PUBLIC KEY-----\nFAKEpub\n-----END PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----\nFAKEcert\n-----END CERTIFICATE-----", preserved: ["FAKEpub", "FAKEcert"], expected: "Preserved" },
  // Malformed IPs and ambiguous versions
  { id: "RT-X33", attack: "IPv4 with port, CIDR and leading zeros", input: "peer 203.0.113.9:443 allow 198.51.100.0/24 old 010.001.002.003", hidden: ["203.0.113.9", "198.51.100.0", "010.001.002.003"], preserved: [":443", "/24"], expected: "Addresses redacted, port/prefix kept" },
  { id: "RT-X34", attack: "out-of-range octets", input: "bad 999.999.999.999 and 256.1.1.1", preserved: ["999.999.999.999", "256.1.1.1"], expected: "Invalid IPv4 preserved" },
  { id: "RT-X35", attack: "IPv6 in brackets, zone id, IPv4-mapped", input: "http://[2001:db8::7]:8080/x fe80::1%eth0 ::ffff:203.0.113.5", hidden: ["2001:db8::7", "fe80::1", "203.0.113.5"], preserved: [":8080/x"], expected: "All three IPv6 forms redacted" },
  { id: "RT-X36", attack: "dotted versions in explicit version fields", input: "release=1.2.3.4 app_version: 10.0.0.1 build 2026.10.07.1", preserved: ["1.2.3.4", "10.0.0.1", "2026.10.07.1"], expected: "Version context preserved" },
  { id: "RT-X37", attack: "bare IPv4-shaped firmware version", input: "Firmware 1.2.3.4 installed", hidden: ["1.2.3.4"], expected: "Over-redacted (documented Manual Test 6 trade-off)" },
  { id: "RT-X38", attack: "dotted MAC (Cisco aabb.ccdd.eeff)", input: "mac aabb.ccdd.eeff", hidden: ["aabb.ccdd.eeff"], status: "known-miss", expected: "Redacted", note: "Only colon/hyphen MAC forms" },
  // Policies and identity
  { id: "RT-X39", attack: "support profile keeps private/loopback, removes public and identity", input: "client 10.1.2.3 peer 203.0.113.9 lo 127.0.0.1 user fake.p@example.test password=FakeProf1", options: { profile: "support" }, hidden: ["203.0.113.9", "fake.p@example.test", "FakeProf1"], preserved: ["10.1.2.3", "127.0.0.1"], expected: "Policy applied as documented" },
  { id: "RT-X40", attack: "custom profile tries to KEEP locked credentials", input: "password=FakeLock1", options: { profile: "custom", categories: { credentials: "KEEP" } }, expectError: "KEEP_FORBIDDEN", expected: "Policy rejected (credentials are locked to REDACT)" },
  { id: "RT-X41", attack: "per-finding KEEP override on a credential", input: "password=FakeLock2 email fake.k@example.test", keepCategory: "PASSWORD", expectError: "KEEP_FORBIDDEN", expected: "Override rejected; nothing revealed" },
  { id: "RT-X42", attack: "per-finding KEEP override on an email", input: "password=FakeLock3 email fake.k@example.test", keepCategory: "EMAIL", hidden: ["FakeLock3"], preserved: ["fake.k@example.test"], expected: "Only the reviewed email is kept" },
  { id: "RT-X43", attack: "pseudonym-looking text planted next to a real email", input: "contact [EMAIL_1] or fake.person@example.test", options: { profile: "strict", mode: "pseudonymization" }, hidden: ["fake.person@example.test"], preserved: ["contact [EMAIL_1] or [EMAIL_2]"], expected: "Real email gets the next free pseudonym; planted text stays inert" },
  { id: "RT-X44", attack: "obfuscated email with [at]/[dot]", input: "fake.person [at] example [dot] test", hidden: ["fake.person [at] example"], status: "known-miss", expected: "Redacted", note: "No natural-language de-obfuscation (by design)" },
  { id: "RT-X45", attack: "tilde home path", input: "cat ~fakeuserx/.ssh/id_rsa", hidden: ["fakeuserx"], status: "known-miss", expected: "Redacted", note: "Only /home, /Users and C:\\Users paths" },
  { id: "RT-X46", attack: "hostile markup around secrets", input: "<script>password=FakeXss1</script><img src=x onerror=\"api_key=FAKExss2key000000\">", hidden: ["FakeXss1", "FAKExss2key000000"], preserved: ["<script>password=", " src=x onerror=\"api_key="], expected: "Values redacted, markup kept as inert text", note: "markup glued to an unquoted password is absorbed into the redaction, because passwords may contain < and >" }
];

function run(testCase) {
  const options = Object.assign({}, strict, testCase.options || {});
  let review;
  let output;
  let applied;
  try {
    review = engine.createReview(testCase.input, options);
    const overrides = {};
    for (const f of review.findings) if (f.category === testCase.keepCategory) overrides[f.id] = "KEEP";
    applied = review.apply(testCase.keepCategory ? overrides : undefined);
    output = applied.sanitized;
  } catch (error) {
    const ok = testCase.expectError && error.code === testCase.expectError;
    return { testCase, status: ok ? "PASS" : "FAIL", actual: "Rejected with " + (error.code || "an uncoded error"), format: review ? review.report.format : "-" };
  }
  if (testCase.expectError) return { testCase, status: "FAIL", actual: "Accepted; expected " + testCase.expectError, format: review.report.format };
  const leaked = (testCase.hidden || []).filter((value) => output.includes(value));
  const lost = (testCase.preserved || []).filter((value) => !output.includes(value));
  const documentedMiss = testCase.status === "known-miss";
  let status;
  if (documentedMiss) status = leaked.length && !lost.length ? "KNOWN MISS" : "FAIL";
  else status = !leaked.length && !lost.length ? "PASS" : "FAIL";
  const categories = Array.from(new Set(applied.findings.filter((f) => f.action === "REDACT").map((f) => f.category)));
  let actual;
  if (leaked.length) actual = leaked.length + " hidden value(s) survived";
  else actual = categories.length ? "Redacted as " + categories.join(", ") : "No redaction";
  if (lost.length) actual += "; " + lost.length + " preserved value(s) changed";
  if (status === "FAIL" && documentedMiss && !leaked.length) actual += " (miss is now detected: update the documentation)";
  return { testCase, status, actual, format: review.report.format };
}

const results = cases.map(run);
const failed = results.filter((r) => r.status === "FAIL");
const misses = results.filter((r) => r.status === "KNOWN MISS");
if (process.argv.includes("--markdown")) {
  console.log("| ID | ATTACK | EXPECTED | ACTUAL | STATUS |");
  console.log("| --- | --- | --- | --- | --- |");
  for (const r of results) {
    const note = r.testCase.note ? " (" + r.testCase.note + ")" : "";
    console.log("| " + [r.testCase.id, r.testCase.attack, r.testCase.expected, r.actual + note, r.status].map((s) => String(s).replace(/\|/g, "\\|")).join(" | ") + " |");
  }
} else {
  for (const r of results) console.log(r.status.padEnd(10) + " " + r.testCase.id + " " + r.testCase.attack + " :: " + r.actual + " [" + r.format + "]");
}
console.log((results.length - failed.length) + "/" + results.length + " extended red-team cases matched expectations (" +
  (results.length - misses.length - failed.length) + " pass, " + misses.length + " known misses, " + failed.length + " fail)");
if (failed.length) process.exitCode = 1;
