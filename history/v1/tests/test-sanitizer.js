const assert = require("assert");
const { sanitize, REDACTION_LABELS } = require("../src/sanitizer");

function test(name, fn) {
  try {
    fn();
    return { name, passed: true };
  } catch (error) {
    return { name, passed: false, error };
  }
}

function assertRedacted(input, secret, label, context) {
  const result = sanitize(input);
  assert(!result.sanitized.includes(secret), `${context}: secret should be removed`);
  assert(result.sanitized.includes(label), `${context}: label should be present`);
  return result;
}

const tests = [
  test("detects and redacts email addresses", () => {
    const result = assertRedacted(
      "Contact alex@example.com for details",
      "alex@example.com",
      REDACTION_LABELS.EMAIL,
      "email"
    );
    assert(result.sanitized.includes("Contact "), "context before email preserved");
    assert(result.categories.includes("EMAIL"), "EMAIL category reported");
  }),

  test("detects valid IPv4 addresses", () => {
    const result = assertRedacted(
      "Server accepted connection from 192.168.1.45 on port 443",
      "192.168.1.45",
      REDACTION_LABELS.IP_ADDRESS,
      "valid IPv4"
    );
    assert(result.sanitized.includes("on port 443"), "context after IP preserved");
  }),

  test("preserves invalid IPv4 addresses", () => {
    const result = sanitize("Bad address 999.999.999.999 should stay visible");
    assert(result.sanitized.includes("999.999.999.999"), "invalid IP preserved");
    assert(!result.categories.includes("IP_ADDRESS"), "invalid IP not categorized");
  }),

  test("redacts Bearer tokens", () => {
    const result = assertRedacted(
      "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456'",
      "abcdefghijklmnopqrstuvwxyz123456",
      REDACTION_LABELS.AUTHORIZATION_HEADER,
      "authorization header"
    );
    assert(result.categories.includes("AUTHORIZATION_HEADER"), "authorization category reported");
  }),

  test("redacts standalone Bearer tokens", () => {
    const result = assertRedacted(
      "token=Bearer abcdefghijklmnopqrstuvwxyz123456",
      "Bearer abcdefghijklmnopqrstuvwxyz123456",
      REDACTION_LABELS.BEARER_TOKEN,
      "bearer token"
    );
    assert(result.categories.includes("BEARER_TOKEN"), "bearer category reported");
  }),

  test("redacts JWTs", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart";
    const result = assertRedacted(`jwt ${jwt}`, jwt, REDACTION_LABELS.JWT, "JWT");
    assert(result.categories.includes("JWT"), "JWT category reported");
  }),

  test("redacts password key=value", () => {
    const result = assertRedacted(
      "db password=correct-horse-battery-staple host=db01",
      "correct-horse-battery-staple",
      REDACTION_LABELS.PASSWORD,
      "password key=value"
    );
    assert(result.sanitized.includes("host=db01"), "non-sensitive context preserved");
  }),

  test("redacts password JSON", () => {
    const result = assertRedacted(
      '{"user":"sam","password":"supersecret"}',
      "supersecret",
      REDACTION_LABELS.PASSWORD,
      "password JSON"
    );
    assert(result.sanitized.includes('"user":"sam"'), "JSON context preserved");
  }),

  test("redacts API key key=value", () => {
    const result = assertRedacted(
      "api_key=abc1234567890SECRET request_id=req-42",
      "abc1234567890SECRET",
      REDACTION_LABELS.API_KEY,
      "API key key=value"
    );
    assert(result.sanitized.includes("request_id=req-42"), "request id preserved");
  }),

  test("redacts API key JSON", () => {
    const result = assertRedacted(
      '{"apiKey":"abc1234567890SECRET","mode":"test"}',
      "abc1234567890SECRET",
      REDACTION_LABELS.API_KEY,
      "API key JSON"
    );
    assert(result.sanitized.includes('"mode":"test"'), "JSON context preserved");
  }),

  test("redacts AWS access keys", () => {
    const result = assertRedacted(
      "AWS key AKIAIOSFODNN7EXAMPLE was logged",
      "AKIAIOSFODNN7EXAMPLE",
      REDACTION_LABELS.AWS_ACCESS_KEY,
      "AWS access key"
    );
    assert(result.categories.includes("AWS_ACCESS_KEY"), "AWS category reported");
  }),

  test("redacts Slack-style tokens", () => {
    const result = assertRedacted(
      "slack=FAKE_SLACK_TOKEN_FOR_TESTING",
      "FAKE_SLACK_TOKEN_FOR_TESTING",
      REDACTION_LABELS.SLACK_TOKEN,
      "Slack token"
    );
    assert(result.categories.includes("SLACK_TOKEN"), "Slack category reported");
  }),

  test("preserves ordinary text and short build IDs", () => {
    const input = "Build abc123xyz completed in 42ms";
    const result = sanitize(input);
    assert.strictEqual(result.sanitized, input);
    assert.strictEqual(result.redactionCount, 0);
  }),

  test("redacts multiple secrets in one log", () => {
    const result = sanitize("user=a@example.com ip=10.0.0.5 password=secret123");
    assert(!result.sanitized.includes("a@example.com"), "email removed");
    assert(!result.sanitized.includes("10.0.0.5"), "IP removed");
    assert(!result.sanitized.includes("secret123"), "password removed");
    assert.strictEqual(result.redactionCount, 3);
  }),

  test("handles empty input", () => {
    const result = sanitize("");
    assert.strictEqual(result.sanitized, "");
    assert.strictEqual(result.redactionCount, 0);
    assert.deepStrictEqual(result.categories, []);
  }),

  test("preserves Unicode context", () => {
    const result = sanitize("Ошибка пользователя алексей: alex@example.com");
    assert(result.sanitized.includes("Ошибка пользователя алексей"), "Unicode context preserved");
    assert(!result.sanitized.includes("alex@example.com"), "email removed");
  }),

  test("handles multiline input", () => {
    const result = sanitize("line one\npassword=multilineSecret\nline three");
    assert(result.sanitized.includes("line one\n"), "first line preserved");
    assert(result.sanitized.includes("\nline three"), "last line preserved");
    assert(!result.sanitized.includes("multilineSecret"), "password removed");
  }),

  test("can preserve IPv4 addresses when user option disables redaction", () => {
    const result = sanitize("Connect to 192.168.0.10", { redactIpAddresses: false });
    assert.strictEqual(result.sanitized, "Connect to 192.168.0.10");
    assert.strictEqual(result.redactionCount, 0);
  })
];

const failed = tests.filter((result) => !result.passed);

tests.forEach((result) => {
  if (result.passed) {
    console.log(`PASS ${result.name}`);
  } else {
    console.error(`FAIL ${result.name}`);
    console.error(result.error.stack);
  }
});

console.log(`${tests.length - failed.length}/${tests.length} tests passed`);

if (failed.length > 0) {
  process.exitCode = 1;
}

