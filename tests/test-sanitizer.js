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

  test("preserves IPv4-like substrings inside larger dotted numeric sequences", () => {
    const input = "1.2.3.4.5";
    const result = sanitize(input);
    assert.strictEqual(result.sanitized, input);
    assert(!result.categories.includes("IP_ADDRESS"), "larger dotted sequence not categorized");
    assert.strictEqual(result.redactionCount, 0);
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

  test("redacts Basic authorization headers", () => {
    const result = assertRedacted(
      "Authorization: Basic dXNlcjpwYXNzd29yZA==",
      "dXNlcjpwYXNzd29yZA==",
      REDACTION_LABELS.AUTHORIZATION_HEADER,
      "basic authorization header"
    );
    assert(result.categories.includes("AUTHORIZATION_HEADER"), "authorization category reported");
  }),

  test("redacts Token authorization headers", () => {
    const result = assertRedacted(
      "Authorization: Token abcdefghijklmnopqrstuvwxyz",
      "abcdefghijklmnopqrstuvwxyz",
      REDACTION_LABELS.AUTHORIZATION_HEADER,
      "token authorization header"
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
    assert(result.sanitized.includes('"user":"[REDACTED_USERNAME]"'), "structured user value redacted");
    assert(result.categories.includes("USERNAME"), "USERNAME category reported");
    assert.strictEqual(result.redactionCount, 2);
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

  test("redacts explicit structured secret fields", () => {
    const result = assertRedacted(
      "secret=FakeSecretValue987",
      "FakeSecretValue987",
      REDACTION_LABELS.SECRET,
      "structured secret"
    );
    assert.strictEqual(result.sanitized, "secret=[REDACTED_SECRET]");
    assert(result.categories.includes("SECRET"), "SECRET category reported");
    assert.strictEqual(result.redactionCount, 1);

    assert.strictEqual(
      sanitize("secret: FakeSecretValue987").sanitized,
      "secret: [REDACTED_SECRET]"
    );
    assert.strictEqual(
      sanitize('{"secret":"FakeSecretValue987","mode":"test"}').sanitized,
      '{"secret":"[REDACTED_SECRET]","mode":"test"}'
    );
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

  test("redacts explicit structured username fields", () => {
    const result = sanitize("username=musman24\nuser_name=alice_dev\nuser=bob-admin");
    assert(!result.sanitized.includes("musman24"), "username value removed");
    assert(!result.sanitized.includes("alice_dev"), "user_name value removed");
    assert(!result.sanitized.includes("bob-admin"), "user value removed");
    assert(result.sanitized.includes("username=[REDACTED_USERNAME]"), "username marker present");
    assert(result.sanitized.includes("user_name=[REDACTED_USERNAME]"), "user_name marker present");
    assert(result.sanitized.includes("user=[REDACTED_USERNAME]"), "user marker present");
    assert(result.categories.includes("USERNAME"), "USERNAME category reported");
    assert.strictEqual(result.redactionCount, 3);
  }),

  test("redacts explicit structured username JSON fields", () => {
    const result = sanitize('{"username":"musman24","role":"admin"}');
    assert.strictEqual(result.sanitized, '{"username":"[REDACTED_USERNAME]","role":"admin"}');
    assert(result.categories.includes("USERNAME"), "USERNAME category reported");
    assert.strictEqual(result.redactionCount, 1);
  }),

  test("preserves arbitrary personal names outside explicit username fields", () => {
    assert.strictEqual(sanitize("name=Muhammad").sanitized, "name=Muhammad");
    assert.strictEqual(
      sanitize("User alice reported that the service failed after deployment.").sanitized,
      "User alice reported that the service failed after deployment."
    );
  }),

  test("preserves IPv4-shaped values in version-related fields", () => {
    assert.strictEqual(sanitize("release=1.2.3.4").sanitized, "release=1.2.3.4");
    assert.strictEqual(sanitize("version=10.20.30.40").sanitized, "version=10.20.30.40");
    assert.strictEqual(sanitize("app_version=2.4.6.8").sanitized, "app_version=2.4.6.8");
    assert.strictEqual(sanitize("software_version=3.5.7.9").sanitized, "software_version=3.5.7.9");
  }),

  test("preserves IPv4-shaped values in strong prose version context", () => {
    assert.strictEqual(
      sanitize("Release 1.2.3.4 passed QA yesterday.").sanitized,
      "Release 1.2.3.4 passed QA yesterday."
    );
    assert.strictEqual(
      sanitize("Version 10.20.30.40 passed QA yesterday.").sanitized,
      "Version 10.20.30.40 passed QA yesterday."
    );
    assert.strictEqual(sanitize("version: 1.2.3.4").sanitized, "version: 1.2.3.4");
    assert.strictEqual(sanitize("release: 1.2.3.4").sanitized, "release: 1.2.3.4");
  }),

  test("redacts IPv4-shaped values in IP-specific fields", () => {
    assert.strictEqual(sanitize("client_ip=10.20.30.40").sanitized, `client_ip=${REDACTION_LABELS.IP_ADDRESS}`);
    assert.strictEqual(sanitize("server_ip=8.8.8.8").sanitized, `server_ip=${REDACTION_LABELS.IP_ADDRESS}`);
  }),

  test("redacts IPv4 addresses in non-version prose contexts", () => {
    assert.strictEqual(sanitize("Server 10.20.30.40 failed").sanitized, `Server ${REDACTION_LABELS.IP_ADDRESS} failed`);
    assert.strictEqual(sanitize("Client 8.8.8.8 disconnected").sanitized, `Client ${REDACTION_LABELS.IP_ADDRESS} disconnected`);
    assert.strictEqual(sanitize("Remote address: 172.20.10.15").sanitized, `Remote address: ${REDACTION_LABELS.IP_ADDRESS}`);
  }),

  test("redacts standalone IPv4 addresses before sentence periods", () => {
    assert.strictEqual(
      sanitize("Connection received from 192.168.20.50.").sanitized,
      `Connection received from ${REDACTION_LABELS.IP_ADDRESS}.`
    );
    assert.strictEqual(
      sanitize("Request originated at 10.1.2.3.").sanitized,
      `Request originated at ${REDACTION_LABELS.IP_ADDRESS}.`
    );
    assert.strictEqual(
      sanitize("Remote host 172.16.4.20 disconnected.").sanitized,
      `Remote host ${REDACTION_LABELS.IP_ADDRESS} disconnected.`
    );
    assert.strictEqual(
      sanitize("Peer address: 8.8.8.8").sanitized,
      `Peer address: ${REDACTION_LABELS.IP_ADDRESS}`
    );
  }),

  test("preserves IPv4-shaped values in versions and hostnames", () => {
    assert.strictEqual(sanitize("Version 3.4.5.6 deployed.").sanitized, "Version 3.4.5.6 deployed.");
    assert.strictEqual(sanitize("Release 5.6.7.8 passed QA.").sanitized, "Release 5.6.7.8 passed QA.");
    assert.strictEqual(sanitize("https://10.20.30.40.example.com/status").sanitized, "https://10.20.30.40.example.com/status");
  }),

  test("preserves PWD path-like environment values", () => {
    const input = "PWD=/workspace/project npm test";
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
  }),

  test("preserves 127.0.0.1 loopback by default", () => {
    const input = "127.0.0.1";
    const result = sanitize(input);
    assert.strictEqual(result.sanitized, input);
    assert(!result.categories.includes("IP_ADDRESS"), "loopback not categorized as redacted IP");
  }),

  test("preserves 127.0.0.2 loopback by default", () => {
    const input = "127.0.0.2";
    const result = sanitize(input);
    assert.strictEqual(result.sanitized, input);
    assert.strictEqual(result.redactionCount, 0);
  }),

  test("preserves 127.255.255.255 loopback by default", () => {
    const input = "127.255.255.255";
    const result = sanitize(input);
    assert.strictEqual(result.sanitized, input);
    assert.strictEqual(result.redactionCount, 0);
  }),

  test("redacts Linux home path username", () => {
    const result = sanitize("/home/alice/project/error.log");
    assert.strictEqual(result.sanitized, "/home/[REDACTED_USERNAME]/project/error.log");
    assert(result.categories.includes("PATH_OR_USERNAME"), "Linux home path category reported");
  }),

  test("redacts Linux home path username with trailing slash", () => {
    const result = sanitize("/home/bob/");
    assert.strictEqual(result.sanitized, "/home/[REDACTED_USERNAME]/");
  }),

  test("preserves non-home Linux system paths", () => {
    assert.strictEqual(sanitize("/var/log/nginx/error.log").sanitized, "/var/log/nginx/error.log");
    assert.strictEqual(sanitize("/usr/local/bin").sanitized, "/usr/local/bin");
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

