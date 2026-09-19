const { sanitize } = require("../src/sanitizer");

const longToken = "longSecretTokenValue1234567890".repeat(6);

const cases = [
  {
    id: "RT-P01",
    focus: "embedded credential",
    input: "GET /callback?api_key=urlSecretValue123456&state=keep-state",
    expected: "Redact embedded API key value and preserve URL context.",
    checks: {
      notContains: ["urlSecretValue123456"],
      contains: ["api_key=", "[REDACTED_API_KEY]", "state=keep-state"]
    }
  },
  {
    id: "RT-P02",
    focus: "credential inside JSON",
    input: "{\"password\":\"jsonPassword123\",\"user\":\"sam\"}",
    expected: "Redact quoted JSON password and structured user value.",
    checks: {
      notContains: ["jsonPassword123", "\"user\":\"sam\""],
      contains: ["[REDACTED_PASSWORD]", "\"user\":\"[REDACTED_USERNAME]\""]
    }
  },
  {
    id: "RT-P03",
    focus: "multiple secrets in one line",
    input: "email=dev@example.com password=firstSecret api_key=secondSecret12345",
    expected: "Redact email, password, and API key.",
    checks: {
      notContains: ["dev@example.com", "firstSecret", "secondSecret12345"],
      contains: ["[REDACTED_EMAIL]", "[REDACTED_PASSWORD]", "[REDACTED_API_KEY]"]
    }
  },
  {
    id: "RT-P04",
    focus: "malformed JWT-like string",
    input: "candidate eyJshort.eyJalso.short should not be redacted",
    expected: "Preserve malformed JWT-like text.",
    checks: {
      equalsInput: true
    }
  },
  {
    id: "RT-P05",
    focus: "invalid IPv4",
    input: "bad fixture 999.999.999.999 should remain",
    expected: "Preserve invalid IPv4 octets.",
    checks: {
      equalsInput: true
    }
  },
  {
    id: "RT-P06",
    focus: "localhost",
    input: "local service bound to 127.0.0.1:8080",
    expected: "Preserve localhost loopback after Manual Test 2 policy refinement.",
    checks: {
      contains: ["127.0.0.1", ":8080"]
    }
  },
  {
    id: "RT-P07",
    focus: "private IP range",
    input: "private subnet check from 172.16.4.20",
    expected: "Redact private IPv4 by default.",
    checks: {
      notContains: ["172.16.4.20"],
      contains: ["[REDACTED_IP_ADDRESS]"]
    }
  },
  {
    id: "RT-P08",
    focus: "Unicode",
    input: "用户 alice@example.com 遇到错误",
    expected: "Preserve Unicode text and redact email.",
    checks: {
      notContains: ["alice@example.com"],
      contains: ["用户", "[REDACTED_EMAIL]", "遇到错误"]
    }
  },
  {
    id: "RT-P09",
    focus: "long line",
    input: `prefix ${"x".repeat(1200)} access_token=${longToken} suffix`,
    expected: "Handle a long line and redact token.",
    checks: {
      notContains: [longToken],
      contains: ["prefix ", "[REDACTED_API_KEY]", " suffix"]
    }
  },
  {
    id: "RT-P10",
    focus: "script tag as plain text",
    input: "<script>alert('x')</script> password=scriptSecret",
    expected: "Preserve script-like text as inert text and redact password.",
    checks: {
      notContains: ["scriptSecret"],
      contains: ["<script>alert('x')</script>", "[REDACTED_PASSWORD]"]
    }
  },
  {
    id: "RT-P11",
    focus: "HTML-like input",
    input: "<div data-user=\"casey@example.net\">failure</div>",
    expected: "Redact email inside HTML-like text without treating it as markup.",
    checks: {
      notContains: ["casey@example.net"],
      contains: ["<div data-user=\"", "[REDACTED_EMAIL]", "\">failure</div>"]
    }
  },
  {
    id: "RT-P12",
    focus: "repeated secrets",
    input: "password=oneSecret password=twoSecret password=threeSecret",
    expected: "Redact repeated password values.",
    checks: {
      notContains: ["oneSecret", "twoSecret", "threeSecret"],
      contains: ["[REDACTED_PASSWORD]"]
    }
  },
  {
    id: "RT-P13",
    focus: "Basic authorization header",
    input: "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    expected: "Redact Basic authorization credential.",
    checks: {
      notContains: ["dXNlcjpwYXNzd29yZA=="],
      contains: ["Authorization:", "[REDACTED_AUTHORIZATION_HEADER]"]
    }
  },
  {
    id: "RT-P14",
    focus: "Token authorization header",
    input: "Authorization: Token abcdefghijklmnopqrstuvwxyz",
    expected: "Redact Token authorization credential.",
    checks: {
      notContains: ["abcdefghijklmnopqrstuvwxyz"],
      contains: ["Authorization:", "[REDACTED_AUTHORIZATION_HEADER]"]
    }
  },
  {
    id: "RT-P15",
    focus: "PWD false positive",
    input: "PWD=/workspace/project npm test",
    expected: "Preserve PWD path-like environment value.",
    checks: {
      equalsInput: true
    }
  }
];

function evaluate(testCase) {
  const result = sanitize(testCase.input);
  const failures = [];
  const checks = testCase.checks;

  if (checks.equalsInput && result.sanitized !== testCase.input) {
    failures.push(`Expected output to equal input. Actual: ${result.sanitized}`);
  }

  (checks.notContains || []).forEach((value) => {
    if (result.sanitized.includes(value)) {
      failures.push(`Output still contains ${value}`);
    }
  });

  (checks.contains || []).forEach((value) => {
    if (!result.sanitized.includes(value)) {
      failures.push(`Output missing ${value}`);
    }
  });

  return {
    ...testCase,
    sanitized: result.sanitized,
    categories: result.categories,
    redactionCount: result.redactionCount,
    passed: failures.length === 0,
    failures
  };
}

const results = cases.map(evaluate);
const failed = results.filter((result) => !result.passed);

console.log("# SafePaste Product Red-Team Results");
console.log("");
console.log(`Total cases: ${results.length}`);
console.log(`Passed: ${results.length - failed.length}`);
console.log(`Failed: ${failed.length}`);
console.log(`Failure IDs: ${failed.length ? failed.map((result) => result.id).join(", ") : "None"}`);
console.log("");

results.forEach((result) => {
  console.log(`${result.passed ? "PASS" : "FAIL"} ${result.id} ${result.focus}`);
  if (!result.passed) {
    console.log(`Expected: ${result.expected}`);
    console.log(`Input: ${result.input}`);
    console.log(`Actual: ${result.sanitized}`);
    result.failures.forEach((failure) => console.log(`- ${failure}`));
  }
});

if (failed.length > 0) {
  process.exitCode = 1;
}
