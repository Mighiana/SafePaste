const { buildHarness } = require("../tests/ui-harness");

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function categoryText(elements) {
  return elements["category-list"].children.map((child) => child.textContent);
}

async function testEmptyInput() {
  const { elements } = buildHarness();
  elements["input-text"].value = "";
  await elements["sanitize-button"].dispatch("click");

  assert(elements["output-text"].value === "", "empty input should produce empty output");
  assert(elements["redaction-count"].textContent === "0", "empty input redaction count should be 0");
  assert(categoryText(elements).join("|") === "No sensitive categories detected.", "empty input should show no fake categories");
  assert(elements["copy-button"].disabled === true, "copy should remain disabled for empty output");
  assert(/No sensitive patterns/.test(elements["status-message"].textContent), "empty input should show understandable status");
}

async function testClearButton() {
  const { elements } = buildHarness();
  const input = "email=dev@example.com password=clearSecret123 ip=10.1.2.3";
  elements["input-text"].value = input;
  await elements["sanitize-button"].dispatch("click");
  await elements["clear-button"].dispatch("click");

  assert(elements["input-text"].value === "", "clear should empty original input");
  assert(elements["output-text"].value === "", "clear should empty sanitized output");
  assert(elements["redaction-count"].textContent === "0", "clear should reset redaction count");
  assert(categoryText(elements).join("|") === "No sensitive categories detected.", "clear should reset categories");
  assert(elements["copy-button"].disabled === true, "copy should disable after clear");
  assert(!JSON.stringify(elements).includes("dev@example.com"), "clear should remove stale sensitive email from visible state");
  assert(!JSON.stringify(elements).includes("clearSecret123"), "clear should remove stale password from visible state");
}

async function testCopyButton() {
  const harness = buildHarness();
  const { elements } = harness;
  elements["input-text"].value = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456";
  await elements["sanitize-button"].dispatch("click");
  await elements["copy-button"].dispatch("click");

  assert(harness.copied() === elements["output-text"].value, "clipboard text should exactly match sanitized output");
  assert(!harness.copied().includes("abcdefghijklmnopqrstuvwxyz123456"), "clipboard should not contain original sensitive token");
  assert(/copied/i.test(elements["status-message"].textContent), "copy should show success feedback");
}

async function testIpv4UserControl() {
  const { elements } = buildHarness();
  const input = "client_ip=192.168.20.50 localhost=127.0.0.1 email=alex@example.com password=secret123";
  elements["input-text"].value = input;

  elements["redact-ip"].checked = true;
  await elements["sanitize-button"].dispatch("click");
  assert(elements["output-text"].value.includes("client_ip=[REDACTED_IP_ADDRESS]"), "IPv4 ON should redact network IP");
  assert(elements["output-text"].value.includes("localhost=127.0.0.1"), "IPv4 ON should preserve loopback");
  assert(elements["output-text"].value.includes("email=[REDACTED_EMAIL]"), "IPv4 ON should redact email");
  assert(elements["output-text"].value.includes("password=[REDACTED_PASSWORD]"), "IPv4 ON should redact password");

  elements["redact-ip"].checked = false;
  await elements["redact-ip"].dispatch("change");
  assert(elements["output-text"].value === "", "policy change must discard stale output");
  assert(elements["copy-button"].disabled, "policy change must disable stale copy");
  await elements["sanitize-button"].dispatch("click");
  assert(elements["output-text"].value.includes("client_ip=192.168.20.50"), "IPv4 OFF should preserve network IP");
  assert(elements["output-text"].value.includes("email=[REDACTED_EMAIL]"), "IPv4 OFF should keep email redaction active");
  assert(elements["output-text"].value.includes("password=[REDACTED_PASSWORD]"), "IPv4 OFF should keep password redaction active");
}

async function testLargeMultilineInput() {
  const { elements } = buildHarness();
  const records = Array.from({ length: 200 }, (_, index) => {
    const octet = (index % 200) + 1;
    return `2026-08-13T12:${String(index % 60).padStart(2, "0")}:00Z request=${index} user=user${index}@example.com ip=10.20.${Math.floor(index / 200)}.${octet} status=500 password=largeSecret${index}`;
  });

  elements["input-text"].value = records.join("\n");
  await elements["sanitize-button"].dispatch("click");
  const output = elements["output-text"].value;

  assert(output.split("\n").length === records.length, "large multiline output should preserve line count");
  assert(output.includes("request=0"), "large multiline output should preserve first record context");
  assert(output.includes("request=199"), "large multiline output should preserve last record context");
  assert(!output.includes("user0@example.com"), "large multiline output should redact email");
  assert(!output.includes("largeSecret199"), "large multiline output should redact password");
  assert(output.includes("[REDACTED_IP_ADDRESS]"), "large multiline output should redact IPv4 values");
  assert(elements["status-message"].textContent.length > 0, "large multiline run should show status");
}

const tests = [
  ["empty input", testEmptyInput],
  ["clear button", testClearButton],
  ["copy button", testCopyButton],
  ["IPv4 user control", testIpv4UserControl],
  ["large multiline input", testLargeMultilineInput]
];

(async function run() {
  let passed = 0;

  for (const [name, fn] of tests) {
    try {
      await fn();
      passed += 1;
      console.log(`PASS product behavior: ${name}`);
    } catch (error) {
      console.error(`FAIL product behavior: ${name}`);
      console.error(error.stack);
    }
  }

  console.log(`${passed}/${tests.length} product behavior checks passed`);

  if (passed !== tests.length) {
    process.exitCode = 1;
  }
})();
