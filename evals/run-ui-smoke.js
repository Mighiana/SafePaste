const { buildHarness } = require("../tests/ui-harness");
const harness = buildHarness();
const { elements } = harness;

async function run() {
  const input = [
    "Login failed for alex@example.com",
    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
    "from 192.168.1.20"
  ].join("\n");

  elements["input-text"].value = input;
  await elements["sanitize-button"].dispatch("click");

  const output = elements["output-text"].value;
  assert(!output.includes("alex@example.com"), "email should be removed");
  assert(!output.includes("dXNlcjpwYXNzd29yZA=="), "authorization credential should be removed");
  assert(!output.includes("192.168.1.20"), "IP should be removed");
  assert(output.includes("[REDACTED_EMAIL]"), "email label should render");
  assert(output.includes("[REDACTED_AUTHORIZATION_HEADER]"), "authorization label should render");
  assert(output.includes("[REDACTED_IP_ADDRESS]"), "IP label should render");
  assert(elements["redaction-count"].textContent === "3", "redaction count should be 3");
  assert(elements["category-list"].children.length === 3, "three categories should be rendered");
  assert(elements["copy-button"].disabled === false, "copy button should be enabled");

  await elements["copy-button"].dispatch("click");
  assert(harness.copied() === output, "copy button should write sanitized text to clipboard API");

  await elements["clear-button"].dispatch("click");
  assert(elements["input-text"].value === "", "input should clear");
  assert(elements["output-text"].value === "", "output should clear");
  assert(elements["redaction-count"].textContent === "0", "redaction count should reset");
  assert(elements["copy-button"].disabled === true, "copy button should disable after clear");

  console.log("PASS UI smoke: sanitize, summary, copy API call, and clear/reset");
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

run().catch((error) => {
  console.error(`FAIL UI smoke: ${error.message}`);
  console.error(error.stack);
  process.exitCode = 1;
});
