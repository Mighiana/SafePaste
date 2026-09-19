const fs = require("fs");
const path = require("path");
const { sanitize } = require("../../src/sanitizer");

const projectRoot = path.resolve(__dirname, "..", "..");
const evalSetPath = path.join(projectRoot, "evals", "eval_set.json");

const selectedCaseIds = [
  "EV-001",
  "EV-005",
  "EV-013",
  "EV-029",
  "EV-039",
  "EV-040",
  "EV-041",
  "EV-044",
  "EV-046",
  "EV-048",
  "EV-049",
  "EV-050",
  "EV-052",
  "EV-055",
  "EV-058",
  "EV-062",
  "EV-065",
  "EV-069",
  "EV-071",
  "EV-072",
  "EV-073"
];

function loadSelectedCases() {
  const evalSet = JSON.parse(fs.readFileSync(evalSetPath, "utf8"));
  const byId = new Map(evalSet.map((evalCase) => [evalCase.id, evalCase]));

  return selectedCaseIds.map((caseId) => {
    const evalCase = byId.get(caseId);
    if (!evalCase) {
      throw new Error(`Missing eval case ${caseId}`);
    }
    return evalCase;
  });
}

function sanitizeForCase(evalCase) {
  return sanitize(evalCase.input, evalCase.options || {});
}

function propertyRows(evalCase) {
  const checks = evalCase.checks || {};
  const result = sanitizeForCase(evalCase);
  const rows = [];

  if (checks.equalsInput) {
    rows.push({
      caseId: evalCase.id,
      expectedProperty: "Must preserve values: sanitized output equals input",
      actualBehavior: result.sanitized,
      passed: result.sanitized === evalCase.input,
      reason: result.sanitized === evalCase.input
        ? "Output preserved exactly as required."
        : "Output changed even though the case required preservation."
    });
  }

  (checks.notContains || []).forEach((value) => {
    const passed = !result.sanitized.includes(value);
    rows.push({
      caseId: evalCase.id,
      expectedProperty: `Original sensitive value no longer appears: ${value}`,
      actualBehavior: passed ? "Value absent from sanitized output." : `Output still contains ${value}`,
      passed,
      reason: passed ? "Sensitive value was removed." : "Sensitive value remained visible."
    });
  });

  (checks.contains || []).forEach((value) => {
    const passed = result.sanitized.includes(value);
    rows.push({
      caseId: evalCase.id,
      expectedProperty: `Expected marker or harmless context appears: ${value}`,
      actualBehavior: passed ? "Expected text present." : `Output missing ${value}`,
      passed,
      reason: passed ? "Required marker/context was preserved." : "Required marker/context was absent."
    });
  });

  (checks.categoriesInclude || []).forEach((category) => {
    const passed = result.categories.includes(category);
    rows.push({
      caseId: evalCase.id,
      expectedProperty: `Detected category includes ${category}`,
      actualBehavior: `Categories: ${result.categories.join(", ") || "none"}`,
      passed,
      reason: passed ? "Expected category was reported." : "Expected category was not reported."
    });
  });

  (checks.categoriesExclude || []).forEach((category) => {
    const passed = !result.categories.includes(category);
    rows.push({
      caseId: evalCase.id,
      expectedProperty: `Detected category excludes ${category}`,
      actualBehavior: `Categories: ${result.categories.join(", ") || "none"}`,
      passed,
      reason: passed ? "Unexpected category was absent." : "Unexpected category was reported."
    });
  });

  if (typeof checks.redactionCount === "number") {
    const passed = result.redactionCount === checks.redactionCount;
    rows.push({
      caseId: evalCase.id,
      expectedProperty: `Redaction count is ${checks.redactionCount}`,
      actualBehavior: `Redaction count: ${result.redactionCount}`,
      passed,
      reason: passed ? "Redaction count matched." : "Redaction count did not match."
    });
  }

  return rows;
}

function escapeMarkdown(value) {
  return String(value).replace(/\|/g, "\\|").replace(/\r?\n/g, "\\n");
}

function renderMarkdown(rows) {
  const passed = rows.filter((row) => row.passed).length;
  const lines = [
    "# Exact/Property Grader Results",
    "",
    "Grader type: automated exact/property checks over deterministic sanitizer output.",
    "",
    `Cases graded: ${selectedCaseIds.join(", ")}`,
    `Property checks: ${rows.length}`,
    `Passed: ${passed}`,
    `Failed: ${rows.length - passed}`,
    "",
    "| Case ID | Expected property | Actual behavior | Result | Reason |",
    "| --- | --- | --- | --- | --- |"
  ];

  rows.forEach((row) => {
    lines.push([
      row.caseId,
      row.expectedProperty,
      row.actualBehavior,
      row.passed ? "PASS" : "FAIL",
      row.reason
    ].map(escapeMarkdown).join(" | "));
  });

  return lines.join("\n") + "\n";
}

function run() {
  const rows = loadSelectedCases().flatMap(propertyRows);
  const markdown = renderMarkdown(rows);
  const outputIndex = process.argv.indexOf("--write");

  if (outputIndex !== -1) {
    const outputPath = process.argv[outputIndex + 1];
    if (!outputPath) {
      throw new Error("--write requires an output path");
    }
    fs.writeFileSync(path.resolve(projectRoot, outputPath), markdown, "utf8");
  }

  process.stdout.write(markdown);

  if (rows.some((row) => !row.passed)) {
    process.exitCode = 1;
  }
}

run();
