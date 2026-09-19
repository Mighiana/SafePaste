const fs = require("fs");
const path = require("path");
const { sanitize } = require("../src/sanitizer");

const projectRoot = path.resolve(__dirname, "..");
const evalPath = path.join(__dirname, "eval_set.json");

function readText(relativePath) {
  return fs.readFileSync(path.join(projectRoot, relativePath), "utf8");
}

function listFiles(directory) {
  const root = path.join(projectRoot, directory);
  if (!fs.existsSync(root)) {
    return [];
  }

  const entries = fs.readdirSync(root, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(root, entry.name);
    const relativePath = path.relative(projectRoot, fullPath).replace(/\\/g, "/");
    if (entry.isDirectory()) {
      if (["node_modules", ".git"].includes(entry.name)) {
        return [];
      }
      return listFiles(relativePath);
    }
    return [relativePath];
  });
}

function productionFiles() {
  return ["index.html", "app.js", "styles.css", "src/sanitizer.js"];
}

function scanFiles(files, patterns) {
  const findings = [];
  files.forEach((file) => {
    const text = readText(file);
    patterns.forEach((pattern) => {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match;
      while ((match = regex.exec(text)) !== null) {
        findings.push({
          file,
          pattern: pattern.label,
          match: match[0],
          index: match.index
        });
        if (!regex.global) {
          break;
        }
      }
    });
  });
  return findings;
}

function evaluateStaticScan(kind) {
  const prod = productionFiles();

  if (kind === "noNetwork") {
    const findings = scanFiles(prod, [
      { label: "fetch(", source: /fetch\s*\(/, flags: "g" },
      { label: "XMLHttpRequest", source: /XMLHttpRequest/, flags: "g" },
      { label: "WebSocket", source: /WebSocket/, flags: "g" },
      { label: "sendBeacon", source: /sendBeacon/, flags: "g" },
      { label: "EventSource", source: /EventSource/, flags: "g" }
    ]);
    return {
      passed: findings.length === 0,
      actual: findings.length === 0 ? "No network primitives found in production files." : findings
    };
  }

  if (kind === "noPersistence") {
    const findings = scanFiles(prod, [
      { label: "localStorage", source: /localStorage/, flags: "g" },
      { label: "sessionStorage", source: /sessionStorage/, flags: "g" },
      { label: "indexedDB", source: /indexedDB/, flags: "g" },
      { label: "document.cookie", source: /document\.cookie/, flags: "g" },
      { label: "caches", source: /\bcaches\b/, flags: "g" }
    ]);
    return {
      passed: findings.length === 0,
      actual: findings.length === 0 ? "No browser persistence primitives found in production files." : findings
    };
  }

  if (kind === "noExternalResources") {
    const html = readText("index.html");
    const findings = [];
    const externalUrl = /(?:src|href)=["']https?:\/\//gi;
    const cdn = /\bcdn\b/gi;
    if (externalUrl.test(html)) {
      findings.push("external src/href URL");
    }
    if (cdn.test(html)) {
      findings.push("cdn mention");
    }
    return {
      passed: findings.length === 0,
      actual: findings.length === 0 ? "No external resource references found in index.html." : findings
    };
  }

  if (kind === "noInnerHtml") {
    const findings = scanFiles(prod, [
      { label: "innerHTML", source: /innerHTML/, flags: "g" }
    ]);
    return {
      passed: findings.length === 0,
      actual: findings.length === 0 ? "No innerHTML usage found in production files." : findings
    };
  }

  if (kind === "noPackageDependencies") {
    const packageFiles = listFiles(".").filter((file) => file === "package.json" || file.endsWith("/package.json"));
    return {
      passed: packageFiles.length === 0,
      actual: packageFiles.length === 0 ? "No package.json exists in SafePaste." : packageFiles
    };
  }

  if (kind === "labelsForTextareas") {
    const html = readText("index.html");
    const checks = [
      /<label\s+for="input-text"/.test(html),
      /<textarea\s+id="input-text"/.test(html),
      /<label\s+for="output-text"/.test(html),
      /<textarea\s+id="output-text"/.test(html)
    ];
    return {
      passed: checks.every(Boolean),
      actual: checks.every(Boolean) ? "Input and output textareas have associated labels." : "Missing textarea label association."
    };
  }

  if (kind === "statusAndFocus") {
    const html = readText("index.html");
    const css = readText("styles.css");
    const hasStatus = /role="status"/.test(html) && /aria-live="polite"/.test(html);
    const hasFocus = /:focus-visible/.test(css);
    return {
      passed: hasStatus && hasFocus,
      actual: `status=${hasStatus}; focusVisible=${hasFocus}`
    };
  }

  return {
    passed: false,
    actual: `Unknown static scan: ${kind}`
  };
}

function evaluateProductCase(evalCase) {
  const result = sanitize(evalCase.input, evalCase.options || {});
  const checks = evalCase.checks || {};
  const failures = [];

  if (checks.equalsInput && result.sanitized !== evalCase.input) {
    failures.push(`Expected sanitized output to equal input. Actual: ${result.sanitized}`);
  }

  (checks.notContains || []).forEach((value) => {
    if (result.sanitized.includes(value)) {
      failures.push(`Sanitized output still contains forbidden value: ${value}`);
    }
  });

  (checks.contains || []).forEach((value) => {
    if (!result.sanitized.includes(value)) {
      failures.push(`Sanitized output missing expected value: ${value}`);
    }
  });

  (checks.categoriesInclude || []).forEach((category) => {
    if (!result.categories.includes(category)) {
      failures.push(`Missing expected category: ${category}`);
    }
  });

  (checks.categoriesExclude || []).forEach((category) => {
    if (result.categories.includes(category)) {
      failures.push(`Unexpected category: ${category}`);
    }
  });

  if (typeof checks.redactionCount === "number" && result.redactionCount !== checks.redactionCount) {
    failures.push(`Expected redaction count ${checks.redactionCount}; actual ${result.redactionCount}`);
  }

  return {
    passed: failures.length === 0,
    actual: {
      sanitized: result.sanitized,
      categories: result.categories,
      redactionCount: result.redactionCount,
      failures
    }
  };
}

function evaluateCase(evalCase) {
  if (evalCase.layer === "engineering") {
    return evaluateStaticScan(evalCase.checks.staticScan);
  }
  return evaluateProductCase(evalCase);
}

function markdownEscape(value) {
  return String(value).replace(/\|/g, "\\|");
}

function buildMarkdown(results) {
  const passed = results.filter((result) => result.passed);
  const failed = results.filter((result) => !result.passed);
  const lines = [];

  lines.push("# SafePaste Evaluation Results");
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Total eval cases: ${results.length}`);
  lines.push(`- Passed: ${passed.length}`);
  lines.push(`- Failed: ${failed.length}`);
  lines.push(`- Failure IDs: ${failed.length ? failed.map((result) => result.case.id).join(", ") : "None"}`);
  lines.push("");
  lines.push("## Case Results");
  lines.push("");
  lines.push("| ID | Layer | Category | Stakeholder | Requirement | Result |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  results.forEach((result) => {
    lines.push([
      result.case.id,
      result.case.layer,
      result.case.category,
      result.case.stakeholder_user_type,
      result.case.mapped_spec_requirement,
      result.passed ? "PASS" : "FAIL"
    ].map(markdownEscape).join(" | "));
  });
  lines.push("");

  if (failed.length > 0) {
    lines.push("## Failures");
    lines.push("");
    failed.forEach((result) => {
      lines.push(`### ${result.case.id}: ${result.case.expected_behavior}`);
      lines.push("");
      lines.push(`- Related stakeholder: ${result.case.stakeholder_user_type}`);
      lines.push(`- Mapped requirement: ${result.case.mapped_spec_requirement}`);
      lines.push(`- Justification: ${result.case.justification}`);
      if (result.case.layer === "product") {
        lines.push("- Failing input:");
        lines.push("");
        lines.push("```text");
        lines.push(result.case.input);
        lines.push("```");
        lines.push("- Actual output:");
        lines.push("");
        lines.push("```text");
        lines.push(result.actual.sanitized);
        lines.push("```");
        lines.push(`- Categories: ${result.actual.categories.join(", ") || "none"}`);
        lines.push(`- Redaction count: ${result.actual.redactionCount}`);
        lines.push("- Failure reason:");
        result.actual.failures.forEach((failure) => {
          lines.push(`  - ${failure}`);
        });
      } else {
        lines.push("- Static finding:");
        lines.push("");
        lines.push("```text");
        lines.push(JSON.stringify(result.actual, null, 2));
        lines.push("```");
      }
      lines.push("");
    });
  }

  return lines.join("\n") + "\n";
}

function run() {
  const evalCases = JSON.parse(fs.readFileSync(evalPath, "utf8"));
  const results = evalCases.map((evalCase) => {
    const outcome = evaluateCase(evalCase);
    return {
      case: evalCase,
      passed: outcome.passed,
      actual: outcome.actual
    };
  });

  const markdown = buildMarkdown(results);
  const outputArgIndex = process.argv.indexOf("--write");
  if (outputArgIndex !== -1) {
    const outputPath = process.argv[outputArgIndex + 1];
    if (!outputPath) {
      throw new Error("--write requires an output path");
    }
    fs.writeFileSync(path.resolve(projectRoot, outputPath), markdown, "utf8");
  }

  process.stdout.write(markdown);

  if (results.some((result) => !result.passed)) {
    process.exitCode = 1;
  }
}

run();
