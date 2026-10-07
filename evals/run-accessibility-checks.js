const fs = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(projectRoot, "index.html"), "utf8");
const css = fs.readFileSync(path.join(projectRoot, "styles.css"), "utf8");

const checks = [
  {
    name: "textarea labels",
    passed: /<label\s+for="input-text">Original text<\/label>/.test(html) &&
      /<textarea\s+id="input-text"/.test(html) &&
      /<label\s+for="output-text">Sanitized text<\/label>/.test(html) &&
      /<textarea\s+id="output-text"/.test(html),
    note: "Original and sanitized textareas have matching labels."
  },
  {
    name: "button text",
    passed: /<button\s+id="sanitize-button"[^>]*>Sanitize<\/button>/.test(html) &&
      /<button\s+id="copy-button"[^>]*>Copy sanitized text<\/button>/.test(html) &&
      /<button\s+id="clear-button"[^>]*>Clear<\/button>/.test(html),
    note: "Primary controls use understandable visible text."
  },
  {
    name: "checkbox label",
    passed: /<label\s+class="toggle"[^>]*>[\s\S]*<input\s+id="redact-ip"\s+type="checkbox"\s+checked>[\s\S]*Redact non-loopback IPv4 addresses[\s\S]*<\/label>/.test(html),
    note: "IPv4 checkbox is wrapped in a label with descriptive text."
  },
  {
    name: "semantic landmarks",
    passed: /<header\b/.test(html) && /<main\b/.test(html) && /<section\b/.test(html) && /<h1>SafePaste<\/h1>/.test(html),
    note: "Page uses header, main, section, and heading elements."
  },
  {
    name: "status live region",
    passed: /id="status-message"[^>]*role="status"[^>]*aria-live="polite"/.test(html),
    note: "Status message is exposed through a polite live region."
  },
  {
    name: "summary labels",
    passed: /aria-labelledby="summary-title"/.test(html) && /aria-label="Detected sensitive data categories"/.test(html),
    note: "Review summary and category list have accessible labels."
  },
  {
    name: "disabled copy default",
    passed: /<button\s+id="copy-button"[^>]*disabled>Copy sanitized text<\/button>/.test(html),
    note: "Copy starts disabled until sanitized output exists."
  },
  {
    name: "visible focus styles",
    passed: /:focus-visible/.test(css) && /outline:\s*3px\s+solid\s+var\(--focus\)/.test(css),
    note: "Keyboard focus-visible styles are defined for buttons, textareas, and inputs."
  },
  {
    name: "native keyboard controls",
    passed: /<button\b/.test(html) && /<textarea\b/.test(html) && /type="checkbox"/.test(html),
    note: "Controls use native keyboard-operable elements."
  },
  {
    name: "status not color-only",
    passed: /Ready\. Paste logs to begin\./.test(html) && /redactions found/.test(html),
    note: "Important state is presented as text, not only color."
  }
];

let passed = 0;

checks.forEach((check) => {
  if (check.passed) {
    passed += 1;
    console.log(`PASS accessibility static: ${check.name} - ${check.note}`);
  } else {
    console.error(`FAIL accessibility static: ${check.name} - ${check.note}`);
  }
});

console.log(`${passed}/${checks.length} accessibility static checks passed`);

if (passed !== checks.length) {
  process.exitCode = 1;
}
