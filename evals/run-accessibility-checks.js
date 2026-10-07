const fs = require("fs");
const path = require("path");

const projectRoot = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(projectRoot, "index.html"), "utf8");
const css = fs.readFileSync(path.join(projectRoot, "styles.css"), "utf8");

function contrast(foreground, background) {
  function luminance(hex) {
    const rgb = hex.match(/[a-f\d]{2}/gi).map(value => {
      const channel = parseInt(value, 16) / 255;
      return channel <= 0.04045 ? channel / 12.92 : Math.pow((channel + 0.055) / 1.055, 2.4);
    });
    return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
  }
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

function cssColor(name) {
  const match = css.match(new RegExp("--" + name + ":\\s*(#[a-f\\d]{6})", "i"));
  return match && match[1];
}

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
  },
  {
    name: "profile and format labels",
    passed: /<label for="profile-select">Privacy profile/.test(html) &&
      /<select id="profile-select" aria-describedby="policy-warning">/.test(html) &&
      /<label for="format-select">Input format/.test(html) && /<select id="format-select">/.test(html),
    note: "Profile and format selectors have visible native labels and policy description."
  },
  {
    name: "file picker alternative",
    passed: /<label for="file-input">Open local text file/.test(html) && /<input id="file-input" type="file"/.test(html),
    note: "Local drag/drop has a keyboard-operable file picker alternative."
  },
  {
    name: "custom category labels",
    passed: /<fieldset id="custom-controls" hidden disabled>/.test(html) &&
      /<legend>Custom categories/.test(html) &&
      ["email", "usernames", "paths", "network"].every(name =>
        new RegExp('<label><input id="category-' + name + '" type="checkbox" checked>').test(html)),
    note: "Custom controls are grouped in a labeled fieldset, initially hidden and disabled."
  },
  {
    name: "output tab semantics",
    passed: /id="sanitized-tab"[^>]*role="tab"[^>]*aria-selected="true"[^>]*aria-controls="output-text"/.test(html) &&
      /id="preview-tab"[^>]*role="tab"[^>]*aria-selected="false"[^>]*aria-controls="preview-panel"[^>]*tabindex="-1"/.test(html) &&
      /id="output-text"[^>]*role="tabpanel"[^>]*aria-labelledby="sanitized-tab"/.test(html) &&
      /id="preview-panel"[^>]*role="tabpanel"[^>]*aria-labelledby="preview-tab"[^>]*tabindex="0"/.test(html),
    note: "Tabs link to named panels with roving focus and a focusable preview."
  },
  {
    name: "review and exports explained",
    passed: /aria-labelledby="findings-title"/.test(html) && /aria-label="Detected findings"/.test(html) &&
      /Preview masks every detected value, including KEEP decisions/.test(html) &&
      /id="download-log"[^>]*disabled/.test(html) && /id="download-report"[^>]*disabled/.test(html),
    note: "Findings and explicit exports are labeled; KEEP/preview difference is visible text."
  },
  {
    name: "responsive reduced motion and extra focus",
    passed: /@media \(prefers-reduced-motion: reduce\)/.test(css) &&
      /@media \(max-width: 620px\)/.test(css) && /select:focus-visible/.test(css) && /summary:focus-visible/.test(css) &&
      /\.review-grid, \.editor-help \{ grid-template-columns: 1fr; \}/.test(css),
    note: "New review layout has responsive stacking and native selector/details focus; reduced motion retained."
  },
  {
    name: "muted text contrast tokens",
    passed: ["text-muted", "text-faint", "text-secondary"].every(fg =>
      ["surface", "surface-secondary", "surface-tertiary"].every(bg =>
        cssColor(fg) && cssColor(bg) && contrast(cssColor(fg), cssColor(bg)) >= 4.5)),
    note: "Static solid text/surface token pairs meet 4.5:1; not a full rendered-browser contrast audit."
  },
  {
    name: "physical-line editor layout",
    passed: /id="input-text"[^>]*wrap="off"/.test(html) && /id="output-text"[^>]*wrap="off"/.test(html) &&
      /white-space: pre;\s*word-break: normal;/.test(css),
    note: "Editors and masked preview preserve physical lines with local horizontal scrolling."
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
