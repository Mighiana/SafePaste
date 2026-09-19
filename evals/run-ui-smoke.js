const fs = require("fs");
const path = require("path");
const vm = require("vm");
const sanitizer = require("../src/sanitizer");

function createElement(id) {
  return {
    id,
    value: "",
    checked: true,
    disabled: false,
    textContent: "",
    children: [],
    listeners: {},
    appendChild(child) {
      this.children.push(child);
    },
    replaceChildren(...children) {
      this.children = children;
    },
    addEventListener(type, handler) {
      this.listeners[type] = handler;
    },
    async dispatch(type) {
      if (!this.listeners[type]) {
        throw new Error(`No listener registered for ${this.id}:${type}`);
      }
      await this.listeners[type]();
    },
    focus() {
      this.focused = true;
    },
    select() {
      this.selected = true;
    }
  };
}

const elements = {
  "input-text": createElement("input-text"),
  "output-text": createElement("output-text"),
  "sanitize-button": createElement("sanitize-button"),
  "copy-button": createElement("copy-button"),
  "clear-button": createElement("clear-button"),
  "redact-ip": createElement("redact-ip"),
  "redaction-count": createElement("redaction-count"),
  "category-list": createElement("category-list"),
  "status-message": createElement("status-message")
};

let copiedText = "";

const sandbox = {
  window: {
    SafePasteSanitizer: sanitizer
  },
  document: {
    getElementById(id) {
      if (!elements[id]) {
        throw new Error(`Missing test element: ${id}`);
      }
      return elements[id];
    },
    createElement(tagName) {
      const element = createElement(tagName);
      element.tagName = tagName.toUpperCase();
      return element;
    }
  },
  navigator: {
    clipboard: {
      async writeText(value) {
        copiedText = value;
      }
    }
  }
};

vm.createContext(sandbox);
const appJs = fs.readFileSync(path.resolve(__dirname, "..", "app.js"), "utf8");
vm.runInContext(appJs, sandbox, { filename: "app.js" });

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
  assert(copiedText === output, "copy button should write sanitized text to clipboard API");

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
