"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const sanitizer = require("../src/sanitizer");

function createElement(id, tag) {
  const attrs = {};
  const classes = new Set();
  let content = "";
  const element = {
    id, tagName: (tag || "div").toUpperCase(), value: "", checked: false,
    disabled: false, hidden: false, children: [], listeners: {}, files: [],
    selectionStart: 0, scrollTop: 0,
    classList: {
      add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
      contains(name) { return classes.has(name); },
      toggle(name, force) {
        const add = force === undefined ? !classes.has(name) : force;
        if (add) classes.add(name); else classes.delete(name);
        return add;
      }
    },
    setAttribute(name, value) { attrs[name] = String(value); },
    getAttribute(name) { return attrs[name] === undefined ? null : attrs[name]; },
    appendChild(child) {
      Object.defineProperty(child, "parent", { value: this, configurable: true, writable: true });
      this.children.push(child);
      return child;
    },
    replaceChildren(...children) { content = ""; this.children = children; },
    addEventListener(type, handler) {
      if (!this.listeners[type]) this.listeners[type] = [];
      this.listeners[type].push(handler);
    },
    async dispatch(type, event = {}) {
      if (!this.listeners[type]) throw new Error("No listener registered for " + id + ":" + type);
      const args = Object.assign({ target: this, preventDefault() { this.prevented = true; } }, event);
      for (const handler of this.listeners[type]) await handler(args);
      return args;
    },
    querySelector(selector) { return descendants(this).find(child => child.tagName.toLowerCase() === selector) || null; },
    focus() { this.focused = true; }, select() { this.selected = true; },
    click() { this.clicked = true; if (this.onClick) this.onClick(); },
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
  };
  Object.defineProperty(element, "textContent", {
    enumerable: true,
    get() { return content + this.children.map(child => child.textContent).join(""); },
    set(value) { content = String(value); this.children = []; }
  });
  return element;
}

function descendants(element) {
  return element.children.flatMap(child => [child].concat(descendants(child)));
}

function buildHarness(config = {}) {
  const html = fs.readFileSync(path.resolve(__dirname, "../index.html"), "utf8");
  const elements = {};
  for (const match of html.matchAll(/<([\w-]+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
    const element = createElement(match[3], match[1]);
    element.checked = /\bchecked\b/.test(match[2]);
    element.disabled = /\bdisabled\b/.test(match[2]);
    element.hidden = /\bhidden\b/.test(match[2]);
    elements[match[3]] = element;
  }
  elements["profile-select"].value = "legacy";
  elements["format-select"].value = "auto";
  elements["sample-select"].value = "web";
  const dataElements = {};
  for (const name of ["drop-zone", "original-meta", "output-meta", "cursor-status", "status-redaction-count", "category-dots"]) {
    dataElements["[data-" + name + "]"] = createElement(name);
  }
  const chips = ["credentials", "tokens", "email", "usernames", "network"].map(name => {
    const chip = createElement(name);
    chip.setAttribute("data-rule-chip", name);
    chip.appendChild(createElement(name + "-count", "strong"));
    return chip;
  });
  let copiedText = "";
  const downloads = [];
  const readers = [];
  const blobs = new Map();
  const revoked = [];
  const timers = new Map();
  let nextTimer = 0;
  const document = createElement("document");
  document.body = createElement("body");
  document.getElementById = function (id) {
    if (!elements[id]) throw new Error("Missing test element: " + id);
    return elements[id];
  };
  document.querySelector = function (selector) {
    if (!dataElements[selector]) throw new Error("Missing test selector: " + selector);
    return dataElements[selector];
  };
  document.querySelectorAll = function (selector) { return selector === "[data-rule-chip]" ? chips : []; };
  document.createTextNode = function (value) {
    const element = createElement("text", "#text");
    element.textContent = value;
    return element;
  };
  document.createElement = function (tag) {
    const element = createElement(tag, tag);
    if (tag === "a") element.onClick = () => downloads.push({ name: element.download, blob: blobs.get(element.href), href: element.href });
    return element;
  };
  class MockReader {
    constructor() { this.readyState = 0; readers.push(this); }
    readAsText(file) { this.file = file; this.readyState = 1; }
    abort() { this.aborted = true; this.readyState = 2; }
    complete(value) { this.result = value; this.readyState = 2; this.onload(); }
    fail() { this.readyState = 2; this.onerror(); }
  }
  const window = createElement("window");
  window.SafePasteSanitizer = config.engine || sanitizer;
  window.confirm = config.confirm || (() => true);
  const sandbox = {
    window, document, Blob, FileReader: MockReader,
    URL: {
      createObjectURL(blob) { const url = "blob:mock-" + blobs.size; blobs.set(url, blob); return url; },
      revokeObjectURL(url) { revoked.push(url); }
    },
    setTimeout(fn) { const id = ++nextTimer; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
    navigator: { clipboard: { async writeText(value) {
      copiedText = value;
      if (config.clipboard) return config.clipboard(value);
    } } }
  };
  if (config.Worker) sandbox.Worker = config.Worker;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.resolve(__dirname, "../app.js"), "utf8"), sandbox, { filename: "app.js" });
  return {
    elements, document, window, downloads, readers, dataElements, chips, revoked,
    copied() { return copiedText; },
    flushTimers() { const pending = Array.from(timers.values()); timers.clear(); pending.forEach(fn => fn()); }
  };
}

module.exports = { buildHarness, descendants };
