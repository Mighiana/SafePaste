"use strict";

// src/theme.js in a minimal DOM: follows the system theme until the user picks one, and stores nothing.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const source = fs.readFileSync(path.resolve(__dirname, "../src/theme.js"), "utf8");
let passed = 0;

function load(systemDark) {
  const attributes = {};
  const listeners = {};
  const media = { matches: systemDark, addEventListener: (type, fn) => { media.change = fn; } };
  const button = {
    attributes: {}, title: "",
    setAttribute(name, value) { this.attributes[name] = String(value); },
    addEventListener(type, fn) { this.click = fn; }
  };
  const document = {
    documentElement: {
      setAttribute(name, value) { attributes[name] = String(value); },
      getAttribute(name) { return attributes[name]; }
    },
    getElementById: id => (id === "theme-toggle" ? button : null),
    addEventListener: (type, fn) => { listeners[type] = fn; }
  };
  const window = { matchMedia: query => { assert.strictEqual(query, "(prefers-color-scheme: dark)"); return media; } };
  vm.runInNewContext(source, { window, document });
  listeners.DOMContentLoaded();
  return { theme: () => attributes["data-theme"], button, media };
}

function test(name, run) {
  run();
  passed += 1;
  console.log("PASS " + name);
}

test("starts on the system theme and labels the switch with the other one", () => {
  const light = load(false);
  assert.strictEqual(light.theme(), "light");
  assert.strictEqual(light.button.attributes["aria-label"], "Switch to dark theme");
  const dark = load(true);
  assert.strictEqual(dark.theme(), "dark");
  assert.strictEqual(dark.button.attributes["aria-label"], "Switch to light theme");
  assert.strictEqual(dark.button.title, "Switch to light theme");
});

test("the switch flips the theme both ways", () => {
  const h = load(false);
  h.button.click();
  assert.strictEqual(h.theme(), "dark");
  assert.strictEqual(h.button.attributes["aria-label"], "Switch to light theme");
  h.button.click();
  assert.strictEqual(h.theme(), "light");
});

test("system changes apply until the user picks a theme", () => {
  const h = load(false);
  h.media.change({ matches: true });
  assert.strictEqual(h.theme(), "dark");
  h.button.click();
  h.media.change({ matches: true });
  assert.strictEqual(h.theme(), "light", "a manual choice wins over later system changes");
});

test("no storage, cookies or network APIs", () => {
  for (const banned of [/localStorage/, /sessionStorage/, /document\.cookie/, /indexedDB/, /fetch\s*\(/, /XMLHttpRequest/]) {
    assert(!banned.test(source), banned + " in theme.js");
  }
});

console.log(passed + "/4 theme checks passed");
