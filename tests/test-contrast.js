"use strict";

// Static WCAG AA audit of the solid colour-token pairs the UI actually renders, in both themes.
// Pairs are listed by role; a rendered-browser audit is still recorded separately in docs/evidence.
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const css = fs.readFileSync(path.resolve(__dirname, "../styles.css"), "utf8");

function block(source) {
  const tokens = {};
  for (const match of source.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;/gi)) tokens[match[1]] = match[2].toLowerCase();
  return tokens;
}

const lightStart = css.indexOf(":root {");
const light = block(css.slice(lightStart, css.indexOf("}", lightStart)));
const darkStart = css.indexOf(':root[data-theme="dark"] {');
assert(darkStart > lightStart, "dark theme :root block present");
const dark = Object.assign({}, light, block(css.slice(darkStart, css.indexOf("}", darkStart))));

function luminance(hex) {
  const [r, g, b] = [1, 3, 5].map(i => parseInt(hex.slice(i, i + 2), 16) / 255)
    .map(c => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function ratio(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

// [foreground, background, where it is used]
const pairs = [
  ["text-primary", "surface", "body text"],
  ["text-secondary", "surface-secondary", "finding text, verify cards"],
  ["text-muted", "surface", "hints, zero counts"],
  ["text-muted", "surface-secondary", "status bar, disabled buttons"],
  ["text-muted", "editor-readonly", "empty output state"],
  ["text-faint", "surface-tertiary", "line-number gutter"],
  ["text-secondary", "editor-readonly", "sanitized text"],
  ["text-primary", "editor-bg", "original text"],
  ["success-strong", "success-soft", "trust badge and indicators"],
  ["success-strong", "surface", "completed flow steps"],
  ["on-action", "success-strong", "completed step tick"],
  ["on-action", "action", "Sanitize, Copy, Download sanitized.log, rule-chip counts"],
  ["on-action", "action-hover", "primary button hover"],
  ["primary-hover", "primary-soft", "active flow step and tab"],
  ["primary-hover", "surface-secondary", "status-bar counts"],
  ["primary-hover", "surface", "redaction count"],
  ["warning-text", "warning-soft", "review warning"],
  ["warning-text", "surface", "finding count"],
  ["danger", "danger-soft", "locked high-risk pill"],
  ["on-badge", "badge-low", "LOW badge"],
  ["on-badge", "badge-medium", "MEDIUM badge"],
  ["on-badge", "badge-high", "HIGH badge"],
  ["link", "surface-secondary", "finding line links"],
  ["link", "surface-tertiary", "hovered finding line link"],
  ["link", "editor-readonly", "load-a-sample link"],
  ["text-primary", "primary-soft", "active rule chip label"]
];

let passed = 0;
for (const [theme, tokens] of [["light", light], ["dark", dark]]) {
  for (const [fg, bg, where] of pairs) {
    assert(tokens[fg] && tokens[bg], theme + " tokens defined: " + fg + ", " + bg);
    const value = ratio(tokens[fg], tokens[bg]);
    assert(value >= 4.5, theme + " " + where + ": --" + fg + " on --" + bg + " is " + value.toFixed(2) + ":1 (< 4.5)");
    passed += 1;
  }
}
console.log(passed + "/" + pairs.length * 2 + " contrast pairs meet WCAG AA 4.5:1 (light and dark)");
