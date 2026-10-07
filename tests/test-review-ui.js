"use strict";

const assert = require("assert");
const fs = require("fs");
const engine = require("../src/sanitizer");
const { buildHarness, descendants } = require("./ui-harness");
let passed = 0;
const tests = [];
function test(name, run) { tests.push([name, run]); }
function controls(h) {
  return descendants(h.elements["findings-list"]).filter(node => node.tagName === "SELECT");
}
function metadata(h) {
  return ["findings-list", "privacy-report", "preview-panel", "policy-details"]
    .map(id => h.elements[id].textContent).join("\n");
}
async function sanitize(h, value, profile) {
  if (profile) {
    h.elements["profile-select"].value = profile;
    await h.elements["profile-select"].dispatch("change");
  }
  h.elements["input-text"].value = value;
  await h.elements["input-text"].dispatch("input");
  await h.elements["sanitize-button"].dispatch("click");
}
function stale(h) {
  const e = h.elements;
  assert.strictEqual(e["output-text"].value, "");
  assert.strictEqual(e["redaction-count"].textContent, "0");
  assert.strictEqual(e["finding-count"].textContent, "0");
  assert(e["copy-button"].disabled);
  assert(e["download-log"].disabled);
  assert(e["download-report"].disabled);
  assert(!e["privacy-report"].textContent.includes("FINDINGS:"));
  assert(!e["preview-panel"].textContent.includes("MASKED"));
}
const input = "email=review@example.test password=SyntheticPassword client_ip=192.168.1.20 localhost=127.0.0.1";

test("Compatibility preserves original IPv4 control while strict detects loopback", async () => {
  const h = buildHarness();
  await sanitize(h, input);
  assert(h.elements["output-text"].value.includes("localhost=127.0.0.1"));
  assert(h.elements["policy-details"].textContent.includes("legacy"));
  assert(h.elements["policy-warning"].textContent.includes("omits preserved IPv4"));
  await sanitize(h, input, "strict");
  assert(!h.elements["output-text"].value.includes("127.0.0.1"));
  assert.strictEqual(h.elements["finding-count"].textContent, "4");
  assert(h.elements["legacy-controls"].hidden);
});

test("support and incident KEEP network only in final output, never masked preview", async () => {
  for (const profile of ["support", "incident"]) {
    const h = buildHarness();
    await sanitize(h, input + " external=203.0.113.24", profile);
    assert(h.elements["output-text"].value.includes("192.168.1.20"));
    assert(h.elements["output-text"].value.includes("127.0.0.1"));
    assert.strictEqual(h.elements["output-text"].value.includes("203.0.113.24"), profile === "incident");
    for (const value of ["192.168.1.20", "127.0.0.1", "203.0.113.24", "review@example.test", "SyntheticPassword"]) {
      assert(!metadata(h).includes(value), profile + " metadata/preview leaked " + value);
    }
    assert(h.elements["policy-warning"].textContent.includes("public sharing"));
  }
});

test("per-finding KEEP/REDACT is deterministic; hidden output is emptied during Preview", async () => {
  const h = buildHarness();
  await sanitize(h, "email=review@example.test email=other@example.test", "strict");
  const actions = controls(h);
  assert.strictEqual(actions.length, 2);
  actions[0].value = "KEEP";
  await actions[0].dispatch("change");
  assert(h.elements["output-text"].value.includes("review@example.test"));
  assert(!h.elements["output-text"].value.includes("other@example.test"));
  const kept = h.elements["output-text"].value;
  assert(!metadata(h).includes("review@example.test"));
  await h.elements["preview-tab"].dispatch("click");
  assert.strictEqual(h.elements["output-text"].value, "");
  assert(h.elements["output-text"].hidden);
  await h.elements["copy-button"].dispatch("click");
  assert.strictEqual(h.copied(), kept);
  await h.elements["sanitized-tab"].dispatch("click");
  assert.strictEqual(h.elements["output-text"].value, kept);
  actions[0].value = "REDACT";
  await actions[0].dispatch("change");
  assert(!h.elements["output-text"].value.includes("review@example.test"));
  assert.strictEqual(h.elements["redaction-count"].textContent, "2");
  actions[0].value = "KEEP";
  await actions[0].dispatch("change");
  assert.strictEqual(h.elements["output-text"].value, kept);
});

test("locked credentials have no KEEP control and tampered decisions fail closed", async () => {
  const h = buildHarness();
  await sanitize(h, input, "strict");
  assert.strictEqual(controls(h).length, 3);
  assert(h.elements["findings-list"].textContent.includes("locked high-risk"));
  const control = controls(h)[0];
  control.value = "BOGUS";
  await control.dispatch("change");
  stale(h);
  assert(h.elements["status-message"].textContent.includes("INVALID_ACTION"));
  assert(!h.elements["status-message"].textContent.includes("review@example.test"));
});

test("input edits discard output, preview, report and decisions before resanitizing", async () => {
  const h = buildHarness();
  await sanitize(h, input, "strict");
  const control = controls(h)[0];
  control.value = "KEEP";
  await control.dispatch("change");
  h.elements["input-text"].value += " changed";
  await h.elements["input-text"].dispatch("input");
  stale(h);
  await h.elements["copy-button"].dispatch("click");
  await h.elements["download-report"].dispatch("click");
  assert.strictEqual(h.copied(), "");
  assert.strictEqual(h.downloads.length, 0);
  await h.elements["sanitize-button"].dispatch("click");
  assert(!h.elements["output-text"].value.includes("review@example.test"));
});

test("every policy/category/format input invalidates output and resets overrides", async () => {
  const names = ["profile-select", "format-select", "redact-ip", "category-email",
    "category-usernames", "category-paths", "category-network", "preserve-loopback", "preserve-private"];
  for (const name of names) {
    const h = buildHarness();
    await sanitize(h, input, name === "redact-ip" ? "legacy" : "custom");
    const control = controls(h)[0];
    control.value = "KEEP";
    await control.dispatch("change");
    const changed = h.elements[name];
    if (name === "profile-select") changed.value = "strict";
    else if (name === "format-select") changed.value = "text";
    else changed.checked = !changed.checked;
    await changed.dispatch("change");
    stale(h);
    await h.elements["sanitize-button"].dispatch("click");
    if (name !== "category-email") assert(!h.elements["output-text"].value.includes("review@example.test"));
  }
});

test("custom category/network toggles are inspectable; high-risk categories stay locked", async () => {
  const h = buildHarness();
  await sanitize(h, input, "custom");
  h.elements["category-email"].checked = false;
  h.elements["preserve-private"].checked = true;
  await h.elements["category-email"].dispatch("change");
  await h.elements["sanitize-button"].dispatch("click");
  assert(h.elements["output-text"].value.includes("review@example.test"));
  assert(h.elements["output-text"].value.includes("192.168.1.20"));
  assert(!h.elements["output-text"].value.includes("SyntheticPassword"));
  assert(!metadata(h).includes("review@example.test"));
  const policy = JSON.parse(h.elements["policy-details"].textContent);
  assert.strictEqual(policy.categories.email, "KEEP");
  assert.strictEqual(policy.categories.credentials, "REDACT");
  assert.strictEqual(policy.network.preservePrivate, true);
  assert(!h.elements["custom-controls"].disabled);
  assert(!h.elements["custom-controls"].hidden);
});

test("escaped JSON, hostile markup and user strings use text-only DOM", async () => {
  const h = buildHarness();
  const value = String.raw`{"password":"<img src=x onerror=alert(1)>","email":"review\u0040example.test","note":"<svg onload=alert(1)>"}`;
  await sanitize(h, value, "strict");
  assert.strictEqual(JSON.parse(h.elements["output-text"].value).password, "[REDACTED_PASSWORD]");
  assert(!metadata(h).includes("<img"));
  assert(h.elements["preview-panel"].textContent.includes("<svg onload=alert(1)>"));
  const nodes = descendants(h.elements["preview-panel"]).concat(descendants(h.elements["findings-list"]));
  assert(!nodes.some(node => ["IMG", "SVG", "SCRIPT"].includes(node.tagName)));
  assert(!fs.readFileSync(require.resolve("../app.js"), "utf8").includes("innerHTML"));
});

test("downloads are explicit, fixed-name final output and metadata-only JSON", async () => {
  const h = buildHarness();
  await sanitize(h, input, "strict");
  assert.strictEqual(h.downloads.length, 0);
  const control = controls(h)[0];
  control.value = "KEEP";
  await control.dispatch("change");
  const finalOutput = h.elements["output-text"].value;
  await h.elements["preview-tab"].dispatch("click");
  await h.elements["download-log"].dispatch("click");
  await h.elements["download-report"].dispatch("click");
  assert.deepStrictEqual(h.downloads.map(item => item.name), ["sanitized.log", "privacy-report.json"]);
  assert.strictEqual(await h.downloads[0].blob.text(), finalOutput);
  const json = await h.downloads[1].blob.text();
  for (const value of ["review@example.test", "SyntheticPassword", "192.168.1.20", "127.0.0.1"]) assert(!json.includes(value));
  const report = JSON.parse(json);
  assert.strictEqual(report.kept, 1);
  assert.strictEqual(report.redacted, 3);
  assert.strictEqual(report.policy.name, "strict");
  assert.strictEqual(report.networkEgress, "none");
  assert.strictEqual(report.persistentStorage, "none");
  assert(!Object.hasOwn(report, "original"));
  assert.strictEqual(h.document.body.children.length, 0);
  await h.elements["input-text"].dispatch("input");
  assert.strictEqual(h.revoked.length, 2);
  h.flushTimers();
  assert.strictEqual(h.revoked.length, 2);
});

test("async copy cannot resurrect stale success or manual-copy selection after edit", async () => {
  for (const rejected of [false, true]) {
    let resolve;
    let reject;
    const h = buildHarness({ clipboard: () => new Promise((yes, no) => { resolve = yes; reject = no; }) });
    await sanitize(h, input, "strict");
    const pending = h.elements["copy-button"].dispatch("click");
    await h.elements["input-text"].dispatch("input");
    if (rejected) reject(new Error("denied")); else resolve();
    await pending;
    stale(h);
    assert.strictEqual(h.elements["copy-button"].textContent, "Copy sanitized text");
    assert(!h.elements["output-text"].selected);
    assert(h.elements["status-message"].textContent.includes("Input changed"));
  }
});

test("clipboard rejection selects reviewed final text even from Preview", async () => {
  const h = buildHarness({ clipboard: async () => { throw new Error("denied"); } });
  await sanitize(h, "email=review@example.test", "strict");
  const control = controls(h)[0];
  control.value = "KEEP";
  await control.dispatch("change");
  await h.elements["preview-tab"].dispatch("click");
  await h.elements["copy-button"].dispatch("click");
  assert(!h.elements["output-text"].hidden);
  assert(h.elements["output-text"].selected);
  assert(h.elements["output-text"].value.includes("review@example.test"));
  assert(h.elements["status-message"].textContent.includes("KEEP decisions"));
});

test("review decisions invalidate pending copy feedback and revoke temporary download URLs", async () => {
  let resolve;
  const h = buildHarness({ clipboard: () => new Promise(yes => { resolve = yes; }) });
  await sanitize(h, "email=review@example.test", "strict");
  await h.elements["download-log"].dispatch("click");
  const pending = h.elements["copy-button"].dispatch("click");
  const action = controls(h)[0];
  action.value = "KEEP";
  await action.dispatch("change");
  resolve();
  await pending;
  assert.strictEqual(h.elements["copy-button"].textContent, "Copy sanitized text");
  assert(h.elements["status-message"].textContent.includes("Review decision"));
  assert.strictEqual(h.revoked.length, 1);
});

test("file picker and drag/drop clear old output and read only local supported files", async () => {
  for (const picker of [true, false]) {
    const h = buildHarness();
    await sanitize(h, input);
    const file = { name: "<script>.log", type: "text/plain", size: 32 };
    if (picker) {
      h.elements["file-input"].files = [file];
      await h.elements["file-input"].dispatch("change");
    } else {
      await h.dataElements["[data-drop-zone]"].dispatch("drop", { dataTransfer: { files: [file] } });
    }
    stale(h);
    assert.strictEqual(h.readers.length, 1);
    h.readers[0].complete("email=loaded@example.test");
    assert.strictEqual(h.elements["input-text"].value, "email=loaded@example.test");
    assert(!h.elements["status-message"].textContent.includes("<script>"));
    stale(h);
    await h.elements["sanitize-button"].dispatch("click");
    assert(!h.elements["output-text"].value.includes("loaded@example.test"));
  }
});

test("file size, text length, unsupported type and read errors fail without partial output", async () => {
  for (const mode of ["size", "text", "type", "error"]) {
    const h = buildHarness();
    await sanitize(h, input);
    h.elements["file-input"].files = [{
      name: mode === "type" ? "file.bin" : "file.log",
      type: mode === "type" ? "application/octet-stream" : "text/plain",
      size: mode === "size" ? 2097153 : 10
    }];
    await h.elements["file-input"].dispatch("change");
    if (mode === "text") h.readers[0].complete("x".repeat(2097153));
    if (mode === "error") h.readers[0].fail();
    stale(h);
    assert.strictEqual(h.elements["input-text"].value, input);
    if (mode === "size" || mode === "type") assert.strictEqual(h.readers.length, 0);
  }
});

test("edits, clear, policy change, and a newer file invalidate delayed file reads", async () => {
  for (const event of ["edit", "clear", "policy", "newer"]) {
    const h = buildHarness();
    h.elements["file-input"].files = [{ name: "one.log", type: "text/plain", size: 10 }];
    await h.elements["file-input"].dispatch("change");
    const old = h.readers[0];
    if (event === "edit") {
      h.elements["input-text"].value = "new manual input";
      await h.elements["input-text"].dispatch("input");
    } else if (event === "clear") {
      await h.elements["clear-button"].dispatch("click");
    } else if (event === "policy") {
      h.elements["profile-select"].value = "strict";
      await h.elements["profile-select"].dispatch("change");
    } else {
      h.elements["file-input"].files = [{ name: "two.log", type: "text/plain", size: 10 }];
      await h.elements["file-input"].dispatch("change");
      h.readers[1].complete("new file");
    }
    const expected = h.elements["input-text"].value;
    old.complete("stale sensitive file");
    assert.strictEqual(h.elements["input-text"].value, expected);
    assert(old.aborted);
    stale(h);
  }
});

test("replacement and Clear require confirmation without losing state on cancel", async () => {
  const h = buildHarness({ confirm: () => false });
  await sanitize(h, input);
  const output = h.elements["output-text"].value;
  await h.elements["sample-button"].dispatch("click");
  await h.elements["clear-button"].dispatch("click");
  h.elements["file-input"].files = [{ name: "test.log", type: "text/plain", size: 1 }];
  await h.elements["file-input"].dispatch("change");
  assert.strictEqual(h.elements["input-text"].value, input);
  assert.strictEqual(h.elements["output-text"].value, output);
  assert.strictEqual(h.readers.length, 0);
});

test("all samples are labeled synthetic and clear prior decisions without automatic export", async () => {
  const h = buildHarness();
  for (const sample of ["web", "cloud", "auth", "support"]) {
    await sanitize(h, input, "strict");
    h.elements["sample-select"].value = sample;
    await h.elements["sample-button"].dispatch("click");
    assert(h.elements["input-text"].value.includes("SAMPLE / SYNTHETIC DATA"));
    stale(h);
    await h.elements["sanitize-button"].dispatch("click");
    assert(Number(h.elements["finding-count"].textContent) > 0, sample);
    assert.strictEqual(h.downloads.length, 0);
    assert.strictEqual(h.copied(), "");
  }
});

test("native tab keys, shortcuts, cursor, line gutters and scroll stay wired", async () => {
  const h = buildHarness();
  h.elements["input-text"].value = "email=review@example.test\r\nuser=demo_user\rlocal=127.0.0.1";
  await h.document.dispatch("keydown", { ctrlKey: true, key: "Enter" });
  assert.strictEqual(h.elements["input-gutter"].textContent, "1\n2\n3");
  assert.strictEqual(h.elements["output-gutter"].textContent, "1\n2\n3");
  h.elements["input-text"].selectionStart = 28;
  await h.elements["input-text"].dispatch("keyup");
  assert(h.dataElements["[data-cursor-status]"].textContent.includes("Ln 2"));
  h.elements["input-text"].scrollTop = 120;
  await h.elements["input-text"].dispatch("scroll");
  assert.strictEqual(h.elements["input-gutter"].scrollTop, 120);
  await h.elements["sanitized-tab"].dispatch("keydown", { key: "ArrowRight" });
  assert.strictEqual(h.elements["preview-tab"].getAttribute("tabindex"), "0");
  assert.strictEqual(h.elements["preview-tab"].getAttribute("aria-selected"), "true");
  assert(h.elements["preview-tab"].focused);
  h.elements["preview-panel"].scrollTop = 200;
  await h.elements["preview-panel"].dispatch("scroll");
  assert.strictEqual(h.elements["output-gutter"].scrollTop, 200);
  await h.document.dispatch("keydown", { metaKey: true, shiftKey: true, key: "C" });
  assert(h.copied().includes("[REDACTED_EMAIL]"));
  await h.elements["preview-tab"].dispatch("keydown", { key: "Home" });
  assert.strictEqual(h.elements["sanitized-tab"].getAttribute("tabindex"), "0");
});

test("findings pagination bounds DOM and preserves per-finding decisions across pages", async () => {
  const h = buildHarness();
  await sanitize(h, Array.from({ length: 105 }, (_, i) => "email=user" + i + "@example.test").join("\n"), "strict");
  assert.strictEqual(controls(h).length, 50);
  controls(h)[0].value = "KEEP";
  await controls(h)[0].dispatch("change");
  await h.elements["findings-next"].dispatch("click");
  assert.strictEqual(controls(h).length, 50);
  await h.elements["findings-next"].dispatch("click");
  assert.strictEqual(controls(h).length, 5);
  assert(h.elements["findings-next"].disabled);
  await h.elements["findings-previous"].dispatch("click");
  await h.elements["findings-previous"].dispatch("click");
  assert.strictEqual(controls(h)[0].value, "KEEP");
  assert(h.elements["findings-page"].textContent.includes("105"));
});

test("programmatic stale input/policy is rejected at copy, export and view boundaries", async () => {
  for (const button of ["copy-button", "download-log", "download-report", "preview-tab"]) {
    const h = buildHarness();
    await sanitize(h, input, "strict");
    h.elements["input-text"].value = "changed without input event";
    await h.elements[button].dispatch("click");
    stale(h);
    assert.strictEqual(h.copied(), "");
    assert.strictEqual(h.downloads.length, 0);
  }
  const h = buildHarness();
  await sanitize(h, input);
  h.elements["redact-ip"].checked = false;
  await h.elements["copy-button"].dispatch("click");
  stale(h);
});

test("input limits fail closed; Clear and page exit release review closure and revoke exports", async () => {
  let clears = 0;
  const spy = Object.assign({}, engine, { createSession() {
    const owner = engine.createSession();
    return { clear: owner.clear, createReview(value, options) {
      const session = owner.createReview(value, options);
      return { findings: session.findings, apply: session.apply, clear() { clears += 1; session.clear(); } };
    } };
  } });
  const h = buildHarness({ engine: spy });
  await sanitize(h, input, "strict");
  await h.elements["download-log"].dispatch("click");
  await h.elements["clear-button"].dispatch("click");
  assert.strictEqual(clears, 1);
  assert.strictEqual(h.revoked.length, 1);
  assert.strictEqual(h.elements["input-text"].value, "");
  stale(h);
  await sanitize(h, input, "strict");
  await h.window.dispatch("pagehide");
  assert.strictEqual(clears, 2);
  stale(h);
  await sanitize(h, "x".repeat(2097153), "strict");
  stale(h);
  assert(h.elements["status-message"].textContent.includes("INPUT_LIMIT"));
});

test("empty analysis never claims safe output; metadata report remains explicit", async () => {
  const h = buildHarness();
  await sanitize(h, "", "strict");
  assert(h.elements["copy-button"].disabled);
  assert(h.elements["download-log"].disabled);
  assert(!h.elements["download-report"].disabled);
  assert(h.elements["status-message"].textContent.includes("Human review required"));
  assert(h.elements["findings-list"].textContent.includes("unknown secrets"));
  assert(!/guaranteed|100%|safe to share/i.test(h.elements["status-message"].textContent));
});

(async function () {
  for (const [name, run] of tests) {
    try { await run(); passed += 1; console.log("PASS review UI: " + name); }
    catch (error) { console.error("FAIL review UI: " + name + "\n" + error.stack); }
  }
  console.log(passed + "/" + tests.length + " mocked review UI checks passed");
  if (passed !== tests.length) process.exitCode = 1;
})();
