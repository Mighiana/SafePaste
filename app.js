(function () {
  "use strict";

  const engine = window.SafePasteSanitizer;
  const byId = function (id) { return document.getElementById(id); };
  const input = byId("input-text");
  const output = byId("output-text");
  const preview = byId("preview-panel");
  const status = byId("status-message");
  const profile = byId("profile-select");
  const format = byId("format-select");
  const mode = byId("mode-select");
  const session = engine.createSession();
  const legacyIp = byId("redact-ip");
  const copy = byId("copy-button");
  const logDownload = byId("download-log");
  const reportDownload = byId("download-report");
  const sanitizedTab = byId("sanitized-tab");
  const previewTab = byId("preview-tab");
  const dropZone = document.querySelector("[data-drop-zone]");
  const categoryControls = ["email", "usernames", "paths", "network"];
  const policyInputs = categoryControls.map(function (name) { return byId("category-" + name); })
    .concat([byId("preserve-loopback"), byId("preserve-private")]);
  const capabilities = engine.getCapabilities();
  const pageSize = 50;
  let review = null;
  let result = null;
  let reviewedInput = null;
  let reviewedOptions = null;
  let maskedOutput = "";
  let overrides = {};
  let generation = 0;
  let page = 0;
  let showPreview = false;
  let reader = null;
  let copyTimer = null;
  const objectUrls = new Set();

  const samples = {
    web: [
      "# SAMPLE / SYNTHETIC DATA — not a real incident",
      "level=error request_id=demo-17 user=demo_user email=demo@example.test client_ip=192.168.1.20 status=500",
      "path=/home/demo_user/app/debug.log release=1.2.3.4"
    ].join("\n"),
    cloud: JSON.stringify({
      sample: "SAMPLE / SYNTHETIC DATA — fake credentials only",
      username: "demo_operator",
      api_key: "DEMO_ONLY",
      client_ip: "203.0.113.24",
      release: "1.2.3.4",
      request_id: "demo-request-42"
    }, null, 2),
    auth: [
      "# SAMPLE / SYNTHETIC DATA — fake authorization only",
      "Authorization: Bearer SYNTHETIC_DEMO_NOT_A_REAL_TOKEN",
      "X-Demo-Account: demo@example.test",
      "X-Request-Id: demo-auth-42"
    ].join("\n"),
    support: [
      "# SAMPLE / SYNTHETIC DATA — fake local configuration",
      "USERNAME=demo_user",
      "PASSWORD=" + "SYNTHETIC_DEMO_NOT_A_REAL_PASSWORD",
      "PWD=/home/demo_user/project",
      "CLIENT_IP=127.0.0.1",
      "RELEASE=1.2.3.4"
    ].join("\n")
  };

  function options() {
    const settings = { format: format.value || "auto", mode: mode.value || "redaction" };
    if (profile.value === "legacy") {
      settings.redactIpAddresses = legacyIp.checked;
    } else {
      settings.profile = profile.value;
      if (profile.value === "custom") {
        settings.categories = {};
        categoryControls.forEach(function (name) {
          settings.categories[name] = byId("category-" + name).checked ? "REDACT" : "KEEP";
        });
        settings.network = {
          preserveLoopback: byId("preserve-loopback").checked,
          preservePrivate: byId("preserve-private").checked
        };
      }
    }
    return settings;
  }

  function inspectPolicy() {
    const policy = engine.inspectPolicy(options());
    byId("custom-controls").hidden = profile.value !== "custom";
    byId("custom-controls").disabled = profile.value !== "custom";
    byId("legacy-controls").hidden = profile.value !== "legacy";
    legacyIp.disabled = profile.value !== "legacy";
    const redactNetwork = byId("category-network").checked;
    byId("preserve-loopback").disabled = !redactNetwork;
    byId("preserve-private").disabled = !redactNetwork;
    byId("policy-details").textContent = JSON.stringify(policy, null, 2);
    byId("policy-warning").textContent = policy.description +
      " Unsupported or unknown sensitive formats may remain. Human review required." +
      (policy.name === "legacy"
        ? " Compatibility omits preserved IPv4 from findings/preview masking; use an explicit profile to review those addresses." : "") +
      (policy.name === "support" || policy.name === "incident" || policy.name === "custom"
        ? " Preserved values may be unsuitable for public sharing." : "");
  }

  function lineCount(value) {
    return value ? value.split(/\r\n|\r|\n/).length : 0;
  }

  function gutter(id, value) {
    const count = Math.max(1, lineCount(value));
    byId(id).textContent = Array.from({ length: count }, function (_, i) { return String(i + 1); }).join("\n");
  }

  function cursorStatus() {
    const before = input.value.slice(0, input.selectionStart || 0);
    const lines = before.split(/\r\n|\r|\n/);
    document.querySelector("[data-cursor-status]").textContent =
      "Ln " + lines.length + ", Col " + (lines[lines.length - 1].length + 1);
  }

  function metrics() {
    gutter("input-gutter", input.value);
    gutter("output-gutter", showPreview ? maskedOutput : output.value);
    const lines = lineCount(input.value);
    document.querySelector("[data-original-meta]").textContent = lines + (lines === 1 ? " line" : " lines");
    document.querySelector("[data-output-meta]").textContent = result
      ? result.report.redacted + " redacted · " + result.report.kept + " kept" : "No current review";
    cursorStatus();
  }

  function resetCopy() {
    if (copyTimer !== null) clearTimeout(copyTimer);
    copyTimer = null;
    copy.textContent = "Copy sanitized text";
  }

  function revokeDownloads() {
    objectUrls.forEach(function (url) { URL.revokeObjectURL(url); });
    objectUrls.clear();
  }

  function abortRead() {
    if (reader) {
      const pending = reader;
      reader = null;
      if (pending.readyState === 1) pending.abort();
    }
  }

  function renderCategories(findings) {
    const list = byId("category-list");
    list.replaceChildren();
    const categories = Array.from(new Set(findings.map(function (finding) { return finding.category; })));
    if (!categories.length) {
      const empty = document.createElement("li");
      empty.textContent = "No sensitive categories detected.";
      list.appendChild(empty);
    }
    categories.forEach(function (category) {
      const item = document.createElement("li");
      item.className = "category-chip";
      item.textContent = category.replace(/_/g, " ");
      list.appendChild(item);
    });
    document.querySelectorAll("[data-rule-chip]").forEach(function (chip) {
      const control = chip.getAttribute("data-rule-chip");
      const count = findings.filter(function (finding) {
        return finding.control === control || (control === "credentials" && finding.control === "secrets") ||
          (control === "usernames" && finding.control === "paths");
      }).length;
      chip.querySelector("strong").textContent = String(count);
      chip.classList.toggle("is-active", count > 0);
    });
    const dots = document.querySelector("[data-category-dots]");
    dots.replaceChildren();
    categories.forEach(function () {
      const dot = document.createElement("span");
      dots.appendChild(dot);
    });
  }

  function renderPreview() {
    preview.replaceChildren();
    preview.classList.toggle("empty", !maskedOutput);
    if (!maskedOutput) {
      preview.textContent = "Your visual redaction preview appears here.";
      return;
    }
    const pattern = /\[(?:REDACTED_[A-Z_]+|(?:EMAIL|USERNAME|PATH|IP|IPV6|MAC)_[1-9][0-9]{0,9})\]/g;
    let cursor = 0;
    let match;
    while ((match = pattern.exec(maskedOutput))) {
      preview.appendChild(document.createTextNode(maskedOutput.slice(cursor, match.index)));
      const bar = document.createElement("span");
      bar.className = "redaction-bar";
      bar.setAttribute("data-category", match[0].slice(1, -1).replace(/^REDACTED_/, "").replace(/_[0-9]+$/, "").replace(/_/g, " "));
      bar.textContent = "MASKED";
      preview.appendChild(bar);
      cursor = match.index + match[0].length;
    }
    preview.appendChild(document.createTextNode(maskedOutput.slice(cursor)));
  }

  function setView(isPreview) {
    showPreview = isPreview;
    output.hidden = isPreview;
    // Do not leave deliberately kept values in the hidden plain-text view.
    output.value = !isPreview && result ? result.sanitized : "";
    preview.hidden = !isPreview;
    sanitizedTab.classList.toggle("active", !isPreview);
    previewTab.classList.toggle("active", isPreview);
    sanitizedTab.setAttribute("aria-selected", String(!isPreview));
    previewTab.setAttribute("aria-selected", String(isPreview));
    sanitizedTab.setAttribute("tabindex", isPreview ? "-1" : "0");
    previewTab.setAttribute("tabindex", isPreview ? "0" : "-1");
    metrics();
  }

  function renderReport() {
    byId("redaction-count").textContent = String(result ? result.report.redacted : 0);
    document.querySelector("[data-status-redaction-count]").textContent = byId("redaction-count").textContent;
    byId("finding-count").textContent = String(result ? result.findings.length : 0);
    if (!result) {
      byId("privacy-report").textContent = "No current review. Human review required before sharing.";
      return;
    }
    const report = result.report;
    const counts = Object.keys(report.categoryCounts).map(function (control) {
      const count = report.categoryCounts[control];
      return control + ": " + count.detected + " detected / " + count.redacted + " redacted / " + count.kept + " kept";
    });
    byId("privacy-report").textContent = [
      "INPUT: " + report.inputLines + " physical lines · " + report.inputLength + " UTF-16 units",
      "PROFILE: " + report.profile,
      "FORMAT: " + report.format + " · " + report.parseStatus,
      "FINDINGS: " + report.totalFindings,
      "REDACTED: " + report.redacted + " · KEPT: " + report.kept,
      "",
      counts.join("\n"),
      "",
      "NETWORK EGRESS: none · PERSISTENT LOG STORAGE: none",
      "Human review required. Unknown secrets may remain.",
      "Kept values can appear in copied/downloaded output."
    ].join("\n");
  }

  function renderFindings() {
    const list = byId("findings-list");
    list.replaceChildren();
    const findings = result ? result.findings : [];
    if (!findings.length) {
      const empty = document.createElement("li");
      empty.textContent = result
        ? "No supported sensitive patterns detected. Human review required; unknown secrets may remain."
        : "Sanitize to start a review. Human review required.";
      list.appendChild(empty);
    }
    findings.slice(page * pageSize, (page + 1) * pageSize).forEach(function (finding) {
      const item = document.createElement("li");
      item.className = "finding";
      const heading = document.createElement("h3");
      heading.textContent = finding.severity.toUpperCase() + " · " + finding.category.replace(/_/g, " ") +
        " · Line " + finding.position.line + ", Col " + finding.position.column;
      const reason = document.createElement("p");
      reason.textContent = finding.description + " — " + finding.reason;
      const detail = document.createElement("p");
      detail.className = "finding-detail";
      detail.textContent = "Rule: " + finding.ruleId + " · Action: " + finding.action +
        " · " + finding.policyReason + " · Replacement: " + finding.replacement;
      item.appendChild(heading);
      item.appendChild(reason);
      item.appendChild(detail);
      if (finding.allowKeep) {
        const label = document.createElement("label");
        label.textContent = "Review action ";
        const control = document.createElement("select");
        control.setAttribute("aria-label", "Action for " + finding.id + ", " + finding.category + ", line " + finding.position.line);
        ["REDACT", "KEEP"].forEach(function (action) {
          const option = document.createElement("option");
          option.value = action;
          option.textContent = action === "KEEP" ? "KEEP in final output (preview stays masked)" : "REDACT in final output";
          control.appendChild(option);
        });
        control.value = finding.action;
        control.addEventListener("change", function () {
          if (!currentReview()) return;
          const next = Object.assign({}, overrides);
          next[finding.id] = control.value;
          try {
            result = review.apply(next);
            overrides = next;
            generation += 1;
            revokeDownloads();
            const decided = result.findings.find(function (entry) { return entry.id === finding.id; });
            detail.textContent = "Rule: " + decided.ruleId + " · Action: " + decided.action +
              " · " + decided.policyReason + " · Replacement: " + decided.replacement;
            renderReport();
            setView(showPreview);
            resetCopy();
            status.textContent = "Review decision applied locally. KEEP can expose values in Copy/download; Preview stays masked. Human review required.";
          } catch (error) {
            failReview(error);
          }
        });
        label.appendChild(control);
        item.appendChild(label);
      } else {
        const locked = document.createElement("p");
        locked.textContent = "REDACT · locked high-risk finding; KEEP is unavailable.";
        item.appendChild(locked);
      }
      list.appendChild(item);
    });
    byId("findings-previous").disabled = page === 0;
    byId("findings-next").disabled = (page + 1) * pageSize >= findings.length;
    byId("findings-page").textContent = findings.length
      ? "Showing " + (page * pageSize + 1) + "–" + Math.min((page + 1) * pageSize, findings.length) + " of " + findings.length
      : "No findings to page.";
  }

  function invalidate(message) {
    generation += 1;
    abortRead();
    if (review) review.clear();
    review = null;
    result = null;
    reviewedInput = null;
    reviewedOptions = null;
    maskedOutput = "";
    overrides = {};
    page = 0;
    resetCopy();
    revokeDownloads();
    copy.disabled = true;
    logDownload.disabled = true;
    reportDownload.disabled = true;
    renderPreview();
    renderCategories([]);
    renderReport();
    renderFindings();
    setView(showPreview);
    if (message) status.textContent = message;
  }

  function currentReview() {
    if (!review || !result) return false;
    if (input.value !== reviewedInput || JSON.stringify(options()) !== reviewedOptions) {
      invalidate("Input or policy changed. Sanitize again; previous decisions and exports were cleared.");
      return false;
    }
    return true;
  }

  function failReview(error) {
    invalidate("Local analysis could not finish (" + (error.code || "ANALYSIS_ERROR") +
      "). Reduce input or check settings. No output is available; human review required.");
  }

  function runSanitize() {
    invalidate();
    status.textContent = "Analyzing locally…";
    try {
      const settings = options();
      review = session.createReview(input.value, settings);
      result = review.apply();
      const mask = {};
      review.findings.forEach(function (finding) { mask[finding.id] = "REDACT"; });
      maskedOutput = review.apply(mask).sanitized;
      reviewedInput = input.value;
      reviewedOptions = JSON.stringify(settings);
      renderPreview();
      renderCategories(result.findings);
      renderReport();
      renderFindings();
      setView(showPreview);
      copy.disabled = !result.sanitized.length;
      logDownload.disabled = !result.sanitized.length;
      reportDownload.disabled = false;
      status.textContent = result.findings.length
        ? "Analyzed locally — " + result.report.redacted + " redacted, " + result.report.kept +
          " kept. Review findings and final output before Copy/download. Human review required."
        : "No sensitive patterns detected by supported rules. Human review required; unknown secrets may remain.";
    } catch (error) {
      failReview(error);
    }
  }

  async function copyOutput() {
    if (!currentReview() || !result.sanitized) return;
    const token = generation;
    try {
      await navigator.clipboard.writeText(result.sanitized);
      if (token !== generation || !currentReview()) return;
      copy.textContent = "Copied";
      status.textContent = "Copied final reviewed text, including KEEP decisions. Review where you paste it next.";
      copyTimer = setTimeout(resetCopy, 1800);
    } catch (error) {
      if (token !== generation || !currentReview()) return;
      resetCopy();
      setView(false);
      output.focus();
      output.select();
      status.textContent = "Clipboard permission unavailable. Final reviewed text is selected for manual copy, including KEEP decisions.";
    }
  }

  function downloadReport(isReport) {
    if (!currentReview() || (!isReport && !result.sanitized)) return;
    let url = null;
    try {
      const value = isReport ? JSON.stringify(result.report, null, 2) + "\n" : result.sanitized;
      const blob = new Blob([value], { type: isReport ? "application/json;charset=utf-8" : "text/plain;charset=utf-8" });
      url = URL.createObjectURL(blob);
      objectUrls.add(url);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = isReport ? "privacy-report.json" : "sanitized.log";
      document.body.appendChild(anchor);
      try { anchor.click(); } finally { anchor.remove(); }
      setTimeout(function () {
        if (objectUrls.delete(url)) URL.revokeObjectURL(url);
      }, 1000);
      status.textContent = isReport
        ? "Metadata-only privacy report download requested locally."
        : "Final reviewed log download requested locally, including KEEP decisions. Human review required.";
    } catch (error) {
      if (url && objectUrls.delete(url)) URL.revokeObjectURL(url);
      status.textContent = "Download unavailable in this browser. Use Copy for reviewed text.";
    }
  }

  function confirmReplacement() {
    return !input.value || window.confirm("Replace the current input and discard review decisions? Nothing will be saved automatically.");
  }

  function supportedFile(file) {
    return file && ((file.type || "").startsWith("text/") ||
      file.type === "application/json" ||
      /\.(?:txt|log|json|csv|md|yaml|yml|xml|html|js|ts|py|java|go|rs|sh|env|conf|ini)$/i.test(file.name || ""));
  }

  function loadFile(file) {
    if (!file) return;
    if (!supportedFile(file)) {
      invalidate("Only local text-like files are supported. Paste other content manually.");
      return;
    }
    if (file.size > capabilities.maxInputLength) {
      invalidate("File exceeds the 2 MiB local file guardrail. No file was read.");
      return;
    }
    if (typeof FileReader !== "function") {
      invalidate("This browser cannot read local files here. Paste the log text instead.");
      return;
    }
    if (!confirmReplacement()) return;
    invalidate("Reading local text file…");
    const token = generation;
    const pending = new FileReader();
    reader = pending;
    pending.onload = function () {
      if (token !== generation) return;
      reader = null;
      const value = String(pending.result || "");
      if (value.length > capabilities.maxInputLength) {
        invalidate("Text exceeds the 2,097,152 UTF-16 unit guardrail. Input was not replaced.");
        return;
      }
      input.value = value;
      invalidate("Loaded local text file. Sanitize to review; human review required.");
      setView(false);
      input.focus();
    };
    pending.onerror = function () {
      if (token !== generation) return;
      reader = null;
      invalidate("Could not read that local file. Paste the log text instead.");
    };
    pending.readAsText(file);
  }

  byId("sanitize-button").addEventListener("click", runSanitize);
  copy.addEventListener("click", copyOutput);
  logDownload.addEventListener("click", function () { downloadReport(false); });
  reportDownload.addEventListener("click", function () { downloadReport(true); });
  byId("clear-button").addEventListener("click", function () {
    if (input.value && !window.confirm("Clear input and all review decisions? This cannot be undone.")) return;
    input.value = "";
    session.clear();
    byId("file-input").value = "";
    invalidate("Cleared. Paste logs to begin.");
    setView(false);
    input.focus();
  });
  input.addEventListener("input", function () {
    invalidate("Input changed. Sanitize again; previous decisions and exports were cleared.");
  });
  input.addEventListener("click", cursorStatus);
  input.addEventListener("keyup", cursorStatus);
  input.addEventListener("scroll", function () { byId("input-gutter").scrollTop = input.scrollTop; });
  output.addEventListener("scroll", function () { byId("output-gutter").scrollTop = output.scrollTop; });
  preview.addEventListener("scroll", function () { byId("output-gutter").scrollTop = preview.scrollTop; });
  [profile, format, mode, legacyIp].concat(policyInputs).forEach(function (control) {
    control.addEventListener("change", function () {
      invalidate("Policy or format changed. Sanitize again; previous decisions and exports were cleared.");
      inspectPolicy();
    });
  });
  sanitizedTab.addEventListener("click", function () { if (result) currentReview(); setView(false); });
  previewTab.addEventListener("click", function () { if (result) currentReview(); setView(true); });
  [sanitizedTab, previewTab].forEach(function (tab) {
    tab.addEventListener("keydown", function (event) {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      if (result) currentReview();
      const isPreview = event.key === "End" || (event.key !== "Home" && !showPreview);
      setView(isPreview);
      (isPreview ? previewTab : sanitizedTab).focus();
    });
  });
  byId("findings-previous").addEventListener("click", function () {
    if (!currentReview() || !page) return;
    page -= 1;
    renderFindings();
    byId("findings-next").focus();
  });
  byId("findings-next").addEventListener("click", function () {
    if (!currentReview() || (page + 1) * pageSize >= result.findings.length) return;
    page += 1;
    renderFindings();
    byId("findings-previous").focus();
  });
  byId("file-input").addEventListener("change", function (event) {
    const file = event.target.files && event.target.files[0];
    byId("file-input").value = "";
    loadFile(file);
  });
  byId("sample-button").addEventListener("click", function () {
    const sample = samples[byId("sample-select").value];
    if (!sample || !confirmReplacement()) return;
    input.value = sample;
    format.value = "auto";
    invalidate("Loaded SAMPLE / SYNTHETIC DATA only. Sanitize to review.");
    inspectPolicy();
    setView(false);
    input.focus();
  });
  ["dragenter", "dragover"].forEach(function (type) {
    dropZone.addEventListener(type, function (event) {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
  });
  ["dragleave", "dragend"].forEach(function (type) {
    dropZone.addEventListener(type, function () { dropZone.classList.remove("is-dragging"); });
  });
  dropZone.addEventListener("drop", function (event) {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
    loadFile(event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0]);
  });
  document.addEventListener("keydown", function (event) {
    const modKey = event.ctrlKey || event.metaKey;
    const key = String(event.key || "").toLowerCase();
    if (modKey && key === "enter") { event.preventDefault(); runSanitize(); }
    if (modKey && event.shiftKey && key === "c" && !copy.disabled) { event.preventDefault(); copyOutput(); }
  });
  window.addEventListener("pagehide", function () {
    invalidate("Review ended. Sanitize again after returning; human review required.");
    session.clear();
  });

  inspectPolicy();
  invalidate();
})();
