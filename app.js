(function () {
  "use strict";

  const sanitizer = window.SafePasteSanitizer;

  const inputText = document.getElementById("input-text");
  const outputText = document.getElementById("output-text");
  const sanitizeButton = document.getElementById("sanitize-button");
  const copyButton = document.getElementById("copy-button");
  const clearButton = document.getElementById("clear-button");
  const redactIp = document.getElementById("redact-ip");
  const redactionCount = document.getElementById("redaction-count");
  const categoryList = document.getElementById("category-list");
  const statusMessage = document.getElementById("status-message");
  const outputPreview = optionalSelector("[data-output-preview]");
  const scanRegion = optionalSelector("[data-drop-zone]");
  const workspaceShell = optionalSelector("[data-workspace-shell]");
  const inputGutter = optionalSelector("#input-gutter");
  const outputGutter = optionalSelector("#output-gutter");
  const inputMeta = optionalSelector("[data-original-meta]");
  const outputMeta = optionalSelector("[data-output-meta]");
  const cursorStatus = optionalSelector("[data-cursor-status]");
  const statusRedactionCount = optionalSelector("[data-status-redaction-count]");
  const statusDots = optionalSelector("[data-category-dots]");
  const sanitizedTab = optionalSelector("#sanitized-tab");
  const previewTab = optionalSelector("#preview-tab");
  const dropZone = optionalSelector("[data-drop-zone]");
  const ruleChips = optionalSelectorAll("[data-rule-chip]");
  let copyResetTimer = null;

  function optionalSelector(selector) {
    if (typeof document.querySelector !== "function") {
      return null;
    }
    return document.querySelector(selector);
  }

  function optionalSelectorAll(selector) {
    if (typeof document.querySelectorAll !== "function") {
      return [];
    }
    return Array.from(document.querySelectorAll(selector));
  }

  function renderCategories(categories) {
    categoryList.replaceChildren();

    if (categories.length === 0) {
      const emptyItem = document.createElement("li");
      emptyItem.textContent = "No sensitive categories detected.";
      categoryList.appendChild(emptyItem);
      return;
    }

    categories.forEach(function (category) {
      const item = document.createElement("li");
      item.className = "category-chip";
      item.textContent = category.replace(/_/g, " ");
      categoryList.appendChild(item);
    });
  }

  function markerCategory(marker) {
    return marker.replace(/^\[REDACTED_/, "").replace(/\]$/, "").replace(/_/g, " ");
  }

  function markerGroup(marker) {
    if (/EMAIL/.test(marker)) {
      return "email";
    }
    if (/USERNAME|USER/.test(marker)) {
      return "usernames";
    }
    if (/IP_ADDRESS/.test(marker)) {
      return "ipv4";
    }
    if (/AUTHORIZATION|BEARER|JWT/.test(marker)) {
      return "tokens";
    }
    return "credentials";
  }

  function markerSeverity(marker) {
    if (/API_KEY|PASSWORD|AUTHORIZATION|BEARER|JWT|AWS|SLACK/.test(marker)) {
      return "high";
    }
    if (/EMAIL|USERNAME|USER/.test(marker)) {
      return "medium";
    }
    return "low";
  }

  function appendTextNode(parent, value) {
    if (!value) {
      return;
    }
    if (typeof document.createTextNode === "function") {
      parent.appendChild(document.createTextNode(value));
    } else {
      const span = document.createElement("span");
      span.textContent = value;
      parent.appendChild(span);
    }
  }

  function renderVisualPreview(value) {
    if (!outputPreview) {
      return;
    }

    outputPreview.replaceChildren();

    if (!value) {
      outputPreview.classList.add("empty");
      outputPreview.textContent = "Your visual redaction preview appears here.";
      return;
    }

    outputPreview.classList.remove("empty");

    const markerPattern = /\[REDACTED_[A-Z_]+\]/g;
    let cursor = 0;
    let match = markerPattern.exec(value);

    while (match) {
      appendTextNode(outputPreview, value.slice(cursor, match.index));

      const marker = match[0];
      const bar = document.createElement("span");
      bar.className = `redaction-bar ${markerSeverity(marker)}`;
      bar.setAttribute("data-category", markerCategory(marker));
      bar.textContent = "REDACTED";
      outputPreview.appendChild(bar);

      cursor = match.index + marker.length;
      match = markerPattern.exec(value);
    }

    appendTextNode(outputPreview, value.slice(cursor));
  }

  function lineCount(value) {
    if (!value) {
      return 0;
    }
    return value.split("\n").length;
  }

  function renderGutter(element, value) {
    if (!element) {
      return;
    }
    const count = Math.max(1, lineCount(value));
    const lines = Array.from({ length: count }, function (_, index) {
      return String(index + 1);
    });
    element.textContent = lines.join("\n");
  }

  function updateEditorMetrics() {
    const inputLines = lineCount(inputText.value);
    const outputLines = lineCount(outputText.value);

    renderGutter(inputGutter, inputText.value);
    renderGutter(outputGutter, outputText.value);

    if (inputMeta) {
      inputMeta.textContent = `${inputLines} ${inputLines === 1 ? "line" : "lines"}`;
    }
    if (outputMeta) {
      outputMeta.textContent = outputText.value ? `${redactionCount.textContent} redactions` : "0 redactions";
    }
    updateCursorStatus();
  }

  function updateCursorStatus() {
    if (!cursorStatus) {
      return;
    }

    const position = typeof inputText.selectionStart === "number" ? inputText.selectionStart : 0;
    const beforeCursor = inputText.value.slice(0, position);
    const line = beforeCursor.split("\n").length;
    const column = beforeCursor.length - beforeCursor.lastIndexOf("\n");
    cursorStatus.textContent = `Ln ${line}, Col ${column}`;
  }

  function buildGroupCounts(value) {
    const counts = {
      credentials: 0,
      tokens: 0,
      email: 0,
      usernames: 0,
      ipv4: 0
    };
    const markerPattern = /\[REDACTED_[A-Z_]+\]/g;
    let match = markerPattern.exec(value || "");

    while (match) {
      counts[markerGroup(match[0])] += 1;
      match = markerPattern.exec(value || "");
    }

    return counts;
  }

  function updateVisualCategoryState(value) {
    const counts = buildGroupCounts(value);

    ruleChips.forEach(function (chip) {
      const group = chip.getAttribute("data-rule-chip");
      const count = counts[group] || 0;
      const valueNode = chip.querySelector("strong");

      chip.classList.toggle("is-active", count > 0);
      if (valueNode) {
        valueNode.textContent = String(count);
      }
    });

    if (statusDots) {
      statusDots.replaceChildren();
      Object.keys(counts).forEach(function (group) {
        if (counts[group] === 0) {
          return;
        }
        const dot = document.createElement("span");
        dot.className = group;
        statusDots.appendChild(dot);
      });
    }
  }

  function pulseScan() {
    [scanRegion, workspaceShell].forEach(function (element) {
      if (element && element.classList) {
        element.classList.add("is-scanning");
      }
    });

    if (typeof setTimeout === "function") {
      setTimeout(function () {
        [scanRegion, workspaceShell].forEach(function (element) {
          if (element && element.classList) {
            element.classList.remove("is-scanning");
          }
        });
      }, 420);
    }
  }

  function resetCopyFeedback() {
    if (copyResetTimer && typeof clearTimeout === "function") {
      clearTimeout(copyResetTimer);
    }
    copyResetTimer = null;
    copyButton.textContent = "Copy sanitized text";
  }

  function setOutputView(showPreview) {
    if (!outputPreview || !sanitizedTab || !previewTab) {
      return;
    }

    outputText.hidden = showPreview;
    outputPreview.hidden = !showPreview;
    sanitizedTab.classList.toggle("active", !showPreview);
    previewTab.classList.toggle("active", showPreview);
    sanitizedTab.setAttribute("aria-selected", showPreview ? "false" : "true");
    previewTab.setAttribute("aria-selected", showPreview ? "true" : "false");
  }

  function runSanitize() {
    resetCopyFeedback();
    pulseScan();

    const result = sanitizer.sanitize(inputText.value, {
      redactIpAddresses: redactIp.checked
    });

    outputText.value = result.sanitized;
    renderVisualPreview(result.sanitized);
    redactionCount.textContent = String(result.redactionCount);
    if (statusRedactionCount) {
      statusRedactionCount.textContent = String(result.redactionCount);
    }
    renderCategories(result.categories);
    updateVisualCategoryState(result.sanitized);
    updateEditorMetrics();
    copyButton.disabled = result.sanitized.length === 0;

    if (result.redactionCount === 0) {
      statusMessage.textContent = "No sensitive patterns detected. Review the text before sharing.";
    } else {
      const plural = result.redactionCount === 1 ? "value" : "values";
      statusMessage.textContent = `Sanitized locally - ${result.redactionCount} sensitive ${plural} found. Review before copying.`;
    }
  }

  function clearAll() {
    resetCopyFeedback();
    inputText.value = "";
    outputText.value = "";
    renderVisualPreview("");
    redactionCount.textContent = "0";
    if (statusRedactionCount) {
      statusRedactionCount.textContent = "0";
    }
    renderCategories([]);
    updateVisualCategoryState("");
    updateEditorMetrics();
    setOutputView(false);
    copyButton.disabled = true;
    statusMessage.textContent = "Cleared. Paste logs to begin.";
    inputText.focus();
  }

  async function copySanitizedText() {
    if (!outputText.value) {
      return;
    }

    try {
      await navigator.clipboard.writeText(outputText.value);
      copyButton.textContent = "Copied";
      statusMessage.textContent = "Copied sanitized text. Review where you paste it next.";
      if (typeof setTimeout === "function") {
        copyResetTimer = setTimeout(function () {
          copyButton.textContent = "Copy sanitized text";
          copyResetTimer = null;
        }, 1800);
      }
    } catch (error) {
      resetCopyFeedback();
      outputText.focus();
      outputText.select();
      statusMessage.textContent = "Clipboard permission unavailable. Sanitized text is selected for manual copy.";
    }
  }

  function syncGutterScroll(textarea, gutter) {
    if (!gutter) {
      return;
    }
    gutter.scrollTop = textarea.scrollTop;
  }

  function isSupportedTextFile(file) {
    if (!file) {
      return false;
    }
    if (file.type && file.type.startsWith("text/")) {
      return true;
    }
    return /\.(?:txt|log|json|csv|md|yaml|yml|xml|html|js|ts|py|java|go|rs|sh|env|conf|ini)$/i.test(file.name || "");
  }

  function setDragging(isDragging) {
    if (dropZone && dropZone.classList) {
      dropZone.classList.toggle("is-dragging", isDragging);
    }
  }

  function handleDroppedFile(event) {
    event.preventDefault();
    setDragging(false);

    if (typeof FileReader !== "function") {
      statusMessage.textContent = "This browser cannot read local files here. Paste the log text instead.";
      return;
    }

    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (!isSupportedTextFile(file)) {
      statusMessage.textContent = "Only local text-like files are supported. Paste other content manually.";
      return;
    }

    const reader = new FileReader();
    reader.onload = function () {
      inputText.value = String(reader.result || "");
      outputText.value = "";
      renderVisualPreview("");
      redactionCount.textContent = "0";
      if (statusRedactionCount) {
        statusRedactionCount.textContent = "0";
      }
      renderCategories([]);
      updateVisualCategoryState("");
      updateEditorMetrics();
      setOutputView(false);
      copyButton.disabled = true;
      statusMessage.textContent = `Loaded ${file.name} locally. Sanitize to review.`;
      inputText.focus();
    };
    reader.onerror = function () {
      statusMessage.textContent = "Could not read that local file. Paste the log text instead.";
    };
    reader.readAsText(file);
  }

  sanitizeButton.addEventListener("click", runSanitize);
  clearButton.addEventListener("click", clearAll);
  copyButton.addEventListener("click", copySanitizedText);
  redactIp.addEventListener("change", function () {
    if (inputText.value || outputText.value) {
      runSanitize();
    }
  });

  inputText.addEventListener("input", updateEditorMetrics);
  inputText.addEventListener("click", updateCursorStatus);
  inputText.addEventListener("keyup", updateCursorStatus);
  inputText.addEventListener("scroll", function () {
    syncGutterScroll(inputText, inputGutter);
  });
  outputText.addEventListener("scroll", function () {
    syncGutterScroll(outputText, outputGutter);
  });

  if (sanitizedTab) {
    sanitizedTab.addEventListener("click", function () {
      setOutputView(false);
    });
  }
  if (previewTab) {
    previewTab.addEventListener("click", function () {
      setOutputView(true);
    });
  }

  if (dropZone) {
    ["dragenter", "dragover"].forEach(function (type) {
      dropZone.addEventListener(type, function (event) {
        event.preventDefault();
        setDragging(true);
      });
    });
    ["dragleave", "dragend"].forEach(function (type) {
      dropZone.addEventListener(type, function () {
        setDragging(false);
      });
    });
    dropZone.addEventListener("drop", handleDroppedFile);
  }

  if (typeof document.addEventListener === "function") {
    document.addEventListener("keydown", function (event) {
      const modKey = event.ctrlKey || event.metaKey;
      const key = String(event.key || "").toLowerCase();

      if (modKey && key === "enter") {
        event.preventDefault();
        runSanitize();
      }

      if (modKey && event.shiftKey && key === "c" && !copyButton.disabled) {
        event.preventDefault();
        copySanitizedText();
      }
    });
  }

  renderVisualPreview("");
  updateVisualCategoryState("");
  updateEditorMetrics();
})();
