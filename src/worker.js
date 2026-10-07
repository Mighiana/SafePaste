/* SafePaste local analysis worker: classic, same-origin, no network, no storage. */
"use strict";

importScripts("sanitizer.js");

(function () {
  const engine = self.SafePasteSanitizer;
  // The worker owns the pseudonym session; the page resets it by terminating the worker.
  const session = engine.createSession({ limits: "large" });
  let review = null;

  function coded(code) {
    const error = new Error("SafePaste: " + code);
    error.code = code;
    return error;
  }

  // Only fixed engine error codes cross the boundary, never messages, stacks or input.
  function safeCode(error) {
    const code = error && typeof error.code === "string" ? error.code : "";
    return /^[A-Z][A-Z0-9_]{0,40}$/.test(code) ? code : "WORKER_ERROR";
  }

  function release() {
    if (review) review.clear();
    review = null;
  }

  function maskAll(current) {
    const mask = {};
    current.findings.forEach(function (finding) { mask[finding.id] = "REDACT"; });
    return current.apply(mask).sanitized;
  }

  self.onmessage = function (event) {
    const message = event.data && typeof event.data === "object" ? event.data : {};
    const job = typeof message.job === "number" ? message.job : null;
    try {
      if (message.type === "analyze") {
        release();
        if (typeof message.input !== "string") throw coded("INVALID_INPUT");
        self.postMessage({ type: "status", job: job, phase: "analyzing" });
        review = session.createReview(message.input, message.options);
        self.postMessage({ type: "result", job: job, result: review.apply(), masked: maskAll(review) });
      } else if (message.type === "apply") {
        if (!review) throw coded("REVIEW_CLEARED");
        self.postMessage({ type: "result", job: job, result: review.apply(message.overrides) });
      } else if (message.type === "release") {
        release();
      } else {
        throw coded("UNKNOWN_MESSAGE");
      }
    } catch (error) {
      if (message.type === "analyze") release();
      self.postMessage({ type: "error", job: job, code: safeCode(error) });
    }
  };

  self.postMessage({ type: "ready", maxInputLength: session.limits.maxInputLength });
})();
