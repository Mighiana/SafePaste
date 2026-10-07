# Phase 5: browser findings review (later extension)

This is October 2026 engineering work built on the phases 2–4 engine handoff,
not part of the academic base. Engine source/API, SPEC_v1.md, history/v1 and
recorded historical evidence are unchanged. No dependencies were installed.

## Consumer contract and intentional behavior changes

- The existing UMD engine remains public: browser SafePasteSanitizer / Node
  require('./src/sanitizer'). No production detection/policy changes.
- UI uses createReview(input, options), apply(completeOverrideMap), clear(),
  inspectPolicy(options) and getCapabilities(). It does not consume sensitive
  legacy original/matches fields. All decisions are in memory only.
- Compatibility is visibly selected initially, preserving the original
  non-loopback IPv4 toggle semantics. Explicit Strict/Support/Incident/Custom
  profiles and format selector are available. Full resolved policy is
  inspectable, including diagnostic exceptions and locked controls.
  Compatibility omits preserved IPv4 from findings, so those undetected
  addresses are not masked in Preview. A visible warning explains this; use
  an explicit profile to review all supported IPv4 candidates.
- Findings show category, severity, line/column, rule, reason, replacement and
  action without original values. Eligible findings permit native KEEP/REDACT
  selects. Credentials/tokens/secrets have no KEEP control. Fifty findings per
  page bounds the panel's DOM, not total analysis work.
- Final output = review.apply(overrides).sanitized. Preview = a separate apply
  with **every detected finding REDACT**, including policy/manual KEEP. No
  replacement rescan. Entering Preview empties the hidden plain-output textarea.
  Switching back restores final output from in-memory review state.
- Copy/log download use final reviewed text, including KEEP. Report download
  serializes result.report only, never input/legacy matches. No original-log
  export exists. Fixed filenames avoid reflecting input filenames into exports.
- Input edits, category/profile/network/format changes clear output, findings,
  report, overrides and Copy/export availability. Press Sanitize again; the
  original IPv4 change auto-sanitization was intentionally removed to prevent
  stale review decisions or implicit analysis after policy edits.
- Clipboard and FileReader completion are generation-checked. Edits/Clear/
  policy changes cancel pending file reads; newer files cannot be overwritten
  by older completions. Manual-copy fallback restores the final plain-text view.
- Clear/replacement use native confirmation. Cancel leaves the current review
  intact. Load sample/file does not analyze/copy/export automatically.
- File picker and drop use the same local loader with a conservative 2 MiB byte
  bound; decoded text and the core use the 2,097,152 UTF-16 bound. Type/size/read/
  analysis errors leave no partial output available. These are resource
  guardrails, **not tested browser-size support/performance claims**.
- Samples are labeled SAMPLE / SYNTHETIC DATA; production rules do not consult
  those fixtures. JSON/header/env/logfmt examples contain fake data only.
- Downloads are user-driven blob URLs, revoked on timeout/state invalidation/
  page exit. There is no automatic storage, network, backend or analytics.
- Safe DOM APIs only. Keyboard tab arrows/Home/End, native controls, polite
  status, text severity/action, responsive stacking and reduced-motion retained.
  Physical editor lines do not wrap; both output views scroll within the editor.
  Solid muted-text/surface color token pairs are checked at 4.5:1, without
  claiming a complete rendered-browser contrast audit.
  No-detection text explicitly says human review is required.

## Checks (Node/static/mock, not real-browser evidence)

Before edits, all inherited seven commands independently exited 0:

| Command | Inherited result |
| --- | --- |
| node tests/test-sanitizer.js | 38/38 |
| node evals/run-evals.js | 73/73 (includes privacy/security static checks) |
| node evals/graders/exact-property-grader.js | 91/91 properties, 21 cases |
| node evals/run-red-team.js | 15/15 |
| node evals/run-ui-smoke.js | PASS |
| node evals/run-product-behavior.js | 5/5 |
| node evals/run-accessibility-checks.js | 10/10 |

Final independent rerun: **every command exited 0**.

| Command | Final result |
| --- | --- |
| node tests/test-sanitizer.js | 38/38 |
| node evals/run-evals.js | 73/73 |
| node evals/graders/exact-property-grader.js | 91/91 properties, 21 cases |
| node evals/run-red-team.js | 15/15 |
| node evals/run-ui-smoke.js | PASS (mocked DOM/clipboard) |
| node evals/run-product-behavior.js | 5/5 (mocked DOM) |
| node evals/run-accessibility-checks.js | 18/18 static checks (original ten + eight) |
| node tests/test-core.js | 9/9 |
| node tests/test-parsers.js | 16/16 |
| node tests/test-policies.js | 22/22 |
| node tests/test-hook.js | PASS staged snapshot/exclusions/unusual paths/fail-closed checks |
| node tests/test-review-ui.js | 22/22 (mocked UI, real core) |

Additional checks: node --check on app.js, tests/ui-harness.js,
tests/test-review-ui.js and all three edited eval runners; sh -n on the unchanged
hook; git diff --check. All pass. No configured linter/type-check command exists
in this plain-JS repository; no dependencies were installed to add one.

Required pre-commit hook runs as **sh .claude/hooks/pre-commit.sh** before every
commit: the inherited script is not executable (mode 100644). Direct execution
initially returned permission denied; invoking the exact script through sh runs
its full staged scan without bypassing it.

Historical generated results are not rewritten. Existing mocked smoke/product assertions all remain.
The scoped IPv4 test additionally asserts invalidation, then explicitly analyzes
before asserting the same preserved/redacted values. The original ten static
accessibility checks remain; label matching accepts the new label ID.

## Limits / parent handoff

- No browser/server/recording setup or UI-driven testing in this stage. Parent
  testing agent must verify all screens/widths, keyboard/screenreader behavior,
  contrast, direct-file clipboard fallback, file read/drop and real downloads.
- No pseudonyms/worker/CLI/new detector categories/CSP added. Analysis is
  synchronous; large browser responsiveness and comprehensive performance are
  unmeasured. Phase 6+ owns later features.
- Preview masks detected spans only, not every possible sensitive value.
  KEEP, Support and Incident can deliberately expose original context in final
  plain output. No-detection is not a guarantee of safety.
- Clear releases retained source references; secure JavaScript memory erasure
  is not promised. Already copied/downloaded output cannot be revoked.
- No PR/merge/deployment. Branch-only handoff; main and academic history intact.
