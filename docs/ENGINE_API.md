# Shared core engine (later extension)

UMD entry point remains `src/sanitizer.js`: `SafePasteSanitizer` in the browser,
`require('./src/sanitizer')` in Node. No package install or additional browser
scripts are required. UI integration is a later stage.

## Detection/review API

- `inspectDetectors()` returns an immutable catalog with IDs, category/control,
  severity, description, reason, replacement, context requirements and KEEP
  eligibility. `certainty` means deterministic rule match, not ML probability.
- `getCapabilities()` returns immutable hard bounds: 2,097,152 UTF-16 code units,
  100,000 candidate findings, 64 JSON container levels, 50,000 parsed fields.
  These are guardrails, not performance/support claims for multi-megabyte files.
- `analyze(input, options)` returns `{findings, report}` without original values.
- `createReview(input, options)` retains input only in a closure and exposes
  immutable `{findings, report, apply(), clear()}`. `apply()` returns
  `{sanitized, findings, report}`. It never scans generated replacements.
  `clear()` releases the retained source reference and disables apply. This is
  not a guarantee of secure memory erasure by the JavaScript runtime.
- `sanitize(input, {redactIpAddresses})` remains the compatibility adapter with
  `{original, sanitized, matches, categories, redactionCount}`. **Do not export
  this result as a privacy report**: `original` and `matches[].text` contain raw
  input. New reports/findings do not. Match offsets now refer to original input.

Findings have deterministic positional IDs (`finding-1`, etc.), rule IDs,
category/control/severity/reason/description, marker replacement, action, KEEP
eligibility and an exclusive `[start,end)` source span. Offsets and 1-based
line/column positions count UTF-16 code units (not graphemes); LF, CRLF and CR
are line breaks. IDs are local to one review, not global identifiers.

All detections operate on the original source. Connected overlapping intervals
are coalesced, using the strongest explicit credential rule (then deterministic
source order for ties), so partial overlaps cannot reveal a candidate suffix.
Replacement is a single forward pass. Home-path spans cover only the username.
The free-text version lookbehind is bounded to 160 code units; unusually distant
prose context may be redacted conservatively. Email components are bounded to
avoid unbounded repeated scans of hostile dotted input.

Errors have stable `code` values and no input excerpts: `INPUT_LIMIT`,
`FINDING_LIMIT`, `REVIEW_CLEARED`. No partial output is returned on an error.
Inspect metadata before a human explicitly chooses to share output; deterministic
rules do not guarantee detection of unknown secrets.
