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

## Structured parsing (phase 3)

`options.format` is `auto` (default), `text`, `json`, `env`, `headers`, or
`logfmt`. Auto recognizes JSON containers/quoted scalars, complete assignment
lines, header lines, then mixed key=value logs. Explicit `env` handles unquoted
values with spaces. Ambiguous mixed prose defaults to narrow token scanning,
not semantic inference. Explicit `text` uses only the original text detectors.
YAML, NDJSON, and general embedded JSON extraction are not implemented.

JSON parsing validates grammar and bounds nesting before detection. Escaped
keys are recognized; decoded value characters map to original source spans
(including Unicode escapes, escaped quotes, backslashes and surrogate units).
All string keys/values and scalar values are scanned, without reserialization.
Duplicate keys and original spacing/order remain. Numeric/boolean credential
replacements are quoted so valid JSON stays valid; consumers must tolerate
that type change. Null/empty values are not treated as credentials. Redacting
object keys can collapse distinct keys; this is best-effort sharing output,
not an unchanged application data structure.

Supported field aliases remain narrow: password/passwd; api_key/access_token/
secret_key/client_secret (optional underscores/hyphens); secret; username/
user_name/user; authorization. Explicit credentials consume the full parsed
scalar, including spaces/escaping, rather than leaking a partial value.
Username syntax remains the existing 3–64-character account-identifier syntax;
emails in user fields remain email findings. Arrays/objects directly under a
secret-named key are not wholly redacted as a unit. Unknown names/secret formats
and general natural-language identities remain limitations.

Version/release/app_version/software_version and request_id/trace_id/build_id
fields preserve only IPv4-shaped diagnostic values; they do not exempt emails
or tokens. Arbitrary free-text IDs receive no blanket exemption. `PWD` remains
a path context, not a password alias. HTTP headers and quoted logfmt/env values
are scanned as scalar units; comments/layout/line separators remain intact.
Single-quoted env values are literal; common double-quoted/logfmt escapes are
decoded, with unknown escapes retained literally for Windows paths. This is a
bounded lexical parser, not a shell evaluator (no expansion or multiline env).

`report.format` and `report.parseStatus` show parser selection. Malformed JSON
falls back to text/assignment detection with `malformed-json-fallback`; escaped
bypasses in malformed JSON may be missed. Unterminated quoted fields fall back
to raw text rules. Limits count parsed scalar units, including JSON keys.

Errors have stable `code` values and no input excerpts: `INPUT_LIMIT`,
`FINDING_LIMIT`, `FIELD_LIMIT`, `DEPTH_LIMIT`, `UNKNOWN_FORMAT`,
`REVIEW_CLEARED`. No partial output is returned on a limit/option error.
Inspect metadata before a human explicitly chooses to share output; deterministic
rules do not guarantee detection of unknown secrets.
