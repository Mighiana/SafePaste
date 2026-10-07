# SafePaste

SafePaste is a privacy-aware browser-based log sanitizer for developers, IT support staff, students, and technical users who need to remove sensitive information before sharing technical text.

## Project Status

This repository was built as an academic Human-Centered AI software engineering project. The implementation is intentionally small, local-only, dependency-free, and auditable.

## Later engineering extension (October 2026)

Phases 2–4 add a shared, dependency-free engine under the existing UMD entry
point: original-source findings with accurate spans, deterministic overlap
resolution, bounded JSON/env/header/logfmt parsing, inspectable privacy profiles,
metadata-only reports, and safe per-finding review overrides. Valid JSON escaping
and layout are preserved where possible; full parsed credential values are
redacted. These capabilities were **not part of the academic base version**.

Phase 5 adds a browser findings review workspace using that same core. The
visibly selected Compatibility policy retains the original IPv4 checkbox
behavior; explicit profiles and custom categories are available beside it.
Phase 6 adds optional in-memory session-local pseudonymization of context identifiers;
secrets stay fully redacted. Clear/reload resets mappings; mode edits disable stale
exports. Phase 7 adds bounded high-confidence detectors: GitHub/Google tokens,
Azure/AWS cloud keys, credential URLs, JDBC/ODBC passwords, whole private-key blocks,
session/cookie/header credentials, decodable Basic credentials, Slack/Discord/Teams
webhook secrets, URL secret parameters, validated IPv6 and MAC addresses
([exact rules and limitations](docs/ENGINE_API.md#phase-7-high-confidence-detectors)).
This is **not yet a CLI or worker**, and unknown secret formats can still be missed.
Omitting a profile in the engine preserves legacy loopback behavior. Explicit strict
redacts all supported IPv4; support keeps RFC1918/loopback; incident keeps network
evidence; custom exposes category/network controls. Credentials/tokens/secrets
cannot be kept. Human review is still required.

See [engine API and limits](docs/ENGINE_API.md) and
[independent baseline/provenance contract](docs/EXTENSION_BASELINE.md), plus
[phase 5 UI behavior, checks and limitations](docs/REVIEW_UI_STAGE_RESULT.md).
Do not export the legacy `sanitize()` result as a report: it contains original
input. New `analyze()`/review reports expose metadata only.

## Motivation

Technical logs often contain useful debugging context mixed with emails, IP addresses, file paths, passwords, API keys, and access tokens. SafePaste helps users review and redact likely sensitive values before sending logs to AI tools, issue trackers, support systems, chat, email, or forums.

## Stakeholders

See [docs/STAKEHOLDER_MAP.md](docs/STAKEHOLDER_MAP.md) for the stakeholder map and explicit conflicts.

## Privacy Architecture

SafePaste runs entirely in the browser with no backend, no database, no analytics, no third-party scripts, no remote fonts, and no automatic persistence of pasted logs. Pasted content stays in page memory. Copy and sanitized-log/report downloads occur only on explicit user action; no original-log export exists.

Production files do not use `fetch`, `XMLHttpRequest`, `WebSocket`, browser storage APIs, cookies, IndexedDB, external resources, or `innerHTML`.

Later extension (phase 8): `index.html` carries a restrictive meta Content
Security Policy (`connect-src 'none'`, `object-src 'none'`, `base-uri 'none'`,
`form-action 'none'`, no `unsafe-inline`), and `node evals/run-static-privacy-checks.js`
turns the statements above into an automated check. Meta CSP cannot enforce
`frame-ancestors`; see [zero-egress controls and header-only limits](docs/ZERO_EGRESS.md).

## Features

- Redacts common credentials, explicit structured secret fields, tokens, emails, structured usernames, home-path usernames, and redaction-eligible IPv4 addresses.
- Preserves useful context such as request IDs, build IDs, Unicode text, system paths, invalid IPv4-like values, and narrow software version contexts. Loopback preservation is policy-dependent.
- Shows an editor-style privacy review workspace with original and sanitized panes, line-number gutters, category chips, and a review summary.
- Provides `sanitized.log` and `preview.log` output views. Final output uses stable markers such as `[REDACTED_EMAIL]` for REDACT decisions. Preview masks **all detected values**, even those explicitly kept in final output. Unknown sensitive values may remain in either view.
- Shows findings with rule/reason, severity, line/column and action, without original values. Eligible findings permit local KEEP/REDACT review; high-risk credentials/tokens/secrets are locked to REDACT.
- Provides inspectable Compatibility, Strict privacy, Support, Security incident and Custom policies and an explicit format selector.
- Clears previous output, findings, report and overrides after input, format or policy edits; reanalysis is explicit.
- Shows redaction count and detected categories.
- Provides Clear and Copy controls and explicit `sanitized.log` / `privacy-report.json` downloads. Report exports contain metadata only, not original values. Copy/log downloads can include values kept by policy or by the reviewer.
- Provides a scoped IPv4 toggle for privacy-versus-diagnostic-usefulness control.
- Supports local-only drag-and-drop and a native file picker for text-like files using browser `FileReader`; unsupported/oversized files fail with inline status feedback. Samples are clearly labeled synthetic.
- Supports keyboard shortcuts: Ctrl/Cmd+Enter to sanitize and Ctrl/Cmd+Shift+C to copy sanitized text.

## UI Architecture

The final UI adopts a muted slate developer/security-tool shell inspired by the approved Claude-generated reference design: compact topbar, amber primary action, Local Only and No Network Egress messaging, detection-category chips, editor tabs, line gutters, status bar, and visual redaction preview. The color system intentionally avoids both a full black background and stark white cards.

The Claude sanitizer implementation was not copied. The UI consumes the existing tested `src/sanitizer.js` review API. Copy/downloads use the current final reviewed plain-text result, never preview markup. Entering Preview empties the hidden output textarea so intentionally kept values are not replicated in a hidden plain-text view. Findings and privacy reports render metadata only through safe DOM APIs.

The findings panel shows 50 findings per page. File loading has a conservative
2 MiB byte guardrail; analysis accepts at most 2,097,152 UTF-16 units, as declared
by the engine. Analysis is still synchronous. These are limits, **not measured
browser responsiveness claims**. Human review remains required even when no
supported sensitive patterns are detected.

## IPv4 User Control

By default, SafePaste redacts valid non-loopback IPv4 addresses and preserves `127.0.0.0/8` loopback addresses. The `Redact non-loopback IPv4 addresses` checkbox lets the user turn off network IPv4 redaction when exact network context is needed for troubleshooting.

This toggle appears only for Compatibility. Changing it clears the previous
review; press Sanitize again. The original scoped behavior is preserved: network
IPs can remain visible while email and credential redaction still works.
Strict redacts supported loopback/private IPv4 too; Support preserves RFC1918
and loopback, and Security incident preserves IPv4 evidence. Those preserving
policies are not automatically suitable for public sharing.

## How To Run

Open `index.html` directly in a browser:

```text
SafePaste/index.html
```

Optional local preview for verification:

```text
node evals/static-server.js
```

Then open:

```text
http://127.0.0.1:8765/
```

## How To Test

Run from the `SafePaste/` directory:

```text
node tests/test-sanitizer.js
node tests/test-core.js
node tests/test-parsers.js
node tests/test-policies.js
node tests/test-hook.js
node tests/test-review-ui.js
node tests/test-static-privacy.js
node evals/run-evals.js
node evals/graders/exact-property-grader.js
node evals/run-red-team.js
node evals/run-ui-smoke.js
node evals/run-product-behavior.js
node evals/run-accessibility-checks.js
node evals/run-static-privacy-checks.js
```

To write final eval results:

```text
node evals/run-evals.js --write evals/results_final.md
```

## Repository Structure

```text
SafePaste/
  index.html
  styles.css
  app.js
  src/sanitizer.js
  tests/test-sanitizer.js
  evals/
  docs/
  history/v1/
  .claude/
```

## Harness

The AI engineering harness is documented in [docs/HARNESS_REVIEW.md](docs/HARNESS_REVIEW.md).

- `AGENTS.md` records persistent AI development instructions.
- `.claude/agents/security-reviewer.md` defines a security-review role.
- `.claude/hooks/pre-commit.sh` runs a lightweight staged secret scan.
- `.claude/settings.json` documents approval boundaries and discouraged actions.
- `evals/` contains unit-linked evals, red-team checks, product behavior checks, accessibility checks, and graders.

## Methodology

The project follows a specification-first engineering loop:

1. document stakeholders and conflicts
2. write a preserved v1 specification
3. create an AI engineering harness
4. implement the smallest complete local product
5. run unit tests, evaluations, red-team checks, and static security checks
6. preserve real failures
7. iterate the implementation and final specification

Key evidence files:

- `SPEC_v1.md`
- `SPEC_FINAL.md`
- `evals/results_v1.md`
- `evals/results_final.md`
- `evals/graders/exact-property-grader.js`
- `evals/graders/exact-property-results.md`
- `evals/graders/human-rubric.md`
- `evals/graders/grader-comparison.md`
- `RED_TEAM.md`
- `AI_WORKLOG.md`
- `CHANGELOG.md`
- `docs/ACCESSIBILITY_REVIEW.md`
- `docs/FINAL_COMPLETION_REPORT.md`
- `docs/HARNESS_REVIEW.md`
- `docs/PRODUCT_BEHAVIOR_REVIEW.md`
- `docs/PRESENTATION_EVIDENCE.md`

## Grader Methodology

SafePaste uses two grader styles:

- Automated exact/property grading for deterministic privacy/security behavior, such as "the original secret is gone" and "required harmless context remains."
- Human rubric grading for diagnostic usefulness, readability, proportionality, and shareability.

No external model-as-judge API is used because sending logs to an external model would conflict with the local-only privacy architecture.

Manual Test 2 extended the grader evidence with a real localhost disagreement. SafePaste now preserves IPv4 loopback addresses in `127.0.0.0/8`, while continuing to redact other valid IPv4 addresses when IPv4 redaction is enabled.

Manual Test 3 extended the policy for structured account identifiers and version context. SafePaste now redacts explicit username fields such as `username=`, `user_name=`, and `user=`, preserves arbitrary names in prose, and preserves IPv4-shaped values in narrow version fields such as `release=` while still redacting explicit `client_ip=` and `server_ip=` values.

Manual Test 4 extended version context to direct prose such as `Release 1.2.3.4` and standardized current username markers on `[REDACTED_USERNAME]`.

Manual Test 5 fixed a standalone IPv4 false negative before sentence punctuation. SafePaste now redacts normal non-loopback IPv4 addresses such as `Connection received from 192.168.20.50.` while preserving version contexts, loopback addresses, larger dotted numeric sequences, and hostname-embedded IPv4-shaped substrings. After this fix, the core sanitizer is frozen unless another high-severity privacy/security regression is found.

Manual Test 6 confirmed the frozen sanitizer and recorded a known borderline limitation: `Firmware 1.2.3.4 installed successfully.` is redacted as an IP address even though a human may read it as firmware-version context. SafePaste intentionally keeps contextual exceptions narrow and auditable instead of adding broad semantic/NLP classification.

Final regression F8 found that `secret=FakeSecretValue987` remained visible. SafePaste now narrowly redacts explicit structured `secret` fields such as `secret=value`, `secret: value`, and JSON `"secret":"value"` using `[REDACTED_SECRET]`. This does not add broad arbitrary-secret guessing.

## Known Limitations

- SafePaste uses deterministic local detection rules rather than cloud services or external AI classification.
- It cannot guarantee every possible secret format is detected.
- Local path detection is intentionally narrow.
- Contextual IPv4 disambiguation is best-effort, not exhaustive. Ambiguous version-like strings outside the supported `Version`/`Release` contexts may be over-redacted.
- Browser automation did not return readable page state in this environment, so real viewport rendering, OS clipboard permission, keyboard traversal, and screen-reader behavior remain manual browser checks. Local harnesses verify the Clipboard API call, static accessibility structure, and responsive CSS rules.
