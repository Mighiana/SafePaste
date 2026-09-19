# SafePaste

SafePaste is a privacy-aware browser-based log sanitizer for developers, IT support staff, students, and technical users who need to remove sensitive information before sharing technical text.

## Project Status

This repository was built as an academic Human-Centered AI software engineering project. The implementation is intentionally small, local-only, dependency-free, and auditable.

## Motivation

Technical logs often contain useful debugging context mixed with emails, IP addresses, file paths, passwords, API keys, and access tokens. SafePaste helps users review and redact likely sensitive values before sending logs to AI tools, issue trackers, support systems, chat, email, or forums.

## Stakeholders

See [docs/STAKEHOLDER_MAP.md](docs/STAKEHOLDER_MAP.md) for the stakeholder map and explicit conflicts.

## Privacy Architecture

SafePaste runs entirely in the browser with no backend, no database, no analytics, no third-party scripts, no remote fonts, and no storage of pasted logs. Pasted content remains in page memory only while the page is open.

Production files do not use `fetch`, `XMLHttpRequest`, `WebSocket`, browser storage APIs, cookies, IndexedDB, external resources, or `innerHTML`.

## Features

- Redacts common credentials, explicit structured secret fields, tokens, emails, structured usernames, home-path usernames, and redaction-eligible IPv4 addresses.
- Preserves useful context such as request IDs, build IDs, Unicode text, system paths, invalid IPv4-like values, loopback addresses, and narrow software version contexts.
- Shows an editor-style privacy review workspace with original and sanitized panes, line-number gutters, category chips, and a review summary.
- Provides `sanitized.log` and `preview.log` output views. `sanitized.log` keeps stable textual markers such as `[REDACTED_EMAIL]`; `preview.log` uses visual redaction bars without exposing original sensitive values.
- Shows redaction count and detected categories.
- Provides Clear and Copy controls.
- Provides a scoped IPv4 toggle for privacy-versus-diagnostic-usefulness control.
- Supports local-only drag-and-drop loading for text-like files using browser `FileReader`; unsupported files fail with inline status feedback.
- Supports keyboard shortcuts: Ctrl/Cmd+Enter to sanitize and Ctrl/Cmd+Shift+C to copy sanitized text.

## UI Architecture

The final UI adopts a muted slate developer/security-tool shell inspired by the approved Claude-generated reference design: compact topbar, amber primary action, Local Only and No Network Egress messaging, detection-category chips, editor tabs, line gutters, status bar, and visual redaction preview. The color system intentionally avoids both a full black background and stark white cards.

The Claude sanitizer implementation was not copied. The UI consumes the existing tested `src/sanitizer.js` module, and Copy always uses the sanitized plain-text textarea value rather than preview markup.

## IPv4 User Control

By default, SafePaste redacts valid non-loopback IPv4 addresses and preserves `127.0.0.0/8` loopback addresses. The `Redact non-loopback IPv4 addresses` checkbox lets the user turn off network IPv4 redaction when exact network context is needed for troubleshooting.

Manual Test 7 confirmed that this toggle is scoped: when IPv4 redaction is off, network IPs remain visible, but unrelated email and credential redaction still works.

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
node evals/run-evals.js
node evals/graders/exact-property-grader.js
node evals/run-red-team.js
node evals/run-ui-smoke.js
node evals/run-product-behavior.js
node evals/run-accessibility-checks.js
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
