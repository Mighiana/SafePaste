# SafePaste: portfolio evidence package

Every number below was produced by the repository's own commands on the
`devin/1791375313-docs` branch (Node v22.20.0, linux/x64, Intel Xeon Platinum
8375C, 8 vCPU), on synthetic data only. Screenshots and the demo clip were captured
from the real running app in Chrome on 2026-10-07 (synthetic sample data only).

## Project title

SafePaste

**Category:** Privacy Engineering / Application Security / Human-Centered AI

## One-liner

A local privacy firewall for technical logs: it finds secrets and personal data
in pasted logs, explains every finding, and lets a person approve sanitized output
before it is shared, without the log ever leaving the device.

## Description

SafePaste is a dependency-free browser tool and CLI that detects credentials,
tokens, private keys, identities and network identifiers in technical logs with
26 deterministic, explainable rules. Users choose a privacy profile, review each
finding (KEEP/REDACT where safe), optionally pseudonymize identifiers to keep
relationships, and export sanitized text plus a metadata-only privacy report. It
began as an academic Human-Centered AI project and was later extended into a
tested privacy/security engineering case study with zero-egress enforcement.

## Problem

Engineers paste logs into AI assistants, issue trackers and support chats to get
help. Those logs routinely contain passwords, bearer tokens, cloud keys, emails,
home-directory usernames and client IPs. Manual redaction misses things; cloud
secret scanners require uploading the exact data that should stay private.

## What I built

- A shared UMD engine (`src/sanitizer.js`) used unchanged by the browser, a Web
  Worker and a Node CLI: format detection, bounded parsers (JSON, env, HTTP
  headers, logfmt, embedded/NDJSON/truncated JSON), 26 catalogued detectors,
  overlap resolution, a policy engine and a metadata-only privacy report.
- Privacy profiles (Strict, Support, Security incident, Custom, plus the original
  academic Compatibility mode) with inspectable resolved policies.
- A findings review workspace: severity, category, line/column, action and reason
  per finding, KEEP/REDACT overrides for eligible findings, a Preview that masks
  every detected value, and explicit Copy / `sanitized.log` / `privacy-report.json`.
- Session-local pseudonymization (`[EMAIL_1]`, `[IP_2]`) held only in memory and
  destroyed by Clear, reload or Cancel.
- A CLI with `--check` for CI gates (exit 0 clean, 1 redactable findings, 2 error)
  and a GitHub Actions example that gates a synthetic build log.
- Zero-egress enforcement: strict CSP, static checks for network/storage/DOM sinks,
  and a pre-commit gate.
- Test infrastructure: 24 dependency-free entry points including synthetic corpora,
  seeded property tests, an extended red-team suite and ReDoS benchmarks.

## Architecture

```text
UNTRUSTED LOG ─► [ USER DEVICE: format parser ─► detection engine ─► policy engine
                   ─► human review ─► sanitized output + metadata report ]
                   browser UI ─► Web Worker ─┐
                   CLI ──────────────────────┴─► one shared engine (src/sanitizer.js)
                 X  no backend · no database · no analytics · no network egress
```

## Privacy model

- Logs are processed only in page/worker/process memory; no storage APIs, cookies,
  IndexedDB or cache; text fields opt out of autocomplete restoration.
- Findings and reports never contain original values; worker errors cross the
  boundary as fixed codes only.
- Credentials, tokens and secrets are locked to REDACT in every profile.
- Pseudonym maps are closure memory per session; they are not anonymization and
  still reveal structure.
- Exports happen only on explicit user action; the original input is never exported.

## Security controls

- CSP: `connect-src 'none'`, `object-src 'none'`, `base-uri 'none'`,
  `form-action 'none'`, `worker-src 'self'`, no `unsafe-inline`/`unsafe-eval`.
- Static privacy checker over all production files (network APIs, storage, unsafe
  DOM sinks, remote assets, script loaders, CSP shape, autocomplete).
- No `innerHTML`; hostile log text is rendered via `value`/`textContent`.
- Fail-closed limits (input, fields, candidates, JSON depth) with stable error codes.
- Pre-commit hook that scans the staged snapshot and blocks edits to the preserved
  academic history.
- Contract checks that pin the public API, finding and report shapes.

## Human-centered design decisions

- The tool assists judgment instead of replacing it: every finding explains why it
  was flagged, and the person decides KEEP/REDACT where that is safe.
- Diagnostic usefulness is protected (request/build IDs, versions, loopback or
  private addresses by profile), based on academic manual tests where over-redaction
  made logs useless.
- Preview never reveals a value the user chose to keep; Copy uses the reviewed text.
- Profiles never change behavior silently; the active policy is shown and reported.
- Severity is shown as text, not colour alone; keyboard file picker as a drag-drop alternative.

## Technical decisions

- Plain HTML/CSS/JS and Node, zero dependencies: smallest auditable surface,
  offline by default.
- Deterministic rules with narrow context exceptions instead of ML or entropy
  guessing, so every decision is explainable and reproducible.
- Bounded lexers and validators (RFC 4291 IPv6 parser, MAC validator, PEM block
  scanner, Basic-credential decoder) instead of large regexes; a quadratic JWT
  regex inherited from the base version was replaced with linear scanning.
- One engine file for browser, worker and CLI to avoid behavioral drift.
- Synchronous fallback (2 MiB) when browsers block workers on `file://`.

## Testing / evaluation

24 entry points, all passing (exit 0):

- Academic suites: unit 38/38, evals 73/73, exact-property grader 91/91 across 21
  cases, product red-team 15/15, UI smoke PASS, product behavior 5/5, accessibility
  static 18/18 (10 original + 8 added).
- Extension suites: core 9/9, parsers 16/16, policies 22/22, hook PASS, review UI
  (mocked DOM) 24/24, pseudonyms 6/6, detectors 14/14, static privacy 10/10 tests +
  checker PASS, worker 10/10, CLI 9/9, benchmarks PASS (32 cases), regressions 10/10,
  properties 11/11, corpora 144/144, extended red-team 46/46 matched, contract 20/20.
- Synthetic corpora: true-positive 56/56, false-positive 22/22, ambiguous 9/9,
  adversarial 39/39 (23 detected, 16 recorded known misses), performance 18/18.

The baseline before the extension was honestly recorded as unit 37/38 and eval
72/73 because of a non-Slack-shaped fixture placeholder.

## Red-team results

- Extended scenario suite: 46 cases, 36 PASS, 10 KNOWN MISS, 0 FAIL; status is
  computed by the runner, which fails if a known miss silently changes.
- Building the suites found seven real leaks/misparses, all fixed with regressions:
  escaped quotes splitting a password, spaced JSON pairs inside log lines/NDJSON,
  unterminated quoted credentials, a Windows path parsed as a header,
  `DB_PASSWORD` in free text, usernames followed by markup, and re-sanitizing
  output that started with a marker.
- Recorded misses include renamed fields (`pwd=`, `token=`), XML password
  elements, lowercase PEM labels, dotted MACs, obfuscated email and Unicode
  look-alike separators.

## Performance results

Engine-only, single run per case, synthetic logfmt (`node evals/run-benchmarks.js --full`):

- 1 MiB: 408 ms (auto, 56 findings); dense 1 MiB with 41,717 findings: 495 ms.
- 10 MiB: 922 ms text / 3,119 ms auto. 16 MiB: 1,378 ms text / 4,886 ms auto.
- 25 MiB and 50 MiB: rejected immediately (`INPUT_LIMIT`); not supported.
- 12 pathological ReDoS-style shapes at 1.81 MiB: worst 850 ms; none hang.

Browser/worker timing in a real browser has not been measured.

## Challenges

- Keeping the academic provenance honest while extending it: the original files,
  specs and results are untouched and the extension is documented separately.
- Preventing partial leaks when rules overlap (e.g. a URL password inside an email
  match) without hiding useful context.
- JSON escapes and truncated logs: decoding values while mapping them back to exact
  source spans.
- Making the UI safe by construction: Preview masking even KEEP values, clearing
  stale exports on any edit, never rendering originals in findings.
- Proving zero egress as a testable property rather than a claim.

## Known limitations

- Unknown, renamed or obfuscated secret formats can be missed; human review is required.
- Deterministic rules do not understand natural-language meaning.
- Pseudonymized output still reveals relationships and structure.
- Inputs above 16 MiB (2 MiB without a worker) are rejected.
- Meta CSP cannot provide anti-framing; browser extensions and the OS are outside
  the trust boundary.
- Real-browser behavior, CSP enforcement, `file://`, keyboard traversal and
  screen-reader output are not yet verified.

## Tech stack

HTML, CSS, plain JavaScript (strict mode, UMD module), Web Workers, Node.js 18+ (CLI and tests),
GitHub Actions. No runtime or development dependencies.

## Project status

Academic base version complete (2026). Security/privacy engineering extension
(phases 2–12, October 2026) implemented and tested at engine, mocked-DOM and
static level on a review branch, plus one real-browser pass in Chrome (Linux).
Not deployed as a hosted service; it is designed to run locally.

## Repository URL

https://github.com/Mighiana/SafePaste

## Visual evidence

Captured from the real running app (served by `node evals/static-server.js`) and a
real terminal on 2026-10-07, using only the built-in synthetic samples and committed
fixtures. Desktop screenshots are full-page at 1585 px width.

| # | Capture | File |
| --- | --- | --- |
| 1 | Main review workspace (Compatibility, web sample) | [01-review-workspace.png](evidence/01-review-workspace.png) |
| 2 | Structured JSON sanitization (Strict, Cloud/API JSON) | [02-structured-json.png](evidence/02-structured-json.png) |
| 3 | Findings review panel (locked PASSWORD finding) | [03-findings-panel.png](evidence/03-findings-panel.png) |
| 4 | Privacy profile selection (Custom, email kept) | [04-privacy-profiles.png](evidence/04-privacy-profiles.png) |
| 5 | Pseudonymized output | [05-pseudonymized-output.png](evidence/05-pseudonymized-output.png) |
| 6 | Privacy report (auth headers, locked Authorization) | [06-privacy-report.png](evidence/06-privacy-report.png) |
| 7 | CLI usage (terminal) | [07-cli-usage.png](evidence/07-cli-usage.png) |
| 8 | Evaluation / red-team results (terminal) | [08-eval-redteam-results.png](evidence/08-eval-redteam-results.png) |
| 9 | Mobile 390 px (Security incident profile) | [09-mobile-390.png](evidence/09-mobile-390.png) |
| 10 | 14 s muted VP9 WebM: load synthetic log, sanitize, preview masking, findings, report | [demo.webm](evidence/demo.webm) |

The browser pass found two issues, fixed before capture: finding REDACT/KEEP selects
overflowed their cards at 390 px, and the Cloud/API sample's 9-character `api_key`
value was below the API_KEY minimum length and stayed visible. A stale file-picker
note ("File limit: 2 MiB ... not yet benchmarked") was also corrected.
