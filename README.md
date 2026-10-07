# SafePaste

**Local privacy firewall for technical logs.** SafePaste finds credentials,
tokens, private keys, identities and network identifiers in pasted logs, lets a
person review every finding, and produces sanitized text that is safer to share
with AI tools, issue trackers, support, chat, email or forums. Everything runs on
the user's device: no backend, no database, no analytics, no network egress.

Detection is deterministic and rule-based (no ML, no remote judge). It is
best-effort: unknown secret formats can be missed, so human review is required
before sharing.

## Hosted demo

https://mighiana.github.io/SafePaste/ — published by `.github/workflows/pages.yml`
from `main` (app files only: `index.html`, `styles.css`, `app.js`, `src/`).
GitHub Pages only serves the static files; pasted text is still analyzed in the
browser and never sent anywhere (`connect-src 'none'`). As with any website,
GitHub sees the page request itself. Pages cannot send response headers, so the
meta CSP applies and `frame-ancestors` is not enforced there; use
`node evals/static-server.js` for header-level protection. Use synthetic data in
the public demo.

## Provenance: academic base and later extension

| | Academic base version | Later security/privacy engineering extension |
| --- | --- | --- |
| When | August 2026 Human-Centered AI software engineering coursework; committed here as `6055112` (`main`) | October 2026, phases 2–12 on `devin/*` branches |
| Scope | Browser sanitizer: 12 ordered regex rules, IPv4 toggle, side-by-side original/sanitized view, spec-first harness, evals, red-team, manual tests | Shared engine, structured parsing, profiles, review workspace, pseudonyms, 14 extra detectors, CSP/static egress checks, Web Worker, CLI, corpora, property tests, CI |
| Evidence | `SPEC_v1.md`, `history/v1/`, `evals/results_v1.md`, `evals/results_final.md`, `evals/manual_test_*.md`, legacy `RED_TEAM.md` sections | `docs/EXTENSION_BASELINE.md`, `docs/ENGINE_API.md`, `docs/TESTING.md`, `docs/PERFORMANCE.md`, `docs/EXTENSION_REPORT.md`, phase sections in `CHANGELOG.md`/`AI_WORKLOG.md`/`RED_TEAM.md` |

The academic files are preserved unchanged. At the start of the extension the
original checks were rerun: unit 37/38 and eval 72/73 failed because a fixture
placeholder (`FAKE_SLACK_TOKEN_FOR_TESTING`) was not Slack-shaped. The fixture
was corrected to an explicitly synthetic Slack-shaped value with all assertions
kept ([details](docs/EXTENSION_BASELINE.md)). The original pre-commit hook assumed
a `SafePaste/` subdirectory and silently scanned nothing; it was fixed, not bypassed.

## Problem

Technical logs mix diagnostic value (request IDs, versions, stack traces, status
codes) with secrets and personal data (passwords, bearer tokens, cloud keys,
emails, usernames in paths, client IPs). People paste them into third-party tools
to get help. Manual redaction is slow and error-prone; cloud scanners require
sending the very data that should not leave the machine.

## Privacy threat model

| Threat | Control | Residual limitation |
| --- | --- | --- |
| Accidental credential / API-token sharing | 26 deterministic detectors; credentials, tokens and secrets are locked to REDACT in every profile and never pseudonymized | Unknown or renamed formats (`pwd=`, `token=`, `auth=`, unlisted headers) can be missed |
| Private-key exposure | Whole PEM block from BEGIN through matching END is one finding; no END redacts to end of input | Lowercase or non-standard PEM labels are missed |
| PII exposure (email, usernames, home paths) | Email syntax, explicit username fields, home-path usernames; redaction or session pseudonyms | Names in prose, obfuscated email (`[at]`), `~alice` paths are not detected |
| Network information disclosure | Validated IPv4/IPv6/MAC with visible per-profile policy and `networkKind` | Dotted Cisco MACs and `addr:port` after unbracketed IPv6 are known gaps |
| False negative by the sanitizer | Corpora, property tests, red-team suites; misses are recorded, not hidden; Preview masks every finding; review required | Corpus results are not a real-world detection rate |
| False positive damaging diagnostics | Version/request/trace/build-ID context, complete-token IPv4 checks, false-positive corpus (22/22) | Ambiguous strings such as `Firmware 1.2.3.4` may be over-redacted |
| Malicious log text injecting markup | Log text only reaches the DOM through `value`/`textContent`/`createTextNode`; no `innerHTML` (static check) | Browser or extension bugs are out of scope |
| Network exfiltration by app code or dependencies | Zero dependencies; meta CSP `connect-src 'none'`; static check for `fetch`/XHR/WebSocket/EventSource/`sendBeacon`/remote assets; pre-commit gate | Meta CSP cannot stop browser extensions, OS capture, or a modified copy of the app |
| Persistent storage of sensitive input | No storage/cookie/IndexedDB/cache APIs (static check); pseudonym maps live in closure memory; Clear and page exit reset them; inputs use `autocomplete="off"` | JS cannot guarantee memory erasure; the OS clipboard and downloaded files are outside the app's control |
| Over-trust in the output | Metadata-only report, "human review required" status text, KEEP is an explicit per-finding choice counted in the report | A reviewer can still choose KEEP on a sensitive value |

## Architecture

```text
               UNTRUSTED LOG (paste / file picker / drag-drop / stdin)
                                   │
 ┌─────────────────────────────── USER DEVICE ───────────────────────────────┐
 │                                                                           │
 │  Browser UI (index.html, app.js)          CLI (bin/safepaste.js)          │
 │        │  postMessage                            │ require                │
 │        ▼                                          ▼                       │
 │  Web Worker (src/worker.js) ──────►  SHARED ENGINE  src/sanitizer.js (UMD)│
 │  sync fallback if workers blocked     1. format detection (auto/explicit)│
 │                                       2. bounded parsing: JSON, env,      │
 │                                          headers, logfmt, embedded pairs  │
 │                                       3. detector catalog (26 rules)      │
 │                                       4. overlap / conflict resolution    │
 │                                       5. policy engine (profile, custom)  │
 │                                       6. redaction or session pseudonyms  │
 │                                       7. metadata-only privacy report     │
 │        ▼                                                                  │
 │  HUMAN REVIEW: findings panel, KEEP/REDACT, masked Preview                │
 │        ▼                                                                  │
 │  SANITIZED OUTPUT: Copy, sanitized.log, privacy-report.json (explicit)    │
 │                                                                           │
 │  NO BACKEND · NO DATABASE · NO ANALYTICS · NO PERSISTENT LOG STORAGE      │
 └───────────────────────────────────┬───────────────────────────────────────┘
                                     X   NO NETWORK EGRESS (CSP connect-src 'none')
```

The engine is a single dependency-free UMD file (`window.SafePasteSanitizer` in
the browser, `require('./src/sanitizer')` in Node), so the browser, worker and
CLI cannot drift apart. It is split into the stages above rather than into a
package tree, which keeps it auditable at ~1,200 lines. Public API:
`sanitize`, `analyze`, `createReview`, `createSession`, `inspectDetectors`,
`inspectPolicy`, `inspectPolicies`, `getCapabilities`, `isValidIpv4`,
`isLoopbackIpv4`, `REDACTION_LABELS` ([reference](docs/ENGINE_API.md)).
`evals/run-contract-checks.js` pins the exact export, finding and report shapes.

## Zero-egress design

- **CSP** (meta tag, first element after charset):
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'self'; manifest-src 'none'; base-uri 'none'; form-action 'none'`.
  No `unsafe-inline`/`unsafe-eval`, no inline scripts, styles or handlers.
- **Static checks** (`node evals/run-static-privacy-checks.js`): production files
  must not use network APIs, storage/cookies/cache, `innerHTML`-style sinks,
  dynamic script loaders, external URLs/fonts, and text fields must carry
  `autocomplete="off"`. The checker also validates the CSP itself.
- **Pre-commit gate** (`sh .claude/hooks/pre-commit.sh`): scans the staged
  snapshot for credentials, requires a FAKE/SYNTHETIC/TEST marker on token-shaped
  fixtures, blocks edits to `history/` and `SPEC_v1.md`, and runs the static checker.
- **Exports are explicit**: Copy, `sanitized.log` and `privacy-report.json` happen
  only on a button press via a local `blob:` URL. The original input is never exported.

Meta CSP cannot set `frame-ancestors`; direct `file://` use therefore has no
anti-framing protection, and Chromium blocks workers from `file:` (the app then
uses the synchronous fallback). See [docs/ZERO_EGRESS.md](docs/ZERO_EGRESS.md).
These controls are verified statically and were checked in Chrome on
2026-10-07: served from localhost the page made only five same-origin requests
(index, styles, engine, app, worker) with no CSP violations; over `file://` it
used the synchronous fallback.

## Supported input formats

`auto` (default), `text`, `json`, `env`, `headers`, `logfmt`. Auto tries JSON,
complete assignment lines, header lines, then mixed key=value logs; NDJSON,
truncated JSON and JSON pairs embedded in log lines are lexed in every non-text
format. Malformed JSON falls back with `parseStatus: "malformed-json-fallback"`.
Field context drives decisions: `username` is identity, `client_ip` is a network
identifier under policy, `release`/`version` and `request_id`/`trace_id`/`build_id`
preserve IPv4-shaped diagnostic values. Parsers are bounded lexers, not shell or
YAML evaluators. YAML is not supported.

| Limit (fails closed, no partial output) | Standard (browser fallback, legacy API) | Large (worker, CLI) |
| --- | --- | --- |
| Input length (UTF-16 code units) | 2,097,152 | 16,777,216 |
| Parsed fields | 50,000 | 1,048,576 |
| Candidate findings | 100,000 | 100,000 |
| JSON nesting depth | 64 | 64 |

## Detection engine

26 catalogued detectors, each with id, category, control, severity, description,
reason, replacement policy, certainty and context requirements
(`inspectDetectors()`). "Certainty" means a deterministic rule matched; it is not
a probability.

| Control | Default | Detectors |
| --- | --- | --- |
| credentials (locked) | REDACT | authorization header, AWS access key, API key, password, GitHub token, Google API key, cloud credential (Azure/AWS secret), URL credentials, connection-string/JDBC/ODBC password, credential headers, decodable Basic credentials |
| tokens (locked) | REDACT | bearer, JWT, Slack, session, cookie value, webhook secret (Slack/Discord/Teams), URL query secret |
| secrets (locked) | REDACT | explicit secret fields and `*_SECRET`-style keys, whole private-key blocks |
| email | REDACT | email address |
| usernames | REDACT | explicit username fields |
| paths | REDACT | username inside home paths |
| network | per profile | IPv4, IPv6 (RFC 4291 parser), MAC |

Overlapping candidates are merged so a partial overlap cannot reveal a suffix;
the strongest rule wins (`PRIVATE_KEY` outranks everything). Replacement is a
single forward pass over the original source, which keeps re-sanitizing idempotent.
No entropy guessing is used.

## Privacy profiles

| Profile | Credentials / tokens / secrets | Email / usernames / paths | Network |
| --- | --- | --- | --- |
| Strict privacy | REDACT (locked) | REDACT | REDACT all, including loopback |
| Support | REDACT (locked) | REDACT | KEEP RFC1918, IPv6 unique-local and loopback; REDACT others |
| Security incident | REDACT (locked) | REDACT | KEEP IPv4/IPv6/MAC evidence. Not a public-sharing default |
| Custom | REDACT (locked) | per-category toggle | toggle plus preserve-loopback / preserve-private |
| Compatibility (browser default) | REDACT | REDACT | original academic IPv4 checkbox; loopback kept; the toggle also covers IPv6/MAC |

The active profile, its description and resolved policy are visible in the UI and
included in every report. Unknown options fail closed; credentials can never be KEEP.

## Pseudonymization

Optional mode for context identifiers only (email, username, path username,
IPv4/IPv6/MAC): the same value becomes the same marker, e.g. `[EMAIL_1]`,
`[EMAIL_2]`, `[IP_1]`, `[IPV6_1]`, `[MAC_1]`. Secrets always use full redaction
markers. Mappings live only in closure memory of one session: never in
storage, findings or reports. Clear, page exit/reload and Cancel (worker restart)
destroy them. Equivalent IPv6/MAC spellings share a number. Pseudonyms preserve
relationships, so output can still reveal structure; this is not anonymization.

## Review workflow

1. Paste, pick a file or drop a text file (or load a labelled synthetic sample:
   web, cloud/API, auth, support).
2. Choose profile, mode and format; press Sanitize (Ctrl/Cmd+Enter).
3. The findings panel lists severity (text, not colour only), category, line and
   column, action and *why it was flagged*. It never shows original values.
4. Eligible findings can be switched KEEP/REDACT; locked categories cannot.
5. **Preview** masks every detected value, including ones marked KEEP. The hidden
   output textarea is emptied while Preview is shown so kept values are not
   duplicated. Preview DOM is capped at 1,048,576 characters / 5,000 markers with a
   visible notice; Copy and downloads always use the complete reviewed result.
6. Any edit to input, profile, mode or format clears stale results and exports.

## CLI

```text
node bin/safepaste.js server.log                                 # sanitized text to stdout
node bin/safepaste.js server.log --profile strict -o server.sanitized.log --report privacy-report.json
cat server.log | node bin/safepaste.js --mode pseudonymization
node bin/safepaste.js --check server.log; echo $?
```

| Exit | Meaning |
| --- | --- |
| 0 | success; with `--check`: no finding is redacted by the active policy |
| 1 | `--check` only: at least one finding would be redacted |
| 2 | usage, input/output or processing error; no output files left behind |

Output files are created new (never overwritten); the report is metadata only;
input over 16 MiB fails closed. Example on the committed synthetic CI fixture:

```text
$ node bin/safepaste.js --check evals/fixtures/ci/synthetic-build-log.txt; echo "exit=$?"
safepaste: profile=strict mode=redaction format=logfmt lines=9 findings=5 redacted=5 kept=0 (redacted/detected: credentials 3/3, email 1/1, network 1/1)
safepaste: check FAILED: 5 finding(s) would be redacted
safepaste: local only; network egress none; human review still required.
exit=1
```

**DevSecOps gate**: `.github/workflows/ci.yml` job `artifact-gate-example` runs
`--check` on that fixture (must exit 1 = block publication), sanitizes it,
requires the sanitized copy to pass (exit 0) and uploads only the sanitized
synthetic log and its report. CI never reads private logs. See [docs/CLI.md](docs/CLI.md).

## Security properties (tested)

- Original values never appear in findings, reports or worker error messages.
- Locked credential/token/secret findings reject KEEP (`KEEP_FORBIDDEN`).
- Known secrets are absent from output; sanitization is deterministic and idempotent
  (seeded property tests).
- Hostile markup in logs stays inert text (no `innerHTML`; mocked-DOM tests).
- Limits fail closed with stable error codes and no partial output.
- No network, storage or remote-asset primitives in production files (static check).

## Testing & evaluation

All 24 entry points run from the repository root with Node 18+ and no install;
the same set runs in GitHub Actions. Current results (Node v22.20.0, linux/x64,
engineVersion 8), all exit 0:

| Suite | Result | Suite | Result |
| --- | --- | --- | --- |
| tests/test-sanitizer.js (academic) | 38/38 | tests/test-core.js | 9/9 |
| evals/run-evals.js (academic) | 73/73 | tests/test-parsers.js | 16/16 |
| evals/graders/exact-property-grader.js (academic) | 91/91, 21 cases | tests/test-policies.js | 22/22 |
| evals/run-red-team.js (academic) | 15/15 | tests/test-hook.js | PASS |
| evals/run-ui-smoke.js (academic) | PASS | tests/test-review-ui.js | 24/24 |
| evals/run-product-behavior.js (academic) | 5/5 | tests/test-pseudonyms.js | 6/6 |
| evals/run-accessibility-checks.js (academic, extended) | 18/18 | tests/test-detectors.js | 14/14 |
| tests/test-static-privacy.js | 10/10 | tests/test-worker.js | 10/10 |
| tests/test-cli.js | 9/9 | evals/run-static-privacy-checks.js | PASS |
| evals/run-benchmarks.js | PASS, 32 cases | tests/test-regressions.js | 10/10 |
| tests/test-properties.js | 11/11 | evals/run-corpora.js | 144/144 |
| evals/run-red-team-extended.js | 46/46 matched | evals/run-contract-checks.js | 20/20 |

Corpora (synthetic, `evals/corpora/`): true-positive 56/56, false-positive 22/22,
ambiguous 9/9, adversarial 39/39 (23 detected, 16 recorded known misses),
performance 18/18. Commands, conditions and semantics: [docs/TESTING.md](docs/TESTING.md).
UI tests use a mocked DOM, not a real browser.

## Red-team testing

`RED_TEAM.md` keeps the academic product red-team (15/15) and adds an extended
suite of 46 scenarios with ATTACK / EXPECTED / ACTUAL / STATUS computed by the
runner: 36 PASS, 10 KNOWN MISS, 0 FAIL. Writing the phase 11 suites exposed seven
real leaks/misparses (escaped quotes, spaced JSON pairs in log lines, unterminated
quotes, a Windows path parsed as a header, `DB_PASSWORD` in free text, usernames
followed by markup, marker re-sniffing); all were fixed with regressions.

## Performance

Engine-only, single run per case, Node v22.20.0 on an 8-vCPU Xeon, synthetic logfmt
(`node evals/run-benchmarks.js --full`, phase 12 run):

| Input | Format | Tier | Outcome | ms |
| --- | --- | --- | --- | --- |
| 1 MiB sparse | auto | large | ok, 56 findings | 408 |
| 1 MiB dense | auto | large | ok, 41,717 findings | 495 |
| 10 MiB sparse | text / auto | large | ok, 553 findings | 922 / 3,119 |
| 16 MiB sparse | text / auto | large | ok, 881 findings | 1,378 / 4,886 |
| 25 MiB, 50 MiB | any | any | fail closed `INPUT_LIMIT` | 0 |
| 1.81 MiB pathological (12 ReDoS-style shapes) | text / auto | standard | ok or fail closed | max 850 |

Supported size is therefore **up to 16 MiB** in the worker and CLI and 2 MiB in
the synchronous fallback; 25 and 50 MiB are rejected, not supported. Dense 10/16 MiB
inputs exceed the candidate or field limits and fail closed (`FINDING_LIMIT` /
`FIELD_LIMIT`). Browser worker timing has not been measured. History and method:
[docs/PERFORMANCE.md](docs/PERFORMANCE.md).

## Accessibility

| Verified (static / mocked DOM) | Not yet verified |
| --- | --- |
| 18 static checks: labelled textareas, selects, custom fieldset; native controls; focus-visible styles; polite live status; tab semantics with roving focus; keyboard file-picker alternative to drag-drop; severity shown as text; muted text token contrast >= 4.5:1; responsive stacking and reduced motion | Real keyboard-only traversal and tab order in a browser; screen-reader announcements; rendered contrast and viewport layout; OS clipboard permission |

A Chrome pass (2026-10-07) checked keyboard sanitize/tab switching, Tab reaching the
finding controls with a visible focus ring, and desktop plus 390 px layouts. A
screen-reader test and an automated rendered-contrast audit have not been done.

## Human-centered design decisions

- Review over automation: the tool explains each finding and leaves the final
  KEEP/REDACT choice to a person, except for credentials.
- Diagnostic usefulness is a requirement: request IDs, build IDs, versions and
  (by policy) loopback/private addresses stay readable.
- Narrow, auditable exceptions instead of semantic guessing (e.g. `Release 1.2.3.4`
  is a version, `Firmware 1.2.3.4` is a recorded over-redaction).
- No silent behavior: the Compatibility profile keeps the academic IPv4 checkbox;
  every other profile shows what it does before it runs.
- Muted developer-tool UI (slate palette, amber primary action, line gutters,
  LOCAL ONLY / NO NETWORK EGRESS) rather than a landing page.

## Known limitations

- Unknown, renamed or obfuscated secret formats can be missed (see recorded misses).
- Deterministic parsing does not understand natural-language meaning; ambiguity remains.
- Pseudonymized output still reveals structure and relationships.
- Large inputs are bounded by browser memory and the fixed engine limits.
- CLI and browser share the engine but differ in environment (worker vs fallback
  limits, file handling, clipboard).
- Meta CSP has header-only gaps; extensions and the OS are outside the trust boundary.
- Real-browser validation was one Chrome pass on Linux (2026-10-07); other browsers,
  screen readers and clipboard read-back were not tested. Screenshots and the demo
  clip are in [docs/evidence/](docs/evidence/) ([visual evidence](docs/PORTFOLIO_PACKAGE.md#visual-evidence)).

## Running locally

Open `index.html` directly, or serve it for worker/CSP-header behavior:

```text
node evals/static-server.js     # then open http://127.0.0.1:8765/
```

## Running the CLI

```text
node bin/safepaste.js --help
```

Run the test suites with the commands in [docs/TESTING.md](docs/TESTING.md), e.g.
`node tests/test-sanitizer.js` and `node evals/run-evals.js`. To regenerate the
archived final eval results: `node evals/run-evals.js --write evals/results_final.md`.

## Repository structure

```text
index.html, styles.css, app.js   browser UI (CSP, review workspace)
src/sanitizer.js                 shared UMD engine
src/worker.js                    local Web Worker wrapper
bin/safepaste.js                 CLI
tests/                           unit, parser, policy, detector, property, regression, UI-harness tests
evals/                           academic evals, graders, manual tests, corpora, red-team, benchmarks, static checks
evals/fixtures/ci/               synthetic CI fixture
docs/                            engine API, testing, performance, zero-egress, CLI, reports
history/v1/, SPEC_v1.md          preserved academic v1 (unchanged)
SPEC_FINAL.md, RED_TEAM.md       final spec and red-team record
AGENTS.md, .claude/              AI engineering harness and pre-commit hook
.github/workflows/ci.yml         CI: all suites + artifact gate example
```

## Methodology and harness

The project follows a specification-first loop: stakeholders and conflicts
([docs/STAKEHOLDER_MAP.md](docs/STAKEHOLDER_MAP.md)), preserved v1 spec, AI harness
(`AGENTS.md`, `.claude/`, [docs/HARNESS_REVIEW.md](docs/HARNESS_REVIEW.md)), smallest
complete product, tests/evals/red-team, preserved real failures, then iteration.
Two grader styles are used: automated exact/property grading for privacy
behavior, and a human rubric for diagnostic usefulness
(`evals/graders/`). No external model-as-judge is used, because sending logs to
one would contradict the local-only architecture. Manual tests 2–8
(`evals/manual_test_*.md`) record the policy refinements made in the academic
version (loopback preservation, structured usernames, version context, IPv4
sentence boundaries, explicit `secret` fields).

Key evidence: `SPEC_v1.md`, `SPEC_FINAL.md`, `evals/results_v1.md`,
`evals/results_final.md`, `RED_TEAM.md`, `AI_WORKLOG.md`, `CHANGELOG.md`,
`docs/ACCESSIBILITY_REVIEW.md`, `docs/FINAL_COMPLETION_REPORT.md`,
`docs/EXTENSION_REPORT.md`, `docs/PORTFOLIO_PACKAGE.md`.
