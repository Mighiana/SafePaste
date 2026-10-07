# Extension report (phases 1–12)

Later security/privacy engineering extension of the academic SafePaste project,
October 2026. Branch `devin/1791375313-docs`, based on `main`
(`6055112d8fdbeb4e353915ebb915fd0a1071285c`) and containing every phase commit.
All numbers were produced by the repository's commands; nothing is estimated.

## 1. Baseline before changes

Run on the original commit before any change (see `docs/EXTENSION_BASELINE.md`):

| Command | Baseline | Exit |
| --- | --- | --- |
| node tests/test-sanitizer.js | 37/38 (Slack-style fixture) | 1 |
| node evals/run-evals.js | 72/73 (EV-018, same fixture) | 1 |
| node evals/graders/exact-property-grader.js | 91/91, 21 cases | 0 |
| node evals/run-red-team.js | 15/15 | 0 |
| node evals/run-ui-smoke.js | PASS (mocked DOM) | 0 |
| node evals/run-product-behavior.js | 5/5 | 0 |
| node evals/run-accessibility-checks.js | 10/10 | 0 |

Both failures used `FAKE_SLACK_TOKEN_FOR_TESTING`, which is not Slack-shaped. The
active fixtures now use an explicitly synthetic Slack-shaped value, with every
assertion kept; archived evidence is unchanged. The original hook assumed a
`SafePaste/` subdirectory and scanned nothing; it now scans the staged snapshot.

## 2. Architecture changes

- `src/sanitizer.js` became a staged engine: format detection, bounded parsers,
  a 26-entry detector catalog, overlap resolution on original-source spans, a
  policy engine, redaction/pseudonym replacement and a metadata-only report.
  It stays one dependency-free UMD file shared by browser, worker and CLI.
- `src/worker.js`: classic Web Worker wrapper with a large-limit session.
- `bin/safepaste.js`: Node CLI on the same engine.
- `app.js`/`index.html`/`styles.css`: review workspace on the new API.

## 3. New features

Structured parsing; privacy profiles and custom categories; findings review with
KEEP/REDACT; masked Preview; session pseudonymization; 14 additional detectors;
CSP and static zero-egress checks; Web Worker with Cancel and sync fallback;
fail-closed limits; CLI with `--check`; metadata-only privacy report;
`sanitized.log` / `privacy-report.json` downloads; synthetic sample logs;
corpora, property, regression, red-team, contract and benchmark suites; CI.

## 4. Detectors

Original 12 (order and markers kept): authorization header, AWS access key, API
key, password, bearer token, JWT, Slack token, secret, email, username, path
username, IPv4.

Added 14: GitHub token, Google API key, cloud credential (Azure AccountKey/SAS,
AWS secret/session), URL credentials, connection-string/JDBC/ODBC password,
private-key block, session token, cookie value, credential header, Basic
credentials, webhook secret, URL query secret, IPv6 address, MAC address.
Exact rules: `docs/ENGINE_API.md`.

## 5. Structured formats

`auto`, `text`, `json`, `env`, `headers`, `logfmt`; NDJSON, truncated JSON and
embedded JSON pairs in every non-text format; malformed JSON fallback. YAML not
implemented. Limits: standard 2,097,152 code units / 50,000 fields; large
16,777,216 / 1,048,576; 100,000 candidates and depth 64 in both.

## 6. Privacy profiles

| Profile | Description (from `inspectPolicies()`) |
| --- | --- |
| strict | Redact all supported sensitive categories including loopback IPv4/IPv6. |
| support | Redact credentials/identity; preserve RFC1918 private, IPv6 unique-local and loopback addresses for troubleshooting. |
| incident | Redact credentials/identity; preserve IPv4/IPv6/MAC network evidence. Not a public-sharing default. |
| custom | Credentials/tokens/secrets locked to REDACT; email, usernames, paths, network configurable; preserve-loopback / preserve-private. |
| legacy (UI: Compatibility) | Original academic behavior with the IPv4 checkbox (which also governs IPv6/MAC). |

## 7. Pseudonymization

`mode: "pseudonymization"` replaces email, username, path username and network
identifiers with `[EMAIL_n]`, `[USERNAME_n]`, `[PATH_n]`, `[IP_n]`, `[IPV6_n]`,
`[MAC_n]`. Same value → same number within one `createSession()`; different
values → different numbers. Secrets always fully redacted. Maps are closure
memory only, reset by `session.clear()`, UI Clear, page exit/reload and Cancel.

## 8. Browser changes

Profile/format/mode selectors, custom category fieldset, findings panel (50 per
page; severity, category, line/column, action, reason; no originals), KEEP/REDACT
overrides, masked Preview with bounded DOM (1,048,576 chars / 5,000 markers),
bounded gutter (10,000 lines), worker processing status/Cancel, synthetic samples (web,
cloud/API, auth, support), Copy and explicit downloads, stale-state clearing,
CSP meta tag, `autocomplete="off"` on text fields.

## 9. CLI commands

```text
node bin/safepaste.js server.log
node bin/safepaste.js server.log --profile strict -o server.sanitized.log --report privacy-report.json
cat server.log | node bin/safepaste.js
node bin/safepaste.js --check server.log      # 0 clean, 1 redactable findings, 2 error
```

## 10. Zero-egress controls

Meta CSP (`connect-src 'none'` etc.), `evals/run-static-privacy-checks.js`, the
pre-commit gate, no dependencies. Header-only limits (`frame-ancestors`) and
`file://` worker restrictions documented in `docs/ZERO_EGRESS.md`.

## 11. Tests / evals / red-team (phase 12 run, all exit 0)

| Command | Result |
| --- | --- |
| node tests/test-sanitizer.js | 38/38 |
| node evals/run-evals.js | 73/73 |
| node evals/graders/exact-property-grader.js | 91/91 across 21 cases |
| node evals/run-red-team.js | 15/15 |
| node evals/run-ui-smoke.js | PASS |
| node evals/run-product-behavior.js | 5/5 |
| node evals/run-accessibility-checks.js | 18/18 |
| node tests/test-core.js | 9/9 |
| node tests/test-parsers.js | 16/16 |
| node tests/test-policies.js | 22/22 |
| node tests/test-hook.js | PASS |
| node tests/test-review-ui.js | 22/22 |
| node tests/test-pseudonyms.js | 6/6 |
| node tests/test-detectors.js | 14/14 |
| node tests/test-static-privacy.js | 9/9 |
| node tests/test-worker.js | 9/9 |
| node tests/test-cli.js | 9/9 |
| node evals/run-static-privacy-checks.js | PASS |
| node evals/run-benchmarks.js | PASS, 32 cases |
| node tests/test-regressions.js | 10/10 |
| node tests/test-properties.js | 11/11 |
| node evals/run-corpora.js | 144/144 (TP 56, FP 22, ambiguous 9, adversarial 39 = 23 detected + 16 known misses, PF 18) |
| node evals/run-red-team-extended.js | 46/46 matched (36 PASS, 10 KNOWN MISS, 0 FAIL) |
| node evals/run-contract-checks.js | 20/20 |

## 12. Performance

`node evals/run-benchmarks.js --full`, phase 12: PASS, 64 cases. Large tier:
1 MiB sparse auto 408 ms; 10 MiB text 922 / auto 3,119 ms; 16 MiB text 1,378 /
auto 4,886 ms; 25 and 50 MiB fail closed `INPUT_LIMIT`. Pathological 1.81 MiB
shapes: worst 850 ms. Full table: `docs/PERFORMANCE.md`.

## 13. Accessibility

Verified statically / mocked DOM: 18 static checks and 22 mocked review-UI checks.
Not verified: real keyboard traversal, screen-reader announcements, rendered
contrast/viewports, clipboard permission.

## 14. Files changed

Relative to `6055112`: see `git diff --stat 6055112d HEAD`. Modified:
`.claude/hooks/pre-commit.sh`, `AGENTS.md`, `AI_WORKLOG.md`, `CHANGELOG.md`,
`README.md`, `RED_TEAM.md`, `SPEC_FINAL.md`, `app.js`, `index.html`, `styles.css`,
`src/sanitizer.js`, `evals/eval_set.csv`, `evals/eval_set.json`,
`evals/run-accessibility-checks.js`, `evals/run-product-behavior.js`,
`evals/run-ui-smoke.js`, `evals/static-server.js`, `tests/test-sanitizer.js`.
Added: `src/worker.js`, `bin/safepaste.js`, `.github/workflows/ci.yml`, 13 test
files under `tests/`, 5 runners and 5 corpora under `evals/`, the CI fixture, and
docs `CLI`, `CORE_STAGE_RESULT`, `ENGINE_API`, `EXTENSION_BASELINE`,
`EXTENSION_REPORT`, `PERFORMANCE`, `PORTFOLIO_PACKAGE`, `REVIEW_UI_STAGE_RESULT`,
`TESTING`, `ZERO_EGRESS`. Unchanged: `SPEC_v1.md`, `history/v1/`,
`evals/results_v1.md`, `evals/results_final.md`, manual tests, graders.

## 15. README summary

Rewritten as a technical case study: provenance table (academic base vs
extension), problem, threat model (threat/control/residual), security-boundary
diagram, zero-egress design, formats and limits, detector table, profiles,
pseudonymization, review workflow, CLI and exit codes, tested security
properties, current test numbers, red-team, measured performance, accessibility
verified vs unverified, human-centered decisions, limitations, structure and
methodology.

## 16. Phase 12 fixes

- Output textarea lacked `autocomplete="off"`; added, and the static checker now
  requires it on every text field (regression cases in `tests/test-static-privacy.js`).
- Custom network labels said "IPv4" although the controls also change IPv6 and MAC
  (and loopback/private include `::1` / `fc00::/7`); unchecking "IPv4 addresses"
  silently kept IPv6/MAC. Labels and the Compatibility help text now name every
  address class; `tests/test-regressions.js` ties the labels to engine behavior.

## 17. Incomplete / pending

- Real-browser validation (worker, CSP enforcement, `file://`, keyboard, screen
  reader, viewports) and all screenshots/demo video: pending, owned by the final
  browser test stage. None were fabricated.
- GitHub Actions has not yet run on GitHub runners; benchmark bounds may need
  review on slow shared runners.
- YAML, renamed fields, XML password elements, lowercase PEM labels, dotted MACs,
  obfuscated emails and other recorded known misses remain unsupported.
- No PR opened, nothing deployed.
