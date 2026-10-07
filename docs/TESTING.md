# Testing and evaluation (phase 11 extension)

This page belongs to the later security/privacy engineering extension. The academic
base version's evidence (`evals/results_v1.md`, `evals/results_final.md`, the legacy
section of `RED_TEAM.md`, `history/v1/`) is kept unchanged; the counts below are
separate and marked as legacy or new.

## Conditions for the numbers on this page

- Date: 2026-10-07, engine `engineVersion` 8, branch `devin/1791373403-evals-ci`.
- Runtime: Node v22.20.0, linux/x64 (kernel 6.8.0-1061-aws), Intel Xeon Platinum
  8375C @ 2.90 GHz, 8 vCPU, 31 GiB RAM. Single run, no warm-up control.
- Inputs: synthetic only (committed fixtures or deterministic generators). No user or
  private logs were read.
- Verification type: **static/engine only** (Node, plus the mocked DOM harness in
  `tests/ui-harness.js`). No real browser, Web Worker in a browser, screen reader or other
  assistive technology was used for anything on this page.

## Commands and current results

All commands are dependency-free (`node <file>`), exit 0 on success and 1 on failure.

| Command | Kind | Result |
| --- | --- | --- |
| `node tests/test-sanitizer.js` | legacy (academic) | 38/38 |
| `node evals/run-evals.js` | legacy (academic) | 73/73 |
| `node evals/graders/exact-property-grader.js` | legacy (academic) | 91/91 across 21 cases |
| `node evals/run-red-team.js` | legacy (academic) | 15/15 |
| `node evals/run-ui-smoke.js` | legacy (academic, mocked DOM) | PASS |
| `node evals/run-product-behavior.js` | legacy (academic, mocked DOM) | 5/5 |
| `node evals/run-accessibility-checks.js` | legacy, extended in phase 5 (static) | 18/18 |
| `node tests/test-core.js` | extension | 9/9 |
| `node tests/test-parsers.js` | extension | 16/16 |
| `node tests/test-policies.js` | extension | 22/22 |
| `node tests/test-hook.js` | extension | PASS |
| `node tests/test-review-ui.js` | extension (mocked DOM) | 22/22 |
| `node tests/test-pseudonyms.js` | extension | 6/6 |
| `node tests/test-detectors.js` | extension | 14/14 |
| `node tests/test-static-privacy.js` | extension | 9/9 |
| `node tests/test-worker.js` | extension (mock Worker) | 9/9 |
| `node tests/test-cli.js` | extension | 9/9 |
| `node evals/run-static-privacy-checks.js` | extension (static) | PASS |
| `node evals/run-benchmarks.js` | extension | PASS, 32 cases within bounds |
| `node tests/test-regressions.js` | **new, phase 11** (+1 in phase 12) | 10/10 |
| `node tests/test-properties.js` | **new, phase 11** | 11/11 (seed 20261007, 160 samples each) |
| `node evals/run-corpora.js` | **new, phase 11** | 144/144 |
| `node evals/run-red-team-extended.js` | **new, phase 11** | 46/46 matched (36 pass, 10 known misses, 0 fail) |
| `node evals/run-contract-checks.js` | **new, phase 11** (static) | 20/20 |

## Corpora (`evals/corpora/*.json`)

Each file is marked `"syntheticOnly": true`; ids are unique across files (enforced by
`run-contract-checks.js`). `node evals/run-corpora.js --only <name>` runs one file.

| Corpus | Meaning | Cases | Result |
| --- | --- | --- | --- |
| `true_positive` | must redact; each listed value must be absent and its category reported | 56 | 56/56 |
| `false_positive` | must preserve; every listed context value survives, and output equals input where marked `unchanged` (versions, request/build ids, hashes, ...) | 22 | 22/22 |
| `ambiguous` | human review; the finding exists with the expected default action per profile, allows KEEP, and KEEP vs REDACT overrides change the output | 9 | 9/9 |
| `adversarial` | bypass attempts; status `detected` or `known-miss` must match what happens | 39 | 39/39 (23 detected, 16 known misses) |
| `performance` | ReDoS / size fixtures with a time bound or an expected fail-closed code | 18 | 18/18 |

False-positive and false-negative evidence from the corpora: 0 of 22 must-preserve cases
changed; 0 of 56 must-redact cases leaked. The 16 adversarial known misses are real false
negatives and are listed in `RED_TEAM.md`. These are counts on a curated synthetic
corpus, not a detection rate for real-world logs.

## Property tests (`tests/test-properties.js`)

Generated with a seeded 32-bit xorshift PRNG (no dependencies), seed 20261007, 160
samples per property: secret absent from output; same value gets the same pseudonym and
different values different pseudonyms; `session.clear()` resets numbering; fixed policy is
deterministic; preserved context unchanged; sanitizing twice is idempotent; finding
positions point into the original input; findings and reports never contain secret
values; parser escapes, hostile markup, overlaps and malformed nested logs; profiles and
custom flags; IPv6, MAC, private keys, headers, DB and connection-string secrets.

## Performance / ReDoS fixtures (`evals/corpora/performance.json`)

Measured in the run recorded above (single run; times vary between runs and machines):

| Case | Input | Result | Time |
| --- | --- | --- | --- |
| PF-001 sparse logfmt, large tier | 1,048,576 chars | ok, 56 findings | 357.0 ms |
| PF-002 dense logfmt, large tier, text | 1,048,576 chars | ok, 41,717 findings | 186.7 ms |
| PF-003 dense logfmt, standard tier, auto | 1,048,576 chars | FIELD_LIMIT | 41.5 ms |
| PF-004 one line without separators | 2,000,000 chars | ok | 355.0 ms |
| PF-005 thousands of dotted digit runs | 1,000,000 chars | ok | 344.0 ms |
| PF-006 malformed bearer repetition | 1,000,000 chars | ok, 43,477 findings | 338.2 ms |
| PF-007 unterminated PEM BEGIN markers | 1,000,000 chars | ok | 89.2 ms |
| PF-008 unclosed JSON string | 1,000,008 chars | ok | 310.0 ms |
| PF-009 JSON nesting 65 | 130 chars | DEPTH_LIMIT | 2.4 ms |
| PF-010 Unicode combining marks and emoji | 1,000,000 chars | ok | 56.5 ms |
| PF-011 repeated escaped quotes in a credential | 1,000,010 chars | ok | 384.8 ms |
| PF-012 dense embedded JSON pairs, standard tier | 1,000,000 chars | FIELD_LIMIT | 45.2 ms |
| PF-013 hex-colon runs (IPv6/MAC-like) | 1,000,000 chars | ok | 152.8 ms |
| PF-014 email-like dotted runs | 500,013 chars | ok | 499.3 ms |
| PF-015 one char over the large tier | 16,777,217 chars | INPUT_LIMIT | 0.0 ms |
| PF-016 dense embedded JSON pairs, large tier | 1,000,000 chars | ok | 462.3 ms |
| PF-017 underscore-joined identifier runs | 1,048,576 chars | ok | 22.7 ms |
| PF-018 near-miss suffix keys | 1,048,576 chars | ok | 49.1 ms |

PF-017/PF-018 were added because the phase 11 suffix-key text rules introduced a new
`[A-Za-z][A-Za-z0-9_.-]{0,62}_` prefix; they confirm it stays bounded. Larger sizes (10,
16, 25, 50 MiB) are covered by `node evals/run-benchmarks.js --full` in
`docs/PERFORMANCE.md`. Browser and worker timing is not measured here.

## Syntax, lint-like and type-contract checks (`evals/run-contract-checks.js`)

No TypeScript or linter dependency. It checks `node --check` on every JS file, JSON parsing,
LF/trailing-whitespace/tab/final-newline hygiene, strict mode and no
`var`/`eval`/`new Function`/`debugger`/`console` in production JS, and exact key sets and
types for the public API: exports, `getCapabilities()`, detector catalog, policies,
`createReview()` findings/report/`apply()` in every format and mode, `createSession()`
limits, the unchanged legacy `sanitize()` result, coded errors, worker message types and
CLI exit codes. Exact key sets mean a new field (for example one carrying an original
value) fails the check until the contract is updated on purpose. It also checks that
production code never loads test/eval fixtures and that the CI workflow runs every
`tests/test-*.js` and `evals/run-*.js` entry point.

## Continuous integration (`.github/workflows/ci.yml`)

Runs on push and pull request with `actions/checkout` and `actions/setup-node` (Node 22)
only; nothing is installed and `contents: read` is the only permission. Job `checks` runs every
command above. Job `artifact-gate-example` shows the DevSecOps gate from `docs/CLI.md` on
the committed synthetic fixture `evals/fixtures/ci/synthetic-build-log.txt`: `--check` on
the raw log must exit 1 (publication blocked), the sanitized copy must exit 0, and only
the sanitized synthetic log and its metadata report are uploaded as an artifact
(`actions/upload-artifact`). The fixture uses `.txt` because `.gitignore` deliberately
ignores `*.log`.

The workflow was validated locally (YAML parses, every command exits 0 on this VM, the
gate exits 1 then 0). It had not run on GitHub-hosted runners when this page was written;
benchmark time bounds there may need adjusting if runners are much slower.
