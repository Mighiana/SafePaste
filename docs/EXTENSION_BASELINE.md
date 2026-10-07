# Security/privacy engineering extension baseline

This is a later (October 2026) extension of the academic Human-Centered AI
project, not functionality present in the original submission. Baseline commit:
`6055112d8fdbeb4e353915ebb915fd0a1071285c` (`origin/main`).

## Privacy and provenance contract

- Deterministic, dependency-free, device-local rules. No backend, remote judges,
  opaque ML, network egress, analytics, or persisted logs.
- Only explicit user-driven sanitized output/report exports may be added later.
- `SPEC_v1.md`, `history/v1/`, recorded eval/grader/manual evidence remain unchanged.
- No fixture-specific production behavior. No deleted/weakened assertions.
- This core stage does not implement UI, pseudonyms, advanced detectors, workers,
  CLI, deployment, or browser verification.

## Independent pre-change checks (2026-10-07)

Every command ran independently before changing behavior; no `--write` flags
were used, so archived result files were not regenerated.

| Command | Actual baseline | Exit |
| --- | --- | --- |
| `node tests/test-sanitizer.js` | 37/38; Slack-style token test failed | 1 |
| `node evals/run-evals.js` | 72/73; EV-018 failed | 1 |
| `node evals/graders/exact-property-grader.js` | 91/91 properties, 21 cases | 0 |
| `node evals/run-red-team.js` | 15/15 | 0 |
| `node evals/run-ui-smoke.js` | PASS (mocked DOM/clipboard) | 0 |
| `node evals/run-product-behavior.js` | 5/5 (mocked DOM) | 0 |
| `node evals/run-accessibility-checks.js` | 10/10 static checks | 0 |

### Fixture discrepancy

Both failing cases contain `FAKE_SLACK_TOKEN_FOR_TESTING`, which has no Slack
token prefix and is correctly *not* matched by the Slack syntax detector.
The current unit test and EV-018 JSON/CSV inputs change to the explicitly
synthetic, non-operational `xoxb-SYNTHETIC-TEST-ONLY-0000000000`. All assertions
are retained with that substituted value. Historical copies remain untouched.
The old recorded 38/38 and 73/73 evidence describes its historical run, not this
checkout's baseline. No rule will recognize the old placeholder specially.

### Harness discrepancy

The hook assumes a `SafePaste/` child directory and exits successfully without
scanning this standalone repository. Repair the root discovery and staged-path
handling, fail closed on scan errors, and avoid printing possible secret values.
Synthetic test/eval and historical documentation remain explicitly excluded;
this lightweight guard is not a comprehensive scanner.

## Audit scope and findings

Reviewed all tracked files: current UI HTML/CSS/JS and sanitizer; both JSON/CSV
corpora; unit, eval, exact/property, red-team, mocked UI/product and accessibility
runners; every document under `docs/`; specifications; README, red-team report,
AI worklog and changelog; all manual/grader/result evidence; historical v1 source,
UI, tests, evals and results; AGENTS, ignore rules, and the complete `.claude`
harness. Compared archived runners/tests with current versions to trace changes.

- Sequential replacement shifts later match offsets and can scan generated
  markers. Resolve spans on original source instead.
- Current `.matches.text` and `.original` intentionally contain raw input; retain
  them only in the legacy compatibility API, not new review/report metadata.
- Existing narrow version/release exceptions, full-token IPv4 validation,
  loopback preservation, home-username-only replacement, scoped IPv4 opt-out,
  structured usernames and stable markers are regression contracts.
- Firmware version ambiguity is documented, not grounds for speculative NLP.
- Existing structured handling is regex-only; escaped JSON values/keys need
  validated parsing and decoded-to-source offsets without reserializing layout.
- Privacy evals discover production files recursively. Existing UI evidence is
  mocked/static; real keyboard, screen-reader, viewport and clipboard checks are
  not established by these commands.
- The development policy file is conceptual, not proof of runtime enforcement.
- No dependencies or framework migration are needed for this bounded core stage.
