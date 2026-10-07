# Core stage result — October 2026 extension, phases 2–4

## Delivered scope

Branch: `devin/1791366708-core-engine`, based on `origin/main` commit
`6055112d8fdbeb4e353915ebb915fd0a1071285c`; prior history retained. Separate
working commits for baseline/hook repair, phase 2 detection metadata/spans,
phase 3 structured parsing, and phase 4 privacy policies/overrides.

- Corrected only active unit/JSON/CSV Slack fixtures without weakening assertions.
- Repaired actual Git-root staged-secret hook; unusual paths, snapshot-only
  scanning, fixture exemptions, no value disclosure and fail-closed errors tested.
- Original-source exclusive spans and line/column metadata; deterministic
  connected-overlap resolution; forward-only replacement. No generated markers
  are scanned during apply. Detector metadata is inspectable and immutable.
- Bounded text/JSON/env/key=value/HTTP-header/logfmt parsing; escaped JSON keys
  and decoded strings map to source offsets. Valid JSON/layout preserved where
  possible (numeric credential replacements change scalar type to string).
- Explicit version/release and request/trace/build-ID contexts exempt IPv4 only.
- Strict/support/incident/custom policy inspection, custom category/network
  controls, metadata-only default/final reports and per-call validated overrides.
  High-risk secrets/credential overlaps cannot be kept or disabled.
- Fixed inherited JWT failure-mode quadratic scanning, retaining prior syntax
  behavior in generated comparisons. Cross-realm plain options supported while
  rejecting non-plain objects. No dependencies or new detector categories.

## Consumer API

UMD `SafePasteSanitizer` / `require('./src/sanitizer')`:

```js
engine.inspectDetectors();
engine.inspectPolicies();
engine.inspectPolicy({profile: 'support'});
engine.getCapabilities();
engine.analyze(input, {profile: 'strict', format: 'auto'}); // {findings, report}
const review = engine.createReview(input, {profile: 'support'});
const result = review.apply({[findingId]: 'REDACT'}); // {sanitized, findings, report}
review.clear(); // later apply throws REVIEW_CLEARED
engine.sanitize(input, {redactIpAddresses: false}); // legacy shape
```

Overrides are per-call, not persistent changes; omit IDs to use the initial
policy. No custom replacement strings. Findings/report omit original values;
only explicitly returned sanitized output can reveal values human/policy KEEP.
The legacy result intentionally includes raw `.original`/`.matches[].text` and
must **not** be exported as a privacy report. Span offsets refer to original
UTF-16 code units; line/column are 1-based. See [complete API](ENGINE_API.md).

Hard bounds: 2,097,152 input code units; 100,000 candidate findings/overrides;
64 JSON container levels; 50,000 parsed scalar units (including keys).
Limits/unknown policies/invalid overrides return value-free errors, not partial
output. These bounds are not measured browser resource-support promises.

## Independently rerun final checks

All commands below exited 0 on the final implementation. Baseline failures are
preserved in [the independent baseline document](EXTENSION_BASELINE.md).

| Command | Current observed result |
| --- | --- |
| `node tests/test-sanitizer.js` | 38/38 |
| `node evals/run-evals.js` | 73/73 (includes static privacy/security cases) |
| `node evals/graders/exact-property-grader.js` | 91/91 properties across 21 cases |
| `node evals/run-red-team.js` | 15/15 |
| `node evals/run-ui-smoke.js` | PASS mocked DOM/clipboard API workflow |
| `node evals/run-product-behavior.js` | 5/5 mocked workflows |
| `node evals/run-accessibility-checks.js` | 10/10 static checks |
| `node tests/test-core.js` | 9/9, including 240 JWT syntax comparisons and 440k-code-unit malformed run |
| `node tests/test-parsers.js` | 16/16, including generated escape/source-span checks and hard parser limits |
| `node tests/test-policies.js` | 22/22, including report privacy, realm compatibility and override bounds |
| `node tests/test-hook.js` | PASS standalone/staged/exemption/error/no-disclosure checks |
| `node --check` on changed source/new tests | PASS |
| `sh -n .claude/hooks/pre-commit.sh` | PASS |
| `git diff --check` | PASS |

Required hook runs against staged content before every working commit. No
historical eval result regeneration (`--write`) was performed. No package,
linter or type-check dependencies/configuration were added; this plain JS repo
uses syntax checks plus existing static security/privacy evals.

## Deliberate gaps and handoff

- No PR, merge or deployment. No UI/server/browser setup in this stage. Parent
  stage owns final real-browser validation. Existing UIs consume the legacy API;
  worker/CLI/finding-review consumers can use the documented new API later.
- No pseudonyms, worker, CLI, exports UI, advanced secret detectors, IPv6,
  private-key detector, YAML, NDJSON or comprehensive performance benchmarks.
- Malformed JSON falls back honestly; escaped malformed input may evade rules.
  Env/logfmt are bounded lexers, not shell expansion/multiline interpreters.
- Unknown secret fields/formats, natural-language identities and ambiguous
  firmware/IP values remain limitations. Short values below legacy thresholds
  are not assumed credentials. Compound objects under a credential-named field
  are not blanket-redacted; object-key redaction may collapse keys.
- Support keeps RFC1918/loopback; incident keeps IPv4 evidence. Neither makes
  preserved context automatically safe for public sharing. Inspect final output.
- Secure memory erasure and complete removal of every sensitive value are not
  guaranteed. KEEP is always an intentional potential disclosure.
- Academic `history/v1`, `SPEC_v1.md`, recorded historical eval/manual/grader
  evidence, UI source and main branch remain unchanged.

Changed files: `src/sanitizer.js`; active `tests/test-sanitizer.js`,
`evals/eval_set.json`, `evals/eval_set.csv`; new `tests/test-core.js`,
`tests/test-parsers.js`, `tests/test-policies.js`, `tests/test-hook.js`;
`.claude/hooks/pre-commit.sh`; `README.md`, `CHANGELOG.md`, `AI_WORKLOG.md`;
new `docs/EXTENSION_BASELINE.md`, `docs/ENGINE_API.md`, and this result.
