# AI Worklog

This file records meaningful AI-assisted engineering decisions and real failures. It intentionally omits trivial command-by-command noise.

## Entries

### 2026-10-07: Later shared-core extension, phases 2–4 only

- Task: Audit all current and historical repository files, reproduce seven
  baseline commands, implement span-aware metadata/structured parsing/policies
  in separate commits, without dependencies or UI changes.
- Baseline observed: unit 37/38 and eval 72/73; exact 91/91, red-team 15/15,
  mocked UI smoke pass, mocked product 5/5, static accessibility 10/10.
- Actual failure: active Slack fixtures were an ordinary placeholder, not Slack
  syntax. Corrected current unit/JSON/CSV data to a synthetic Slack-shaped value,
  retained assertions, and never taught production to recognize the placeholder.
- Harness failure: hook expected a child SafePaste directory and scanned nothing.
  Fixed actual Git-root scanning, NUL-safe staged paths, error propagation and
  no printing of matched values. Test/eval/history/documentation exemptions are
  explicit; this is still a heuristic guard, not comprehensive secret scanning.
- Core decision: collect on original source, coalesce overlapping spans, apply
  once. New immutable findings/reports omit raw values; the legacy adapter alone
  retains original/raw matches for compatibility. Closure-backed review can be
  cleared; secure runtime memory erasure is not claimed.
- Parser iteration failures: auto env recognition initially swallowed mixed
  prose; raw-vs-parsed filtering initially missed a Bearer token crossing a scalar
  boundary; username classification initially hid expected email categories.
  Existing tests/evals caught these. Narrowed auto env classification, retained
  crossing raw findings and kept the existing username syntax. Fixed the actual
  bugs rather than changing assertions.
- Context decision: version/release and parsed request/trace/build fields exempt
  IPv4 only; credential/email detectors still run. JSON replacements map escapes
  to original spans and preserve layout, with quoted primitive replacements.
- Policy decision: legacy remains implicit. Explicit strict includes loopback;
  support preserves RFC1918/loopback; incident preserves IPv4 evidence; custom
  exposes controls but never disables high-risk credentials/tokens/secrets.
  Overrides are validated per-call decisions, never arbitrary replacement text.
- Bounded-scanning failure found: repeated `eyJFAKETEST-` runs demonstrated
  inherited JWT regex scaling (1k/2k/4k repeats: 35.2/114.0/468.5 ms in this Node
  run). Lexing maximal token runs and walking dot components produced
  2.8/1.5/3.0 ms for the same diagnostic samples; 40k repeats took 29.6 ms.
  These are single-run diagnostics, **not** stable benchmark/support claims.
  Added the 440k-code-unit malformed-token regression plus 240 generated syntax
  comparisons against the prior JWT grammar. Large-file worker benchmarks remain
  a later stage.
- Final full-suite failure: strict same-realm Object-prototype validation rejected
  options originating in the mocked browser VM, breaking UI smoke and all five
  product checks. Fixed validation to accept native Object prototypes across JS
  realms while rejecting custom prototypes/arrays, and added an explicit realm
  regression. No UI or harness assertions were changed.
- Accepted scope: phases 2, 3, 4 are separate working commits; no new detector
  categories, YAML dependencies, UI, pseudonyms, worker, CLI, PR or deployment.
  Historical v1/spec and recorded historical evidence remain unchanged. Exact
  final verification is in docs/CORE_STAGE_RESULT.md; real browser checks belong
  to the parent stage, not these mocked/static results.

### 2026-08-13: Project initialization

- Task: Establish SafePaste methodology and preserved v1 requirements before writing product code.
- Instruction given: Build SafePaste as a privacy-aware local browser sanitizer with stakeholder analysis, v1 specification, harness, evaluations, red-team testing, and honest evidence.
- What AI produced: Initial repository structure, README skeleton, stakeholder map, `SPEC_v1.md`, `AGENTS.md`, and changelog skeleton.
- Accepted: Accepted after SafePaste files were staged, committed, and pushed while unrelated workspace changes were left untouched.
- Manual changes: None at this stage.
- Failure or surprise: Existing workspace is a different Flutter project with unrelated modified debug-symbol files, so SafePaste is being created in a contained `SafePaste/` subdirectory.
- Resulting control: Stage and commit only SafePaste files; do not modify or revert unrelated workspace changes.

### 2026-08-13: Initial sanitizer and unit tests

- Task: Build the smallest local browser sanitizer and deterministic unit tests.
- Instruction given: Implement isolated sanitizer logic and test required categories including password JSON and API key JSON.
- What AI produced: Static UI, `src/sanitizer.js`, and `tests/test-sanitizer.js`.
- Accepted: Accepted as v1 evidence, but not final behavior.
- Manual changes: None before the first test run.
- Failure or surprise: The first unit test run passed 16/18 tests but failed quoted JSON key cases for `"password":"..."` and `"apiKey":"..."`.
- Resulting control: Preserve the failure in v1 results and add/fix JSON key handling after the initial evaluation snapshot.

### 2026-08-13: Harness verification

- Task: Manually invoke the SafePaste pre-commit hook before committing v1 evidence.
- Instruction given: Run the hook against the staged SafePaste files.
- What AI produced: The hook printed `grep: command not found` and exited with status 0.
- Accepted: Not accepted as final harness behavior.
- Manual changes: None before recording the failure.
- Failure or surprise: The hook depended on `grep`, which was not available in the shell used for invocation, so the hook did not actually scan.
- Resulting control: Preserve the failure in `evals/results_v1.md`; update the hook after the v1 snapshot to use `git grep` or fail closed.

### 2026-08-13: Security-review-driven fixes

- Task: Address real v1 failures and security-review findings.
- Instruction given: Fix JSON credential redaction, Basic/Token Authorization headers, `PWD` false positives, static scan coverage, and hook portability without weakening tests.
- What AI produced: Updated sanitizer rules, unit tests, eval cases EV-037 through EV-039, red-team cases RT-P13 through RT-P15, recursive production scanning, and a revised hook.
- Accepted: Accepted after local tests passed.
- Manual changes: None outside the documented patches.
- Failure or surprise: Browser automation through the in-app browser failed because the Node REPL kernel hit a filesystem permission error outside the workspace.
- Resulting control: Added `evals/run-ui-smoke.js` to verify UI wiring with a mocked DOM/clipboard and documented that OS clipboard permission remains not browser-verified.

### 2026-08-13: Final harness hardening

- Task: Address final security-reviewer low-severity harness findings.
- Instruction given: Make external-resource eval scanning fully recursive and verify the pre-commit hook handles staged filenames with spaces.
- What AI produced: Recursive external-resource scanning and an initial `mktemp`-based hook path loop.
- Accepted: Partially; the eval fix was accepted, but the hook needed another revision.
- Manual changes: Removed a temporary staged file named `hook path smoke.js` after the hook test.
- Failure or surprise: The revised hook still failed in this environment because `mktemp` was unavailable.
- Resulting control: Replaced the `mktemp` approach with a pipe/read loop that handles spaces and does not rely on `grep` or fixed temp files; reran the hook successfully against the staged spaced filename.

### 2026-08-13: Session 7 grader extension

- Task: Extend SafePaste evaluation methodology with automated and human-style graders.
- Instruction given: Add two grader styles without removing the existing eval set, include localhost as a borderline case, compare grader verdicts, and document any specification implications.
- What AI produced: `evals/graders/exact-property-grader.js`, `evals/graders/human-rubric.md`, `evals/graders/grader-comparison.md`, EV-040, and a localhost unit regression test.
- Accepted: Accepted after grader and test runs.
- Manual changes: Human rubric judgments were applied manually by the AI-assisted development evaluator, not by an external study participant.
- Failure or surprise: Automated grading passed EV-040, while the human rubric marked it `NEEDS DISCUSSION` because localhost redaction harms debugging context.
- Resulting control: Updated `SPEC_FINAL.md` and `CHANGELOG.md` to document localhost redaction as a human-in-the-loop judgment call.

### 2026-08-13: Manual Test 2 follow-up

- Task: Continue the engineering loop from real manual Test 2 results.
- Instruction given: Fix IPv4 substring false positives, resolve loopback policy, investigate Linux home path username coverage, update graders/docs, and rerun all checks.
- What AI produced: `evals/manual_test_2.md`, new unit regressions, EV-041 through EV-047, sanitizer fixes, grader updates, and specification/changelog/design-decision updates.
- Accepted: Accepted after unit tests, full evals, graders, red-team, UI smoke, static checks, secret scan, hook, commit, and push passed.
- Manual changes: None outside the documented code and evidence patches.
- Failure or surprise: Local reproduction confirmed all three user-observed findings before code changes. The Linux `/home/` detector existed conceptually, but a leading word-boundary prevented matching paths that start with `/home/`.
- Resulting control: Complete-token IPv4 detection, loopback preservation policy, Linux home-path username tests/evals, and updated grader comparison.

### 2026-08-13: Manual Test 3 follow-up

- Task: Continue the engineering loop from real manual Test 3 results.
- Instruction given: Preserve prior evidence, keep `SPEC_v1.md` unchanged, investigate structured username coverage and version/IP false positives, update graders/docs, and rerun checks.
- What AI produced: `evals/manual_test_3.md`, new unit regressions, EV-048 through EV-057, structured username redaction, narrow version-field IPv4 preservation, grader updates, and specification/changelog/design-decision updates.
- Accepted: Accepted after unit tests, full evals, exact/property grader, red-team, UI smoke, static checks, and secret scan passed.
- Manual changes: None outside the documented code, test, eval, and evidence patches.
- Failure or surprise: Adding the structured `user=` policy intentionally changed the expected handling of JSON `"user":"sam"` in the password JSON test and RT-P02; it is now redacted as a username rather than preserved as harmless context.
- Resulting control: Explicit username-field tests/evals, arbitrary-name preservation tests/evals, version-field IPv4 false-positive tests/evals, and updated grader comparison for the F5 automated-vs-human disagreement.

### 2026-08-13: Manual Test 4 follow-up

- Task: Continue the engineering loop from real manual Test 4 results.
- Instruction given: Preserve prior evidence and `SPEC_v1.md`, fix prose version-like IPv4 false positive, review username marker consistency, add tests/evals, update docs/graders, and rerun checks.
- What AI produced: `evals/manual_test_4.md`, new unit regressions, EV-058 through EV-064, direct `Version`/`Release` prose context handling, current marker standardization on `[REDACTED_USERNAME]`, and spec/changelog/design/grader updates.
- Accepted: Accepted after unit tests, full evals, exact/property grader, red-team, UI smoke, static checks, secret scan, hook, commit, and push passed.
- Manual changes: None outside the documented code, test, eval, and evidence patches.
- Failure or surprise: `version:` and `release:` already preserved before the fix, but direct `Version 1.2.3.4` and `Release 1.2.3.4` did not. Current output also used two username markers for the same concept.
- Resulting control: Prose version-context regression tests/evals, non-version prose IP redaction tests/evals, and unified current username marker expectations.

### 2026-08-13: Manual Test 5 follow-up

- Task: Continue the engineering loop from real manual Test 5 results.
- Instruction given: Preserve prior evidence, keep `SPEC_v1.md` unchanged, fix the standalone IPv4 false negative before sentence punctuation, add tests/evals, update evidence, and freeze the core sanitizer after full regression success unless another high-severity privacy/security regression appears.
- What AI produced: `evals/manual_test_5.md`, unit regressions for sentence-ending IPv4 redaction and preservation guards, EV-065 through EV-071, exact/property grader coverage for EV-065, EV-069, and EV-071, and a narrow IPv4 token-boundary fix.
- Accepted: Accepted after focused unit tests, evals, and automated grader checks passed; final full-suite verification is recorded in `evals/results_final.md`.
- Manual changes: None outside the documented code, test, eval, and evidence patches.
- Failure or surprise: The IPv4 validator and policy were correct, but the regex boundary rejected IP candidates followed by any dot, so a normal sentence-ending period caused `192.168.20.50.` and `10.1.2.3.` to remain visible.
- Resulting control: Sentence-punctuation IPv4 unit tests, EV-065 and EV-066 privacy evals, EV-069 through EV-071 preservation guards, and a core sanitizer freeze after F7 unless a high-severity privacy/security regression is found.

### 2026-08-13: Manual Test 6 final methodology close-out

- Task: Complete the final SafePaste methodology pass after real manual Test 6 results.
- Instruction given: Treat the core sanitizer as frozen unless a high-severity privacy/security failure is found; record `Firmware 1.2.3.4 installed successfully.` as a known borderline limitation and human-vs-automated-grader disagreement rather than adding another keyword exception.
- What AI produced: `evals/manual_test_6.md`, EV-072, updated exact/property grader selection, human rubric judgment, grader comparison, design decision, red-team limitation note, final spec limitation clarification, README known limitation, presentation evidence, and final results refresh.
- Accepted: Accepted after complete unit tests, evals, exact/property grader, red-team, UI smoke, static/privacy scan, and secret scan were rerun.
- Manual changes: None outside the documented evidence and documentation patches.
- Failure or surprise: The automated grader passes the firmware case under current privacy behavior, while the human rubric marks it `NEEDS DISCUSSION` because it is likely firmware-version context.
- Resulting control: The firmware case is preserved as a known limitation and grader disagreement. No sanitizer feature change was made because this is not a high-severity privacy/security regression.

### 2026-08-13: Manual Test 7 product behavior and human-control evaluation

- Task: Record a successful manual evaluation of the IPv4 redaction toggle.
- Instruction given: Treat the core sanitizer as frozen, record Run A with IPv4 redaction on and Run B with IPv4 redaction off, and do not modify sanitizer behavior.
- What AI produced: `evals/manual_test_7.md`, human rubric rows for MT-7A and MT-7B, and presentation evidence documenting the toggle as a scoped human-control mechanism.
- Accepted: Accepted as a successful product-behavior and human-control evaluation; no sanitizer behavior changed.
- Manual changes: User performed Manual Test 7 and confirmed the observed behavior for both toggle settings.
- Failure or surprise: None. The toggle behaved as intended.
- Resulting control: The IPv4 toggle is documented as scoped to IP redaction only: disabling IPv4 protection preserves network IPs for diagnostic usefulness while unrelated email and credential rules continue to redact.

### 2026-08-13: Final completion mode

- Task: Complete every remaining Human-Centered AI project requirement and produce verifiable final evidence while the sanitizer is frozen.
- Instruction given: Verify product behavior, accessibility/human evaluation, automated and human graders, grader comparison, engineering history, final specs, changelog, harness, privacy/static review, secret scan, eval set, red-team report, design decisions, presentation evidence, README, and final completion report.
- What AI produced: `evals/run-product-behavior.js`, `evals/run-accessibility-checks.js`, `docs/PRODUCT_BEHAVIOR_REVIEW.md`, `docs/ACCESSIBILITY_REVIEW.md`, `docs/HARNESS_REVIEW.md`, `docs/FINAL_COMPLETION_REPORT.md`, README/harness/presentation/red-team/design/eval metadata updates, and refreshed final result artifacts.
- Accepted: Accepted after unit tests, evals, exact/property grader, red-team, UI smoke, product behavior checks, accessibility static checks, eval metadata validation, production static scans, production credential scan, whole-tree secret scan, and hook execution passed or were documented with rationale.
- Manual changes: Browser-only clipboard permission, tab-order traversal, and screen-reader behavior were not automated and are listed as NOT VERIFIED manual checks.
- Failure or surprise: Eval metadata validation initially needed to treat EV-023's empty input as intentional rather than missing. No high-severity privacy/security regression was found.
- Resulting control: Final completion report uses PASS/FAIL/NOT VERIFIED statuses and links to evidence files; no sanitizer behavior changed.

### 2026-08-13: Final UI integration from Claude visual reference

- Task: Port the approved Claude-generated SafePaste visual/UI direction into the current project while preserving the frozen tested sanitizer, evaluations, and history.
- Instruction given: Keep the dark developer/security visual language, amber accent, topbar, category chips, editor panes, line gutters, `sanitized.log`/`preview.log` views, visual redaction bars, status bar, keyboard shortcuts, local-only drag/drop, responsive behavior, and local-only invariants. Do not copy Claude's sanitizer regex implementation, Google Fonts, external resources, or changed redaction semantics.
- What AI produced: Updated `index.html`, `styles.css`, and `app.js` with the final UI shell. The UI still calls `src/sanitizer.js`; `sanitized.log` and Copy use stable plain-text markers, while `preview.log` renders safe redaction bars from already-sanitized output using node/text APIs.
- Documentation updated: `README.md`, `SPEC_FINAL.md`, `CHANGELOG.md`, `AI_WORKLOG.md`, `docs/DESIGN_DECISIONS.md`, `docs/PRESENTATION_EVIDENCE.md`, `docs/ACCESSIBILITY_REVIEW.md`, and `docs/FINAL_COMPLETION_REPORT.md`.
- Accepted verification at that pre-F8 point: unit tests `37/37`, evals `72/72`, exact/property grader `86/86`, red-team `15/15`, UI smoke PASS, product behavior `5/5`, accessibility static `10/10`, representative A-K regressions `11/11`, responsive static checks `4/4`, production privacy/resource scan PASS, and production secret scan PASS.
- Manual changes: None by the user during this integration step.
- Failure or surprise: Two ad-hoc A-K regression command attempts failed before Node executed because PowerShell quoting corrupted the inline script; the third command executed and passed `11/11`. Browser-control setup executed but returned no readable page state, so real viewport rendering, keyboard traversal, clipboard permission, and screen-reader behavior remain NOT VERIFIED manual checks.
- Resulting control: The final UI integration is documented as visual/presentation work only. No sanitizer feature changes were made, no `SPEC_v1.md` or historical results were modified, and no external runtime resources were introduced.

### 2026-08-13: Final UI readability palette refinement

- Task: Refine the final SafePaste UI because the full dark background was difficult to see.
- Instruction given: Do not change product logic, sanitizer behavior, layout logic, tests, or evaluation logic; improve the color scheme and visual identity.
- What AI produced: Replaced the full-dark palette in `styles.css` with a brighter high-contrast developer/security palette: light page background, white workspace, pale editor surfaces, slate text, restrained category colors, green privacy indicators, and amber primary action.
- Documentation updated: `README.md`, `CHANGELOG.md`, `AI_WORKLOG.md`, `docs/DESIGN_DECISIONS.md`, `docs/PRESENTATION_EVIDENCE.md`, `docs/FINAL_COMPLETION_REPORT.md`, and `docs/SCREENSHOTS_NEEDED.md`.
- Accepted verification: UI smoke PASS, product behavior `5/5`, accessibility static `10/10`, production privacy/resource scan PASS, and local server HTTP 200.
- Manual changes: User identified the readability issue from visual review.
- Failure or surprise: None in executed checks. Real browser viewport inspection remains NOT VERIFIED for the same browser-tool limitation documented in the UI integration step.
- Resulting control: The UI remains visually polished and security-oriented but no longer relies on a complete dark background for identity.

### 2026-08-13: Final UI middle-ground palette refinement

- Task: Refine the SafePaste UI again after manual review found that both the full dark and bright white directions were not good.
- Instruction given: Keep product logic, sanitizer behavior, layout logic, tests, and evaluation logic unchanged; adjust visual design only.
- What AI produced: Updated `styles.css` from bright white/light surfaces to a muted slate/blue-gray palette that avoids both black and white extremes.
- Documentation updated: `README.md`, `CHANGELOG.md`, `AI_WORKLOG.md`, `docs/DESIGN_DECISIONS.md`, `docs/PRESENTATION_EVIDENCE.md`, `docs/FINAL_COMPLETION_REPORT.md`, and `docs/SCREENSHOTS_NEEDED.md`.
- Accepted verification: UI smoke PASS, product behavior `5/5`, accessibility static `10/10`, production privacy/resource scan PASS, and local server HTTP 200.
- Manual changes: User provided visual feedback that both black and white extremes were uncomfortable.
- Failure or surprise: None in executed checks.
- Resulting control: Current UI uses a middle-ground slate security-console identity with readable logs and less glare.

### 2026-08-13: Final regression F8 structured secret field

- Task: Fix one high-severity privacy failure found in final regression testing while preserving all other sanitizer behavior.
- Observed input: `secret=FakeSecretValue987`.
- Observed output before fix: `secret=FakeSecretValue987`.
- Expected output: `secret=[REDACTED_SECRET]`.
- Instruction given: Record the real failure, add a regression test before fixing, extend credential handling narrowly for explicit `secret` fields, do not add broad arbitrary-secret guessing, and do not modify IPv4, version, username, path, firmware limitation, or UI behavior.
- Pre-fix evidence: Added the unit test `redacts explicit structured secret fields`; `node tests/test-sanitizer.js` then failed with `37/38 tests passed` and `structured secret: secret should be removed`. Added EV-073; `node evals/run-evals.js` then failed with `72/73` passed and failure ID EV-073.
- What AI produced: Added `REDACTION_LABELS.SECRET`, one explicit structured `secret` field rule in `src/sanitizer.js`, unit coverage for `secret=`, `secret:`, and JSON `"secret"`, EV-073, exact/property grader coverage, and `evals/manual_test_8.md`.
- Accepted verification: Unit tests `38/38`, evals `73/73`, exact/property grader `91/91`, and requested regression sweep `6/6`.
- Manual changes: User provided the final regression failure and expected policy.
- Failure or surprise: None after the narrow fix. The failing pre-fix unit/eval evidence is preserved.
- Resulting control: Explicit `secret` fields are now protected with `[REDACTED_SECRET]` while broad secret guessing remains out of scope.

## Most Important AI Failures

### Initial sanitizer missed quoted JSON credential keys

AI behavior
-> The first sanitizer implementation handled unquoted credential keys but missed quoted JSON keys.

Why it was problematic
-> JSON logs and config snippets are common, and missing those values could leak credentials.

How it was detected
-> Unit tests failed 2 cases, evals failed EV-004 and EV-005, red-team failed RT-P02, and the security reviewer reported SR-001.

Human response
-> Preserve the failing evidence before fixing.

Permanent control added
-> JSON credential tests and eval cases remain in the suite.

### Initial hook depended on unavailable `grep`

AI behavior
-> The pre-commit hook used `grep` without verifying the command existed.

Why it was problematic
-> Manual invocation in this environment printed `grep: command not found` and exited successfully, giving a false sense of protection.

How it was detected
-> Running `sh SafePaste/.claude/hooks/pre-commit.sh` against staged files.

Human response
-> Preserve the failure in v1 results before fixing.

Permanent control added
-> Hook updated to use `git grep`; a later `mktemp` portability failure was also fixed with a pipe/read loop.

### Intermediate hook fix depended on unavailable `mktemp`

AI behavior
-> The first final hook hardening used `mktemp` to handle filenames safely.

Why it was problematic
-> Manual hook verification printed `mktemp: command not found` and exited with failure.

How it was detected
-> Running the hook against a staged file named `SafePaste/src/hook path smoke.js`.

Human response
-> Remove the temporary file and patch the hook again.

Permanent control added
-> Hook now uses `git diff --name-only | while IFS= read -r file` with explicit status handling.

### Automated and human graders disagreed on localhost

AI behavior
-> The automated property grader treated `Localhost: 127.0.0.1` as a successful default IP redaction.

Why it was problematic
-> A human rubric found that redacting localhost can damage diagnostic usefulness even when privacy/security properties pass.

How it was detected
-> Session 7 grader comparison across EV-040.

Human response
-> Manual Test 2 adopted a policy change: preserve IPv4 loopback addresses in `127.0.0.0/8`.

Permanent control added
-> EV-040, loopback preservation tests, `human-rubric.md`, `grader-comparison.md`, and a `SPEC_FINAL.md` refinement that preserves `127.0.0.0/8`.

### IPv4 detector redacted substrings inside larger dotted numeric sequences

AI behavior
-> The IPv4 regex matched `1.2.3.4` inside `1.2.3.4.5`.

Why it was problematic
-> It created a false positive and produced confusing output: `[REDACTED_IP_ADDRESS].5`.

How it was detected
-> Manual Test 2 F1 and local reproduction.

Human response
-> Add a regression test and eval before fixing.

Permanent control added
-> Complete-token IPv4 detection plus EV-041.

### Linux home path usernames were not redacted

AI behavior
-> The path detector did not redact `/home/usman/...` because its leading boundary prevented matching a path starting with `/home/`.

Why it was problematic
-> The accepted path policy covers reasonably detectable local home-directory usernames.

How it was detected
-> Manual Test 2 F3 and local reproduction.

Human response
-> Add Linux home-path and non-home-path regression tests before fixing.

Permanent control added
-> Linux home-path username redaction plus EV-044 through EV-047.

### Structured username fields remained visible

AI behavior
-> The sanitizer preserved `username=musman24`, `user_name=alice_dev`, and `user=bob-admin`.

Why it was problematic
-> Explicit account identifiers have a strong privacy signal and can identify the person whose data appears in logs.

How it was detected
-> Manual Test 3 F4 and local reproduction.

Human response
-> Treat `SPEC_v1.md` as ambiguous, resolve the final policy in `SPEC_FINAL.md`, and add failing tests/evals before fixing.

Permanent control added
-> Structured username unit tests plus EV-048 and EV-049, with EV-050 and EV-051 preserving arbitrary names.

### Version fields were over-redacted as IP addresses

AI behavior
-> The sanitizer redacted `release=1.2.3.4` as an IP address.

Why it was problematic
-> The automated syntactic redaction looked privacy-protective, but human review found it removed useful software version context.

How it was detected
-> Manual Test 3 F5, local reproduction, and the grader-disagreement analysis.

Human response
-> Preserve IPv4-shaped values only in narrow version-related fields; continue redacting explicit IP fields.

Permanent control added
-> Version-field unit tests plus EV-052 through EV-057.

### Prose release/version context was over-redacted as an IP address

AI behavior
-> The sanitizer redacted `Release 1.2.3.4 passed QA yesterday.` as an IP address.

Why it was problematic
-> Automated syntactic IP redaction looked privacy-protective, but human review found it removed obvious release-version context.

How it was detected
-> Manual Test 4 F6 and local reproduction.

Human response
-> Extend the existing version-context policy only to direct `Version` and `Release` prose associations, without broad NLP or disabling IP redaction.

Permanent control added
-> Prose version-context unit tests plus EV-058 through EV-064.

### Standalone IPv4 addresses before sentence periods were not redacted

AI behavior
-> The sanitizer preserved `Connection received from 192.168.20.50.` because the IPv4 regex rejected candidates followed by any dot.

Why it was problematic
-> The value was a valid standalone non-loopback IPv4 address in normal network prose, so leaving it visible was a privacy/security false negative.

How it was detected
-> Manual Test 5 F7 and local reproduction, then a failing unit regression and failing evals EV-065 and EV-066 before the production fix.

Human response
-> Treat this as an implementation bug against the existing final policy, not a new specification ambiguity; add failing tests/evals before changing `src/sanitizer.js`.

Permanent control added
-> IPv4 sentence-punctuation boundary tests plus EV-065 through EV-071.

### Ambiguous firmware version context is over-redacted

AI behavior
-> The frozen sanitizer redacts `Firmware 1.2.3.4 installed successfully.` as an IP address.

Why it was problematic
-> A human evaluator may reasonably interpret `1.2.3.4` as firmware version context, so redaction can reduce diagnostic usefulness.

How it was detected
-> Manual Test 6 and local reproduction.

Human response
-> Record the case as a known limitation and human-vs-automated-grader disagreement; do not add a speculative keyword exception.

Permanent control added
-> EV-072, `manual_test_6.md`, human rubric and grader-comparison entries, and a documented sanitizer freeze unless a high-severity privacy/security regression is found.

### Username replacement labels were inconsistent

AI behavior
-> The sanitizer used `[REDACTED_USER]` in home paths and `[REDACTED_USERNAME]` in structured username fields.

Why it was problematic
-> The two labels represented the same conceptual category, which made current product output and grading evidence less consistent.

How it was detected
-> Manual Test 4 consistency review and local reproduction.

Human response
-> Standardize current product, tests, evals, and live docs on `[REDACTED_USERNAME]`.

Permanent control added
-> Updated path username tests/evals and documented that historical evidence files preserve prior observed labels.
