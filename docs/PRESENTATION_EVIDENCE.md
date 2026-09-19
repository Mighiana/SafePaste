# Presentation Evidence

## 1. Project: what and for whom

Final one-line description:
SafePaste is a local-only browser log sanitizer that helps technical users redact likely sensitive values before sharing logs.

Intended users:
Developers, IT support engineers, technical students, security/compliance reviewers, data subjects appearing in logs, and support recipients.

Screenshot recommendation:
Capture the final muted slate developer/security UI with a mixed log, `sanitized.log`, `preview.log`, category chips, redaction count, and IPv4 toggle visible.

## 2. Stakeholders and conflicts

| Stakeholder | Main wants | Main fears |
| --- | --- | --- |
| Developer / IT support engineer | Fast useful sanitization, readable logs | Over-redaction and lost debugging details |
| Person whose data appears in logs | Privacy and credential protection | Emails, IPs, usernames, and tokens leaking |
| Security / compliance team | Aggressive, predictable local redaction | False negatives and unsafe implementation |
| Support recipient | Enough context to solve the issue | Logs made useless by excessive redaction |

Two main conflicts:

- Privacy vs diagnostic usefulness.
- Detection sensitivity vs false positives.

Decisions caused by those conflicts:

- Non-loopback IPv4 addresses are redacted by default but can be preserved by user choice.
- Loopback IPv4 addresses are preserved after Manual Test 2 showed localhost redaction harmed diagnostic usefulness.
- Manual Test 7 confirmed the IPv4 toggle is scoped correctly: turning IPv4 redaction off preserves network IPs for diagnostics while unrelated email and credential redaction still works.
- IPv4-shaped values in narrow version fields are preserved after Manual Test 3 showed release context was over-redacted.
- Direct prose version contexts are preserved after Manual Test 4 showed `Release 1.2.3.4` was over-redacted.
- Explicit structured username fields are redacted while arbitrary names in prose are preserved.
- Current username replacement markers are standardized on `[REDACTED_USERNAME]`.
- Generic secrets require credential-like key context.
- `PWD` path values are preserved because security review showed they were false positives.

## 3. Spec v1 -> final + changelog

| Change | Trigger | Changelog entry | Supporting evidence |
| --- | --- | --- | --- |
| Quoted JSON credential keys became explicit scope | Unit tests, EV-004, EV-005, RT-P02, SR-001 | v1.1 | `tests/test-sanitizer.js`, `evals/results_v1.md`, `RED_TEAM.md` |
| Basic and Token Authorization headers added | Security review SR-002 | v1.2 | EV-037, EV-038 |
| `PWD` removed from password aliases | Security review SR-003 | v1.3 | EV-039 |
| Static privacy scan changed from hardcoded list to recursive production scan | Security review SR-004 | v1.4 | `evals/run-evals.js` |
| Hook moved away from `grep` and fixed temp file | Manual hook failure and SR-005 | v1.5 | `evals/results_v1.md`, `.claude/hooks/pre-commit.sh` |
| External-resource scan expanded across production files | Final security review | v1.6 | `evals/run-evals.js`, `evals/results_final.md` |
| Hook path loop made space-safe without `mktemp` | Final hook smoke test | v1.7 | `AI_WORKLOG.md`, `.claude/hooks/pre-commit.sh` |
| Grader methodology added and localhost disagreement recorded | Session 7 requirement | v1.8 | `evals/graders/grader-comparison.md` |
| IPv4 token boundary fixed | Manual Test 2 F1 | v1.9 | `evals/manual_test_2.md`, EV-041 |
| Loopback addresses preserved | Manual Test 2 F2 and grader disagreement | v1.10 | EV-040, EV-042, EV-043 |
| Linux home usernames redacted narrowly | Manual Test 2 F3 | v1.11 | EV-044 through EV-047 |
| Structured username fields redacted | Manual Test 3 F4 | v1.12 | `evals/manual_test_3.md`, EV-048 through EV-051 |
| Version-field IPv4-shaped values preserved | Manual Test 3 F5 and grader disagreement | v1.13 | EV-052 through EV-057 |
| Prose version IPv4-shaped values preserved | Manual Test 4 F6 and grader disagreement | v1.14 | `evals/manual_test_4.md`, EV-058 through EV-064 |
| Username marker standardized | Manual Test 4 consistency review | v1.15 | EV-029, EV-044, EV-045 |
| Sentence-final standalone IPv4 redaction fixed | Manual Test 5 F7 | v1.16 | `evals/manual_test_5.md`, EV-065 through EV-071 |
| Firmware-version limitation documented without sanitizer change | Manual Test 6 grader disagreement | v1.17 | `evals/manual_test_6.md`, EV-072 |
| IPv4 toggle scoped human control confirmed | Manual Test 7 successful product-behavior evaluation | No product/spec change | `evals/manual_test_7.md`, `evals/graders/human-rubric.md` |
| Final completion evidence added | Final completion gate | v1.18 | `docs/FINAL_COMPLETION_REPORT.md`, `docs/ACCESSIBILITY_REVIEW.md`, `docs/PRODUCT_BEHAVIOR_REVIEW.md`, `docs/HARNESS_REVIEW.md` |
| Final Claude-reference UI shell integrated | Final UI integration request | v1.19 | `index.html`, `styles.css`, `app.js`, `CHANGELOG.md`, `docs/DESIGN_DECISIONS.md` |
| Full-dark UI palette lightened for readability | Manual visual review | v1.20 | `styles.css`, `CHANGELOG.md`, `AI_WORKLOG.md`, `docs/DESIGN_DECISIONS.md` |
| Bright white UI palette softened to muted slate | Manual visual review | v1.21 | `styles.css`, `CHANGELOG.md`, `AI_WORKLOG.md`, `docs/DESIGN_DECISIONS.md` |
| Explicit structured `secret` fields redacted | Final regression F8 | v1.22 | `evals/manual_test_8.md`, EV-073, `tests/test-sanitizer.js` |

## 4. Harness components and why

| Component | Location in repository | Purpose | Concrete example where it mattered |
| --- | --- | --- | --- |
| Persistent instruction file | `AGENTS.md` | Repeatedly tells AI agents the architecture and privacy rules | Prevented adding dependencies or network services during implementation |
| Security-review sub-agent | `.claude/agents/security-reviewer.md` | Reviews code for privacy and security regressions | Found Basic/Token Authorization gaps and `PWD` false positives |
| Hook | `.claude/hooks/pre-commit.sh` | Lightweight staged secret scan | Manual invocation exposed a portability failure that was fixed |
| Permission policy | `.claude/settings.json` | Documents approval boundaries | Keeps dependency/network/destructive actions explicit |
| Evaluation runners | `evals/run-evals.js`, `evals/run-red-team.js`, `evals/run-ui-smoke.js` | Tie behavior to spec requirements and adversarial checks | Preserved v1 failures and verified final fixes |
| Product behavior harness | `evals/run-product-behavior.js` | Verifies empty input, clear, copy, IPv4 toggle, and large multiline behavior | Manual Test 7 and final completion mode required product workflow evidence |
| Accessibility checker | `evals/run-accessibility-checks.js` | Automates label, semantic HTML, focus CSS, live-region, and text-state checks | Final completion mode required accessibility evidence |

Full harness review:
`docs/HARNESS_REVIEW.md`

## 5. Evals and results

V1 result:
34/36 eval cases passed. EV-004 and EV-005 failed because quoted JSON credential keys were not redacted.

Final result:
73/73 eval cases passed after the final F8 structured-secret fix.

Final product behavior:
5/5 product behavior checks passed in `evals/run-product-behavior.js`; see `docs/PRODUCT_BEHAVIOR_REVIEW.md`.

Final accessibility review:
10/10 automated static accessibility checks passed in `evals/run-accessibility-checks.js`; browser keyboard traversal, logical tab order, real viewport rendering, OS clipboard permission, and screen-reader announcement quality remain NOT VERIFIED pending a human browser/assistive-technology pass. Static responsive CSS checks passed 4/4. See `docs/ACCESSIBILITY_REVIEW.md`.

Final UI integration result:
Claude visual features retained where practical: developer/security visual language, subtle radial glows, amber primary accent, category accent colors, compact topbar, Local Only and No Network Egress messaging, privacy review workspace, toolbar chips, editor panes, line gutters, `original.log`/`sanitized.log`/`preview.log` style tabs, visual redaction bars, status bar, review summary, keyboard shortcuts, local-only text-file drop, and responsive CSS. The final palette uses muted slate/blue-gray surfaces after manual review found both full-dark and bright-white directions uncomfortable.

Sanitizer preservation result:
The Claude sanitizer implementation was not copied. The final UI calls the existing tested `src/sanitizer.js`, Copy uses the sanitized plain-text textarea value, and production scans found no network APIs, storage APIs, external URLs/fonts/imports, `innerHTML`, or production credential-looking values.

Representative final UI regression sweep:
11/11 passed for larger dotted sequence preservation, loopback preservation, standalone IPv4 redaction, prose version preservation, structured username redaction, Windows/Linux home username redaction, system path preservation, IPv4-off scoped behavior, and HTML-like literal sanitizer output.

Session 7 grader result:

- Automated exact/property grader: 21 cases, 91/91 property checks passed.
- Human rubric: 20 current eval cases plus 2 Manual Test 7 control runs graded; 21 PASS and 1 NEEDS DISCUSSION for EV-072. Preserved before-refinement judgments include EV-040 NEEDS DISCUSSION, EV-048 FAIL, EV-052 FAIL, EV-058 FAIL, and EV-065 FAIL.
- Disagreements: EV-040 originally passed automated IP redaction but needed human discussion for diagnostic usefulness; Manual Test 2 refined the spec to preserve `127.0.0.0/8`. EV-052 exposed a Manual Test 3 syntactic-IP vs version-context disagreement; Manual Test 4 extended that same issue to direct prose `Release`/`Version` contexts. Manual Test 5 F7 was not a grader disagreement after adding the correct property: both graders failed the visible standalone IPv4 address before the fix. Manual Test 6 EV-072 is a current disagreement: automated privacy grading passes `Firmware 1.2.3.4...` redaction, while human review marks it `NEEDS DISCUSSION`. Final regression F8 was not a grader disagreement: the structured secret remained visible, and both unit/eval property checks failed before the narrow fix.

Most interesting failures:

- JSON credentials in `"password"` and `"apiKey"` forms remained visible in v1.
- Basic and Token Authorization headers were missed by security review.
- `PWD=/workspace/project` was over-redacted in v1.
- The first hook version used unavailable `grep` and exited successfully without scanning.
- Manual Test 2 F1: `1.2.3.4.5` became `[REDACTED_IP_ADDRESS].5`.
- Manual Test 2 F3: `/home/usman/...` did not redact the username.
- Manual Test 3 F4: `username=musman24`, `user_name=alice_dev`, and `user=bob-admin` remained visible.
- Manual Test 3 F5: `release=1.2.3.4` became `release=[REDACTED_IP_ADDRESS]`.
- Manual Test 4 F6: `Release 1.2.3.4 passed QA yesterday.` became `Release [REDACTED_IP_ADDRESS] passed QA yesterday.`
- Manual Test 4 consistency review: current product used both `[REDACTED_USER]` and `[REDACTED_USERNAME]` for username redaction.
- Manual Test 5 F7: `Connection received from 192.168.20.50.` remained unchanged because a sentence-ending period blocked IPv4 token matching.
- Manual Test 6 limitation: `Firmware 1.2.3.4 installed successfully.` is redacted, although human review considers it likely firmware-version context.
- Manual Test 7 success: IPv4 redaction off preserved network IPs, while email and credential redaction continued to work.
- Final regression F8: `secret=FakeSecretValue987` remained visible before the fix and now redacts to `secret=[REDACTED_SECRET]`.

Categories tested:
API keys, explicit structured secret fields, passwords, emails, structured usernames, valid and invalid IPv4 addresses, loopback IPv4, dotted numeric false positives, version-field and prose-version IPv4-shaped values, sentence-final IPv4 punctuation, hostname-embedded IPv4-shaped values, known borderline firmware-version limitation, explicit IP fields, non-version prose IP addresses, scoped IPv4 toggle behavior, Authorization headers, Bearer tokens, JWTs, AWS-style keys, Slack-style tokens, false positives, paths/usernames, Linux home paths, Unicode, multiline logs, HTML-like input, static privacy checks, and accessibility/usability checks.

Representative eval cases:
EV-004, EV-005, EV-013, EV-026, EV-037, EV-038, EV-039, EV-040, EV-041, EV-044, EV-046, EV-048, EV-050, EV-052, EV-055, EV-058, EV-062, EV-065, EV-069, EV-071, EV-072, and EV-073.

## 5a. Graders and the human in the loop

| Grader | Location | Why chosen | Cases graded | Result |
| --- | --- | --- | --- | --- |
| Automated exact/property grader | `evals/graders/exact-property-grader.js` | SafePaste sanitizer behavior is deterministic and can be checked by properties without sending data anywhere. | 21 | 91/91 property checks passed |
| Human rubric | `evals/graders/human-rubric.md` | Diagnostic usefulness, readability, proportionality, shareability, and human-control trade-offs require judgment. | 20 current eval cases plus 2 Manual Test 7 control runs and preserved before/after evidence | 21 PASS, 1 NEEDS DISCUSSION for EV-072; before-refinement EV-040 remains NEEDS DISCUSSION, EV-048 FAIL, EV-052 FAIL, EV-058 FAIL, and EV-065 FAIL |

Model-as-judge was not used because an external LLM API would conflict with SafePaste's local-only privacy architecture.

## 6. Honest AI/product failures and responses

Failure:
Quoted JSON credential keys were not redacted.

Detection:
Unit tests, EV-004, EV-005, RT-P02, and SR-001.

Response:
Credential regexes were updated to support quoted JSON keys and camelCase keys.

Permanent engineering control:
JSON credential unit tests and eval cases remain in the suite.

Failure:
Basic and Token Authorization headers were missed.

Detection:
Security-review finding SR-002.

Response:
Authorization header detection was broadened to common schemes.

Permanent engineering control:
Unit tests and evals EV-037/EV-038.

Failure:
`PWD` path values were over-redacted.

Detection:
Security-review finding SR-003.

Response:
Removed `pwd` from password aliases.

Permanent engineering control:
Unit test and EV-039.

Failure:
The v1 pre-commit hook relied on unavailable `grep`.

Detection:
Manual hook invocation before the v1 commit.

Response:
Hook now uses `git grep` and avoids a fixed temp output file.

Permanent engineering control:
Hook portability is documented in `CHANGELOG.md` and v1 results.

Failure:
The first final hook hardening relied on unavailable `mktemp`.

Detection:
Manual hook test with staged file `SafePaste/src/hook path smoke.js`.

Response:
Removed the temporary file and rewrote the hook loop without `mktemp`.

Permanent engineering control:
Hook now uses a `read -r` loop and was rerun successfully against a staged path containing a space.

Failure:
IPv4 substring false positive.

Detection:
Manual Test 2 F1 and local reproduction showed `1.2.3.4.5` became `[REDACTED_IP_ADDRESS].5`.

Response:
IPv4 detector now requires complete IPv4 tokens.

Permanent engineering control:
Unit test plus EV-041.

Failure:
Linux home path username was not redacted.

Detection:
Manual Test 2 F3 and local reproduction showed `/home/usman/projects/safepaste/server.log` remained unchanged.

Response:
Path detector now redacts only the username segment for `/home/name/...`.

Permanent engineering control:
Unit tests plus EV-044 through EV-047.

Failure:
Structured username fields remained visible.

Detection:
Manual Test 3 F4 and local reproduction showed `username=musman24`, `user_name=alice_dev`, and `user=bob-admin` were unchanged.

Response:
Added a narrow structured username detector for explicit account fields and quoted JSON equivalents.

Permanent engineering control:
Unit tests plus EV-048 through EV-051.

Failure:
Version-field value was over-redacted as an IP address.

Detection:
Manual Test 3 F5 and grader comparison showed `release=1.2.3.4` became `release=[REDACTED_IP_ADDRESS]`.

Response:
Added a narrow version-field context exception while keeping `client_ip=` and `server_ip=` redaction.

Permanent engineering control:
Unit tests plus EV-052 through EV-057.

Failure:
Prose release/version context was over-redacted as an IP address.

Detection:
Manual Test 4 F6 and local reproduction showed `Release 1.2.3.4 passed QA yesterday.` became `Release [REDACTED_IP_ADDRESS] passed QA yesterday.`

Response:
Extended the narrow version-context exception to direct `Version` and `Release` prose associations.

Permanent engineering control:
Unit tests plus EV-058 through EV-064.

Failure:
Standalone IPv4 before sentence punctuation was not redacted.

Detection:
Manual Test 5 F7 and local reproduction showed `Connection received from 192.168.20.50.` remained unchanged.

Response:
IPv4 token-boundary handling now treats sentence-ending periods as punctuation while preserving larger dotted numeric sequences and hostname-embedded values.

Permanent engineering control:
Unit tests plus EV-065 through EV-071.

Known limitation:
Firmware-version context can be over-redacted.

Detection:
Manual Test 6 showed `Firmware 1.2.3.4 installed successfully.` became `Firmware [REDACTED_IP_ADDRESS] installed successfully.`

Response:
No sanitizer change was made. The case was documented as a current automated-vs-human grader disagreement.

Permanent engineering control:
EV-072, `manual_test_6.md`, `human-rubric.md`, and `grader-comparison.md`.

Successful control evaluation:
IPv4 toggle is scoped correctly.

Detection:
Manual Test 7 Run A confirmed network IPv4 redaction on; Run B confirmed network IPv4 preservation when the toggle is off.

Response:
No sanitizer behavior change was made.

Permanent engineering control:
`manual_test_7.md` and human rubric rows MT-7A/MT-7B.

Failure:
Explicit structured `secret` field remained visible.

Detection:
Final regression F8 showed `secret=FakeSecretValue987` remained unchanged. The new unit regression failed before the fix with `37/38 tests passed`; EV-073 failed before the fix with `72/73` eval cases passed.

Response:
Added a narrow `SECRET` category and `[REDACTED_SECRET]` marker for explicit `secret=value`, `secret: value`, and JSON `"secret":"value"` forms only.

Permanent engineering control:
Unit test coverage, EV-073, exact/property grader coverage, and `evals/manual_test_8.md`.

Consistency finding:
Username replacement labels were inconsistent.

Detection:
Manual Test 4 review showed home-path usernames used `[REDACTED_USER]` while structured username fields used `[REDACTED_USERNAME]`.

Response:
Current product output, tests, evals, and live docs now standardize on `[REDACTED_USERNAME]`.

Permanent engineering control:
Updated path username tests/evals while preserving historical evidence files unchanged.
