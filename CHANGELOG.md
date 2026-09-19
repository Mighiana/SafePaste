# Changelog

All meaningful changes must describe what changed, why it changed, stakeholder impact, and mapped requirement.

## v0.1

Changed:
Created the preserved stakeholder map, `SPEC_v1.md`, README skeleton, `AGENTS.md`, and initial worklog.

Why:
The project requires specification-first development and traceable stakeholder analysis before product implementation.

Stakeholder impact:
Clarifies privacy, diagnostic usefulness, compliance, and support-recipient trade-offs before implementation choices are made.

Mapped requirement:
Methodology phase 0 and phase 1.

## v1.0

Changed:
Implemented the first local-only SafePaste UI, isolated sanitizer, unit tests, eval runner, 36-case eval set, red-team runner, and v1 results.

Why:
The project needed a smallest complete browser implementation before meaningful testing and iteration could happen.

Stakeholder impact:
Gave developers a usable review flow while giving security and privacy stakeholders concrete behavior to evaluate.

Mapped requirement:
R1-R15, PS1-PS10, A1-A6.

Known v1 failures:
Unit tests and evals showed that quoted JSON credential keys were not redacted. The security reviewer also found Basic/Token Authorization header gaps, `PWD` false positives, narrow static scan coverage, and a portability issue in the pre-commit hook.

## v1.1

Changed:
Credential rules now redact quoted JSON keys such as `"password":"..."`, `"apiKey":"..."`, and `"client_secret":"..."`.

Why:
Unit tests failed `redacts password JSON` and `redacts API key JSON`; evals failed EV-004 and EV-005; red-team case RT-P02 failed.

Stakeholder impact:
Improves protection for people whose data appears in JSON logs and addresses security/compliance concerns about common credential formats.

Mapped requirement:
R5, R12.

## v1.2

Changed:
Authorization header detection now redacts Basic and Token schemes in addition to Bearer and bare long header values.

Why:
Security-review finding SR-002 showed that `Authorization: Basic ...` and `Authorization: Token ...` could remain visible.

Stakeholder impact:
Reduces credential leak risk for security/compliance stakeholders and data subjects.

Mapped requirement:
R5.

## v1.3

Changed:
Removed `pwd` from broad password aliases and added a regression test/eval for `PWD=/workspace/project`.

Why:
Security-review finding SR-003 showed that `PWD` path values were redacted as passwords, harming diagnostic usefulness.

Stakeholder impact:
Improves developer trust and support-recipient usefulness while still redacting `password` and `passwd` keys.

Mapped requirement:
R12, R14.

## v1.4

Changed:
Static privacy evals now discover production `.html`, `.css`, and `.js` files recursively while excluding docs, tests, evals, history, and harness metadata.

Why:
Security-review finding SR-004 showed that a hardcoded production-file list could miss future source files.

Stakeholder impact:
Improves security/compliance confidence that privacy invariants remain checked as the project grows.

Mapped requirement:
PS1-PS4, AI1, AI2, AI6.

## v1.5

Changed:
The pre-commit hook now uses `git grep` against staged SafePaste production/harness files and no longer writes matches to a fixed temp file.

Why:
Manual hook invocation found `grep: command not found` with exit status 0, and security-review finding SR-005 identified fixed-temp-file risk.

Stakeholder impact:
Makes the harness more portable and avoids leaving possible secret matches in a shared predictable temp path.

Mapped requirement:
PS5 and harness component 3.

## v1.6

Changed:
External-resource eval scanning now checks all production `.html`, `.css`, and `.js` files, not only `index.html`.

Why:
Final security-review finding showed EV-032 could miss a future external URL in CSS or another production script.

Stakeholder impact:
Improves security/compliance confidence that no remote scripts, fonts, imports, or CDN references are introduced.

Mapped requirement:
PS3, AI1.

## v1.7

Changed:
The pre-commit hook now handles staged file paths with spaces using a `read -r` loop and no longer depends on `mktemp`.

Why:
Final hook testing with a staged file named `hook path smoke.js` showed that `mktemp` was unavailable in this environment.

Stakeholder impact:
Improves hook portability and reduces the chance that a staged file is skipped because of whitespace in its path.

Mapped requirement:
PS5 and harness component 3.

## v1.8

Changed:
Added Session 7 grader methodology with an automated exact/property grader, a human rubric, a grader comparison, EV-040 for localhost, and a localhost unit regression test.

Why:
The grader comparison showed that automated IP redaction can pass while human diagnostic-usefulness judgment still needs discussion for `Localhost: 127.0.0.1`.

Stakeholder impact:
Makes the privacy vs diagnostic usefulness conflict more visible for developers, support recipients, and security reviewers without changing SafePaste's default local-only redaction behavior.

Mapped requirement:
R6, R10, R12, Human-Centered AI Session 7.

## v1.9

Changed:
IPv4 detection now requires complete IPv4 tokens and preserves larger dotted numeric sequences such as `1.2.3.4.5`.

Why:
Manual Test 2 F1 showed that the previous detector redacted a valid-looking four-octet substring inside a larger dotted numeric sequence, producing `[REDACTED_IP_ADDRESS].5`.

Stakeholder impact:
Improves developer trust and diagnostic usefulness by reducing false-positive redaction.

Mapped requirement:
R6, R12, R14.

## v1.10

Changed:
IPv4 loopback addresses in `127.0.0.0/8` are now preserved by default while other valid IPv4 addresses remain redacted when IPv4 redaction is enabled.

Why:
Manual Test 2 F2 and the grader comparison showed a real stakeholder/specification conflict: automated privacy grading considered localhost redaction successful, while human diagnostic-usefulness grading considered it unnecessarily destructive.

Stakeholder impact:
Improves troubleshooting usefulness for developers and support recipients while retaining privacy defaults for non-loopback IPv4 addresses.

Mapped requirement:
R6, R10, R12.

## v1.11

Changed:
Linux home-directory usernames in `/home/name/...` are now redacted by replacing only the username segment; non-home paths such as `/var/log/nginx/error.log` and `/usr/local/bin` remain unchanged.

Why:
Manual Test 2 F3 showed `/home/usman/projects/safepaste/server.log` remained visible even though the accepted username/path policy covers reasonably detectable local home paths.

Stakeholder impact:
Improves privacy for people whose local usernames appear in logs while preserving diagnostic path context for support recipients.

Mapped requirement:
R13, R12, R14.

## v1.12

Changed:
Explicit structured username fields now redact account-like values using `[REDACTED_USERNAME]`. Covered forms include `username=`, `user_name=`, `user-name=`, `user=`, and quoted JSON equivalents such as `"username":"..."` and `"user":"..."`.

Why:
Manual Test 3 F4 showed structured usernames remained visible. `SPEC_v1.md` allowed username redaction when reasonably detectable but did not clearly require these structured fields, so the ambiguity was resolved in `SPEC_FINAL.md`.

Stakeholder impact:
Improves privacy for people whose account identifiers appear in logs while preserving arbitrary names in `name=` fields and prose to avoid excessive false positives.

Mapped requirement:
R13, R12, R14.

## v1.13

Changed:
IPv4-shaped values are now preserved when they are clearly values of narrow version-related fields such as `release=`, `version=`, `app_version=`, and `software_version=`.

Why:
Manual Test 3 F5 showed `release=1.2.3.4` was redacted as an IP address even though human evaluation judged it to be useful version context. The automated syntactic interpretation and human usefulness judgment disagreed, exposing a specification gap.

Stakeholder impact:
Improves diagnostic usefulness for developers and support recipients while preserving privacy protection for explicit IP fields such as `client_ip=10.20.30.40` and `server_ip=8.8.8.8`.

Mapped requirement:
R6, R12, R14.

## v1.14

Changed:
IPv4-shaped values are now preserved when directly associated with strong prose version keywords, such as `Version 1.2.3.4` and `Release 1.2.3.4`, case-insensitively.

Why:
Manual Test 4 F6 showed `Release 1.2.3.4 passed QA yesterday.` was redacted as an IP address even though the human rubric judged it to be obvious release-version context. This extended the Manual Test 3 version/IP grader disagreement from key/value syntax into direct natural-language version context.

Stakeholder impact:
Improves diagnostic usefulness for developers and support recipients while preserving IPv4 redaction for ordinary network prose such as `Server 10.20.30.40 failed`, `Client 8.8.8.8 disconnected`, and `Remote address: 172.20.10.15`.

Mapped requirement:
R6, R12, R14.

## v1.15

Changed:
Current product output now standardizes username replacements on `[REDACTED_USERNAME]` for both structured username fields and usernames inside recognized home-directory paths.

Why:
Manual Test 4 consistency review found two labels, `[REDACTED_USERNAME]` and `[REDACTED_USER]`, representing the same conceptual category. The current product, tests, evals, and live documentation now use one marker while historical evidence files preserve the labels actually observed at the time.

Stakeholder impact:
Improves readability and grading consistency without changing which username values are protected.

Mapped requirement:
R13, R12.

## v1.16

Changed:
IPv4 token-boundary handling now redacts standalone valid non-loopback IPv4 addresses before sentence-ending periods, while preserving the trailing punctuation.

Why:
Manual Test 5 F7 showed `Connection received from 192.168.20.50.` remained unchanged because the detector treated the sentence-ending period like part of a larger dotted token or hostname. This was an implementation bug against the existing final policy, not a new specification ambiguity.

Stakeholder impact:
Improves privacy/security for people whose IP details appear in logs and for security reviewers, while preserving diagnostic usefulness for version contexts, loopback addresses, larger dotted numeric sequences, and hostname-embedded IPv4-shaped values.

Mapped requirement:
R6, R12, R14.

## v1.17

Changed:
Documented Manual Test 6's firmware-version borderline case as a known limitation and grader disagreement; no sanitizer feature change was made.

Why:
`Firmware 1.2.3.4 installed successfully.` is likely firmware-version context to a human, but the frozen deterministic sanitizer redacts it as an IP address because only narrow `Version`/`Release` contexts are exempt. Adding another keyword exception would be speculative and could make the rule set harder to audit.

Stakeholder impact:
Keeps the privacy/security posture stable while honestly surfacing a diagnostic-usefulness limitation for developers and support recipients.

Mapped requirement:
R6, R12, R14.

## v1.18

Changed:
Added final completion evidence: product-behavior harness, accessibility static checker, accessibility review, product behavior review, harness review, final completion report, eval `grader` metadata, and refreshed final evidence docs.

Why:
Final completion mode required verifiable evidence for UI behavior, accessibility checks, grader methodology, harness components, security/privacy review, secret scanning, and presentation readiness without changing the frozen sanitizer.

Stakeholder impact:
Improves grading confidence and presentation readiness for evaluators while preserving the audited product behavior.

Mapped requirement:
Human-Centered AI final completion gate, product behavior tests, accessibility/human evaluation, harness final check, and presentation evidence requirements.

## v1.19

Changed:
Adopted the approved Claude-generated visual concept as the final SafePaste UI shell while preserving the existing evaluated sanitizer engine. The UI now presents a dark developer/security workspace with compact topbar, amber primary action, Local Only and No Network Egress messaging, grouped category chips, editor-style panes, line-number gutters, `sanitized.log` and `preview.log` tabs, visual redaction bars, status bar, local text-file drag/drop, and keyboard shortcuts.

Why:
The previous interface was functionally correct but lacked the final presentation polish and visual hierarchy requested for the Human-Centered AI project. The Claude prototype supplied the approved visual direction, but its sanitizer implementation could not be used because SafePaste's frozen `src/sanitizer.js` is the tested source of truth.

Stakeholder impact:
Improves presentation readiness, readability, and developer trust without changing sanitizer semantics. The visual preview helps users see redaction locations, while Copy continues to use stable textual markers such as `[REDACTED_EMAIL]` and `[REDACTED_IP_ADDRESS]`.

Privacy/security impact:
Removed Claude's Google Fonts dependency and kept system/local font stacks. Final production scans found no network APIs, storage APIs, external URLs/fonts/imports, `innerHTML`, or production credential-looking values.

Mapped requirement:
R1, R7-R12, R16-R19, PS1-PS4, A1-A7, Human-Centered AI final UI integration.

## v1.20

Changed:
Refined the final UI palette from a full dark background to a brighter high-contrast developer/security shell. The page background, workspace, toolbar, and editor panes now use light neutral surfaces with darker slate text, while amber remains the primary action/status accent and category colors remain restrained.

Why:
Manual visual review found the full-dark UI difficult to see. The refinement keeps the polished security-tool identity while improving readability and reducing visual fatigue.

Stakeholder impact:
Improves usability for developers, support recipients, graders, and presenters without changing sanitizer behavior, eval logic, product logic, or local-only privacy guarantees.

Mapped requirement:
A1-A7, R11, R12, Human-Centered AI final UI readability.

## v1.21

Changed:
Adjusted the UI palette again from bright light surfaces to a muted middle-ground slate/blue-gray system. The app now avoids both full black backgrounds and stark white cards, using tinted surfaces, slate text, amber primary action, and restrained security accents.

Why:
Manual visual review found that both extremes were uncomfortable: full dark was hard to see, and bright white felt too harsh. The middle palette better matches a polished privacy/security tool while keeping logs readable.

Stakeholder impact:
Improves readability and presentation comfort without changing product logic, sanitizer behavior, tests, evals, or privacy invariants.

Mapped requirement:
A1-A7, R11, R12, Human-Centered AI final UI readability.

## v1.22

Changed:
Added narrow credential handling for explicit structured `secret` fields. Supported forms include `secret=value`, `secret: value`, and quoted JSON equivalents such as `"secret":"value"`. The replacement marker is `[REDACTED_SECRET]`.

Why:
Final regression F8 showed `secret=FakeSecretValue987` remained visible. This was a high-severity privacy failure because an explicit structured `secret` field provides strong evidence that the value is sensitive.

Stakeholder impact:
Improves privacy protection for people whose sensitive configuration values appear in logs and increases security/compliance confidence. The change is narrow and does not alter IPv4 behavior, version exceptions, username behavior, path behavior, the firmware known limitation, or UI design.

Mapped requirement:
R5, R12, PS5, final high-severity regression response.
