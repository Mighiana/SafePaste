# Manual Test 4 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 4, followed by local reproduction against the then-current sanitizer before code changes.

## Regression Passes Observed By User

- Structured username fields are now redacted.
- JSON username fields are redacted.
- `name` and `display_name` remain visible.
- Version-related key/value fields are preserved.
- Network-related IP fields are redacted.
- Loopback `127.0.0.0/8` remains visible.
- Malformed and larger dotted sequences remain visible.
- Windows and Linux home usernames are redacted.
- Generic system paths remain visible.
- Credentials are redacted.
- Harmless IDs remain unchanged.
- Usernames mentioned in ordinary prose remain unchanged.
- HTML/script-looking text remains literal.

## Before Results Reproduced Locally

Command:

```text
@('Release 1.2.3.4 passed QA yesterday.','Version 1.2.3.4 passed QA yesterday.','version: 1.2.3.4','release: 1.2.3.4','release=1.2.3.4','Server 10.20.30.40 failed','Client 8.8.8.8 disconnected','Remote address: 172.20.10.15','Error opening C:\Users\usman\Desktop\secret.log','/home/alice/project/error.log','username=musman24') | ForEach-Object { $env:SAFEP_INPUT=$_; node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); const input=process.env.SAFEP_INPUT; const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount}));" }
```

Observed output before fixes:

```text
{"input":"Release 1.2.3.4 passed QA yesterday.","sanitized":"Release [REDACTED_IP_ADDRESS] passed QA yesterday.","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Version 1.2.3.4 passed QA yesterday.","sanitized":"Version [REDACTED_IP_ADDRESS] passed QA yesterday.","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"version: 1.2.3.4","sanitized":"version: 1.2.3.4","categories":[],"redactionCount":0}
{"input":"release: 1.2.3.4","sanitized":"release: 1.2.3.4","categories":[],"redactionCount":0}
{"input":"release=1.2.3.4","sanitized":"release=1.2.3.4","categories":[],"redactionCount":0}
{"input":"Server 10.20.30.40 failed","sanitized":"Server [REDACTED_IP_ADDRESS] failed","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Client 8.8.8.8 disconnected","sanitized":"Client [REDACTED_IP_ADDRESS] disconnected","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Remote address: 172.20.10.15","sanitized":"Remote address: [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Error opening C:\\Users\\usman\\Desktop\\secret.log","sanitized":"Error opening C:\\Users\\[REDACTED_USER]\\Desktop\\secret.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"/home/alice/project/error.log","sanitized":"/home/[REDACTED_USER]/project/error.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"username=musman24","sanitized":"username=[REDACTED_USERNAME]","categories":["USERNAME"],"redactionCount":1}
```

## Findings

### F6: Version-Like IPv4 In Prose

Input:

```text
Release 1.2.3.4 passed QA yesterday.
```

Actual before fix:

```text
Release [REDACTED_IP_ADDRESS] passed QA yesterday.
```

Human expected:

```text
Release 1.2.3.4 passed QA yesterday.
```

Diagnosis:
The existing version-field context exception handled `release=1.2.3.4`, `release: 1.2.3.4`, and `version: 1.2.3.4`, but not obvious natural-language version context such as `Release 1.2.3.4` or `Version 1.2.3.4`.

Automated-vs-human interpretation:
An automated syntactic IP interpretation can treat the redaction as a privacy pass because a valid non-loopback IPv4-shaped token was removed. The human rubric treats it as a diagnostic-usefulness and proportionality failure because obvious release/version information was unnecessarily removed.

### Replacement Marker Consistency

Current product output used both `[REDACTED_USER]` for usernames inside home paths and `[REDACTED_USERNAME]` for structured username fields. These represent the same conceptual category: account or local usernames. The current product, tests, evals, and live documentation should standardize on `[REDACTED_USERNAME]`.

Historical evidence files are not rewritten merely to hide the prior behavior. Existing manual-test and v1 evidence that recorded `[REDACTED_USER]` remains historically accurate.

## Regression Tests Added Before Fix

Command:

```text
node tests/test-sanitizer.js
```

Result before sanitizer fix:

- Total unit tests: 35
- Passed: 32
- Failed: 3

Failing tests:

- `preserves IPv4-shaped values in strong prose version context`
- `redacts Linux home path username`
- `redacts Linux home path username with trailing slash`

Eval command:

```text
node evals/run-evals.js
```

Result before sanitizer fix:

- Total eval cases: 64
- Passed: 59
- Failed: 5
- Failure IDs: EV-029, EV-044, EV-045, EV-058, EV-059

Automated property grader command:

```text
node evals/graders/exact-property-grader.js
```

Result before sanitizer fix:

- Cases graded: 16
- Property checks: 69
- Passed: 64
- Failed: 5

## After Results

Command:

```text
node tests/test-sanitizer.js
```

Result after sanitizer fix:

- Total unit tests: 35
- Passed: 35
- Failed: 0

Eval command:

```text
node evals/run-evals.js
```

Result after sanitizer fix:

- Total eval cases: 64
- Passed: 64
- Failed: 0

Automated property grader command:

```text
node evals/graders/exact-property-grader.js
```

Result after sanitizer fix:

- Cases graded: 16
- Property checks: 69
- Passed: 69
- Failed: 0

Focused reproduction command:

```text
@('Release 1.2.3.4 passed QA yesterday.','Version 1.2.3.4 passed QA yesterday.','version: 1.2.3.4','release: 1.2.3.4','release=1.2.3.4','Server 10.20.30.40 failed','Client 8.8.8.8 disconnected','Remote address: 172.20.10.15','Error opening C:\Users\usman\Desktop\secret.log','/home/alice/project/error.log','username=musman24') | ForEach-Object { $env:SAFEP_INPUT=$_; node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); const input=process.env.SAFEP_INPUT; const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount}));" }
```

Observed output after fixes:

```text
{"input":"Release 1.2.3.4 passed QA yesterday.","sanitized":"Release 1.2.3.4 passed QA yesterday.","categories":[],"redactionCount":0}
{"input":"Version 1.2.3.4 passed QA yesterday.","sanitized":"Version 1.2.3.4 passed QA yesterday.","categories":[],"redactionCount":0}
{"input":"version: 1.2.3.4","sanitized":"version: 1.2.3.4","categories":[],"redactionCount":0}
{"input":"release: 1.2.3.4","sanitized":"release: 1.2.3.4","categories":[],"redactionCount":0}
{"input":"release=1.2.3.4","sanitized":"release=1.2.3.4","categories":[],"redactionCount":0}
{"input":"Server 10.20.30.40 failed","sanitized":"Server [REDACTED_IP_ADDRESS] failed","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Client 8.8.8.8 disconnected","sanitized":"Client [REDACTED_IP_ADDRESS] disconnected","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Remote address: 172.20.10.15","sanitized":"Remote address: [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Error opening C:\\Users\\usman\\Desktop\\secret.log","sanitized":"Error opening C:\\Users\\[REDACTED_USERNAME]\\Desktop\\secret.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"/home/alice/project/error.log","sanitized":"/home/[REDACTED_USERNAME]/project/error.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"username=musman24","sanitized":"username=[REDACTED_USERNAME]","categories":["USERNAME"],"redactionCount":1}
```

## Final Verification After Documentation Updates

Commands:

```text
node tests/test-sanitizer.js
node evals/run-evals.js --write evals/results_final.md
node evals/graders/exact-property-grader.js
node evals/run-red-team.js
node evals/run-ui-smoke.js
rg -n "fetch\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB|document\.cookie|innerHTML|https?://|<script[^>]+src=|TODO.*security|bypass" SafePaste
rg -n 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN .*PRIVATE KEY-----|password\s*[:=]\s*[^,\s;}{]{8,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_./+=-]{16,}' SafePaste
```

Results:

- Unit tests: 35 total, 35 passed, 0 failed.
- Eval cases: 64 total, 64 passed, 0 failed.
- Automated exact/property grader: 16 cases, 69 property checks, 69 passed, 0 failed.
- Human rubric: manually updated for EV-058 before/after and EV-062 current judgment.
- Red-team cases: 15 total, 15 passed, 0 failed.
- UI smoke: PASS.
- Privacy/static scan: contextual documentation, history, eval-runner, local static server, local script tags, and scan-pattern hits only; no production network, persistence, cookie, or unsafe DOM finding.
- Secret scan: synthetic fixtures in tests/evals/history/docs only; no production hardcoded credential finding.
- Remaining failures from executed checks: none.
