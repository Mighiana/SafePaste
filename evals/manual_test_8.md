# Manual Test 8 - Final Structured Secret Regression

Date:
2026-08-13

Core sanitizer status:
Frozen except for high-severity privacy/security failures.

## Real Failure F8 - explicit structured secret field remained visible

Observed input:

```text
secret=FakeSecretValue987
```

Observed output before fix:

```text
secret=FakeSecretValue987
```

Expected output:

```text
secret=[REDACTED_SECRET]
```

Severity:
High. This is an explicit structured secret field, not arbitrary secret guessing.

Scope decision:
Extend credential handling narrowly for explicit `secret` field forms only:

- `secret=value`
- `secret: value`
- `"secret": "value"`

Do not add broad arbitrary-secret inference. Do not change IPv4 behavior, version exceptions, username behavior, path behavior, firmware limitation, or UI design.

## Pre-Fix Regression Evidence

Command:

```text
node tests/test-sanitizer.js
```

Result before fix:

```text
37/38 tests passed
FAIL redacts explicit structured secret fields
AssertionError [ERR_ASSERTION]: structured secret: secret should be removed
```

Eval case added before fix:
EV-073.

## Post-Fix Evidence

Implementation change:
Added a narrow `SECRET` redaction label/category and explicit structured-field rule for `secret=value`, `secret: value`, and JSON `"secret":"value"` forms.

Unit test result after fix:

```text
node tests/test-sanitizer.js
38/38 tests passed
```

Eval result after fix:

```text
node evals/run-evals.js --write evals/results_final.md
73/73 eval cases passed
Failure IDs: None
```

Automated exact/property grader after fix:

```text
node evals/graders/exact-property-grader.js --write evals/graders/exact-property-results.md
21 cases graded
91/91 property checks passed
```

Requested regression sweep after fix:

```text
PASS input=secret=FakeSecretValue987 output=secret=[REDACTED_SECRET]
PASS input=1.2.3.4.5 output=1.2.3.4.5
PASS input=Version 3.4.5.6 deployed successfully. output=Version 3.4.5.6 deployed successfully.
PASS input=Connection received from 192.168.20.50. output=Connection received from [REDACTED_IP_ADDRESS].
PASS input=username=musman24 output=username=[REDACTED_USERNAME]
PASS input=/home/bob/projects/app/debug.log output=/home/[REDACTED_USERNAME]/projects/app/debug.log
6/6 requested regressions passed
```

Unchanged behavior confirmed in requested regressions:

- Larger dotted numeric sequences remain visible.
- Prose version context remains visible.
- Standalone non-loopback IPv4 addresses still redact.
- Structured usernames still redact.
- Linux home-path usernames still redact only the username segment.
