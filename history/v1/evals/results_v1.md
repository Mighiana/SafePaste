# SafePaste v1 Evaluation Results

These results were recorded before fixing the initial sanitizer defects. The failures below are preserved as real v1 evidence.

## Commands Run

- `node tests/test-sanitizer.js`
- `node evals/run-evals.js --write evals/results_v1.md`
- `rg -n "fetch\\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|localStorage|sessionStorage|indexedDB|document\\.cookie|innerHTML|https?://|cdn" SafePaste`
- `rg -n 'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN .*PRIVATE KEY-----|password\\s*[:=]\\s*[^,\\s;}{]{8,}|api[_-]?key\\s*[:=]\\s*[A-Za-z0-9_./+=-]{16,}' SafePaste`

## Unit Test Results

- Total unit tests: 18
- Passed: 16
- Failed: 2
- Failure IDs/names:
  - `redacts password JSON`
  - `redacts API key JSON`

### Unit Test Failure: password JSON

- Related stakeholder: Security / compliance team
- Mapped requirement: R5
- Failing input:

```text
{"user":"sam","password":"supersecret"}
```

- Expected: remove `supersecret` and preserve `"user":"sam"`.
- Actual: `supersecret` remained in the sanitized output.
- Diagnosis: v1 credential regexes supported unquoted keys such as `password=value`, but did not handle quoted JSON keys followed by a quote before the colon.

### Unit Test Failure: API key JSON

- Related stakeholder: Security / compliance team
- Mapped requirement: R5
- Failing input:

```text
{"apiKey":"abc1234567890SECRET","mode":"test"}
```

- Expected: remove `abc1234567890SECRET` and preserve `"mode":"test"`.
- Actual: `abc1234567890SECRET` remained in the sanitized output.
- Diagnosis: v1 credential regexes supported unquoted keys such as `api_key=value`, but did not handle quoted JSON keys followed by a quote before the colon.

## Static Privacy And Security Checks

- Network/persistence/unsafe-DOM scan: no production use of `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `EventSource`, `localStorage`, `sessionStorage`, `indexedDB`, `document.cookie`, or `innerHTML` was found.
- Contextual hits: the scan found these terms in specifications, agent instructions, and the eval runner's own static-scan patterns. They were reviewed as documentation/test-harness references, not runtime product use.
- Secret scan: hits were limited to synthetic test and eval fixtures such as fake AWS-shaped and Slack-shaped strings, fake API key values, and fake passwords used to verify redaction. No production hardcoded credential was identified.
- Security-review sub-agent: completed before v1 snapshot. Findings are summarized below.
- Manual hook invocation: `sh SafePaste/.claude/hooks/pre-commit.sh` printed `grep: command not found` and exited with status 0. This means the v1 hook was not verified as functional in this environment.

## Security-Reviewer Findings

The security-reviewer was run as a read-only sub-agent using `.claude/agents/security-reviewer.md`.

### SR-001: JSON-form secrets are not redacted

- Severity: High
- Evidence: Unit tests failed `redacts password JSON` and `redacts API key JSON`; evals failed EV-004 and EV-005.
- Affected stakeholders: Security / compliance team; person whose data appears in logs.
- Mapped requirements: R5, R12
- Recommended fix: Support quoted JSON property names and camelCase keys without broadening arbitrary-string redaction.

### SR-002: Non-Bearer Authorization headers can leak credentials

- Severity: High
- Evidence: Security review reported that `Authorization: Basic dXNlcjpwYXNzd29yZA==` and `Authorization: Token abcdefghijklmnopqrstuvwxyz` remained unchanged.
- Affected stakeholders: Security / compliance team; person whose data appears in logs.
- Mapped requirement: R5
- Recommended fix: Redact common Authorization schemes such as Basic, Bearer, and Token, or redact Authorization header values to a safe line/quote boundary.

### SR-003: `pwd=` causes broad false positives

- Severity: Medium
- Evidence: Security review reported that `PWD=/workspace/project npm test` was treated as a password.
- Affected stakeholders: Developer / IT support engineer; support recipient.
- Mapped requirements: R12, R14
- Recommended fix: Treat `pwd` cautiously or remove it from broad password aliases.

### SR-004: Static privacy evals scan a hardcoded production-file list

- Severity: Low
- Evidence: `productionFiles()` in `evals/run-evals.js` listed only four files.
- Affected stakeholder: Security / compliance team.
- Mapped requirements: PS1-PS4, AI1, AI2, AI6
- Recommended fix: Recursively scan production `.html`, `.css`, and `.js` files while excluding docs/tests/evals/history.

### SR-005: Pre-commit hook writes matches to a fixed temp file

- Severity: Low
- Evidence: `.claude/hooks/pre-commit.sh` wrote possible matches to `/tmp/safepaste-secret-scan.txt`.
- Affected stakeholders: Developers; security / compliance team.
- Mapped requirement: PS5 and harness secret-scan intent.
- Recommended fix: Use `mktemp` with trap cleanup or avoid writing matches to disk.

### HR-001: Manual hook invocation did not scan because `grep` was unavailable

- Severity: Medium
- Evidence: `sh SafePaste/.claude/hooks/pre-commit.sh` printed `grep: command not found` and exited with status 0.
- Affected stakeholders: Security / compliance team; developers relying on the hook.
- Mapped requirement: Harness component 3; PS5
- Recommended fix: Replace shell dependency on `grep` with `git grep` or explicitly fail closed when required scan tools are unavailable.

## Summary

- Total eval cases: 36
- Passed: 34
- Failed: 2
- Failure IDs: EV-004, EV-005

## Case Results

| ID | Layer | Category | Stakeholder | Requirement | Result |
| --- | --- | --- | --- | --- | --- |
EV-001 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
EV-002 | product | secret/api-key | Person whose data appears in the logs | R5, R12 | PASS
EV-003 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
EV-004 | product | secret/api-key | Security / compliance team | R5, R12 | FAIL
EV-005 | product | secret/api-key | Security / compliance team | R5, R12 | FAIL
EV-006 | product | false-positive | Developer / IT support engineer | R14 | PASS
EV-007 | product | email | Person whose data appears in the logs | R4 | PASS
EV-008 | product | email | Person whose data appears in the logs | R4 | PASS
EV-009 | product | email | Developer / IT support engineer | R4, R12 | PASS
EV-010 | product | email | Developer / IT support engineer | R12, R14 | PASS
EV-011 | product | ip | Person whose data appears in the logs | R6 | PASS
EV-012 | product | ip | Security / compliance team | R6 | PASS
EV-013 | product | ip | Developer / IT support engineer | R6, R14 | PASS
EV-014 | product | ip | Support recipient | R10, R12 | PASS
EV-015 | product | authentication/token | Security / compliance team | R5 | PASS
EV-016 | product | authentication/token | Security / compliance team | R5 | PASS
EV-017 | product | authentication/token | Security / compliance team | R5 | PASS
EV-018 | product | authentication/token | Security / compliance team | R5 | PASS
EV-019 | product | false-positive | Developer / IT support engineer | R14 | PASS
EV-020 | product | false-positive | Support recipient | R12, R14 | PASS
EV-021 | product | false-positive | Developer / IT support engineer | R12, R14 | PASS
EV-022 | product | false-positive | Developer / IT support engineer | R12, R14 | PASS
EV-023 | product | malformed/edge | Developer / IT support engineer | R2, R3 | PASS
EV-024 | product | malformed/edge | Person whose data appears in the logs | R4, R12 | PASS
EV-025 | product | malformed/edge | Support recipient | R5, R12 | PASS
EV-026 | product | adversarial/security | Person whose data appears in the logs | R4, PS4 | PASS
EV-027 | product | adversarial/security | Developer / IT support engineer | R5, R14 | PASS
EV-028 | product | adversarial/security | Security / compliance team | R4, R5, R8 | PASS
EV-029 | product | path-or-username | Person whose data appears in the logs | R13 | PASS
EV-030 | engineering | privacy/static | Security / compliance team | R1, PS1, PS3, AI1 | PASS
EV-031 | engineering | privacy/static | Person whose data appears in the logs | PS2, AI2 | PASS
EV-032 | engineering | privacy/static | Security / compliance team | PS3 | PASS
EV-033 | engineering | privacy/static | Security / compliance team | PS4, AI6 | PASS
EV-034 | engineering | privacy/static | Security / compliance team | PS8, AI4 | PASS
EV-035 | engineering | accessibility/usability | Developer / IT support engineer | A2 | PASS
EV-036 | engineering | accessibility/usability | Developer / IT support engineer | A4, A5 | PASS

## Failures

### EV-004: Redact quoted JSON client_secret value and preserve service.

- Related stakeholder: Security / compliance team
- Mapped requirement: R5, R12
- Justification: JSON configuration is a common place for accidental credential exposure.
- Failing input:

```text
{"client_secret":"clientSecretValue12345","service":"billing"}
```
- Actual output:

```text
{"client_secret":"clientSecretValue12345","service":"billing"}
```
- Categories: none
- Redaction count: 0
- Failure reason:
  - Sanitized output still contains forbidden value: clientSecretValue12345
  - Sanitized output missing expected value: [REDACTED_API_KEY]
  - Missing expected category: API_KEY
  - Expected redaction count 1; actual 0

### EV-005: Redact quoted JSON apiKey value and preserve mode.

- Related stakeholder: Security / compliance team
- Mapped requirement: R5, R12
- Justification: CamelCase JSON keys are common in frontend and API logs.
- Failing input:

```text
{"apiKey":"abc1234567890SECRET","mode":"test"}
```
- Actual output:

```text
{"apiKey":"abc1234567890SECRET","mode":"test"}
```
- Categories: none
- Redaction count: 0
- Failure reason:
  - Sanitized output still contains forbidden value: abc1234567890SECRET
  - Sanitized output missing expected value: [REDACTED_API_KEY]
  - Missing expected category: API_KEY
  - Expected redaction count 1; actual 0
