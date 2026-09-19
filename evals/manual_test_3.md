# Manual Test 3 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 3, followed by local reproduction against the then-current sanitizer before code changes.

## Regression Passes Observed By User

- Loopback `127.x.x.x` addresses remained visible.
- Invalid IPv4 candidates remained visible.
- `1.2.3.4.5` remained visible.
- Windows and Linux home-path usernames were redacted.
- Generic system paths remained unchanged.
- Private and public IP addresses were redacted.
- Credentials were redacted.
- Harmless request/build IDs, UUID, and commit hash remained unchanged.

## SPEC_v1 Review Before Code Changes

`SPEC_v1.md` was preserved unchanged.

F4 structured usernames:
`SPEC_v1.md` says local file paths and usernames may be redacted only when reasonably detectable, and ordinary short identifiers should normally remain unchanged unless there is strong evidence they are sensitive. This covers the general idea that usernames can be sensitive, but it does not explicitly require redacting `username=`, `user_name=`, or `user=` fields. This was treated as ambiguous and resolved in `SPEC_FINAL.md`.

F5 version/IP context:
`SPEC_v1.md` requires valid IPv4 detection and preserving non-sensitive context where practical. It does not say whether a syntactically valid IPv4-shaped token should be preserved when it is clearly a software version value. This was treated as a real false-positive / grader-disagreement case and resolved in `SPEC_FINAL.md`.

## Before Results Reproduced Locally

Command:

```text
node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); const inputs=['username=musman24','user_name=alice_dev','user=bob-admin','name=Muhammad','User alice reported that the service failed after deployment.','release=1.2.3.4','version=10.20.30.40','app_version=2.4.6.8','software_version=3.5.7.9','client_ip=10.20.30.40','server_ip=8.8.8.8']; for (const input of inputs) { const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount})); }"
```

Observed output before fixes:

```text
{"input":"username=musman24","sanitized":"username=musman24","categories":[],"redactionCount":0}
{"input":"user_name=alice_dev","sanitized":"user_name=alice_dev","categories":[],"redactionCount":0}
{"input":"user=bob-admin","sanitized":"user=bob-admin","categories":[],"redactionCount":0}
{"input":"name=Muhammad","sanitized":"name=Muhammad","categories":[],"redactionCount":0}
{"input":"User alice reported that the service failed after deployment.","sanitized":"User alice reported that the service failed after deployment.","categories":[],"redactionCount":0}
{"input":"release=1.2.3.4","sanitized":"release=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"version=10.20.30.40","sanitized":"version=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"app_version=2.4.6.8","sanitized":"app_version=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"software_version=3.5.7.9","sanitized":"software_version=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"client_ip=10.20.30.40","sanitized":"client_ip=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"server_ip=8.8.8.8","sanitized":"server_ip=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
```

## Findings

### F4: Structured Usernames Remain Visible

Input:

```text
username=musman24
user_name=alice_dev
user=bob-admin
```

Actual before fix:

```text
username=musman24
user_name=alice_dev
user=bob-admin
```

Recommended final policy:
Redact values of explicit structured username fields such as `username=`, `user_name=`, and `user=`, including quoted JSON equivalents when practical. Do not attempt arbitrary personal-name detection in prose.

Reason:
Explicit account identifiers have a strong privacy signal, while arbitrary name detection would produce excessive false positives and damage diagnostic usefulness.

### F5: Version/IP Semantic False Positive

Input:

```text
release=1.2.3.4
```

Actual before fix:

```text
release=[REDACTED_IP_ADDRESS]
```

Human-expected:

```text
release=1.2.3.4
```

Diagnosis:
The detector correctly recognized IPv4 syntax but ignored the contextual meaning of `release=`. Automated syntactic grading could reasonably pass the redaction, while human usefulness grading failed it because version context was unnecessarily removed.

## Regression Tests Added Before Fix

Command:

```text
node tests/test-sanitizer.js
```

Result before sanitizer fix:

- Total unit tests: 33
- Passed: 30
- Failed: 3

Failing tests:

- `redacts explicit structured username fields`
- `redacts explicit structured username JSON fields`
- `preserves IPv4-shaped values in version-related fields`

Eval command:

```text
node evals/run-evals.js
```

Result before sanitizer fix:

- Total eval cases: 57
- Passed: 51
- Failed: 6
- Failure IDs: EV-048, EV-049, EV-052, EV-053, EV-054, EV-057

Automated property grader command:

```text
node evals/graders/exact-property-grader.js
```

Result before sanitizer fix:

- Cases graded: 14
- Property checks: 60
- Passed: 45
- Failed: 15

## After Results

Command:

```text
node tests/test-sanitizer.js
```

Result after sanitizer fix:

- Total unit tests: 33
- Passed: 33
- Failed: 0

Eval command:

```text
node evals/run-evals.js
```

Result after sanitizer fix:

- Total eval cases: 57
- Passed: 57
- Failed: 0

Automated property grader command:

```text
node evals/graders/exact-property-grader.js
```

Result after sanitizer fix:

- Cases graded: 14
- Property checks: 60
- Passed: 60
- Failed: 0

Red-team command:

```text
node evals/run-red-team.js
```

Result after sanitizer fix:

- Total red-team cases: 15
- Passed: 15
- Failed: 0

Focused reproduction command:

```text
@('username=musman24','user_name=alice_dev','user=bob-admin','{"username":"musman24","role":"admin"}','name=Muhammad','User alice reported that the service failed after deployment.','release=1.2.3.4','version=10.20.30.40','app_version=2.4.6.8','software_version=3.5.7.9','client_ip=10.20.30.40','server_ip=8.8.8.8') | ForEach-Object { $env:SAFEP_INPUT=$_; node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); const input=process.env.SAFEP_INPUT; const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount}));" }
```

Observed output after fixes:

```text
{"input":"username=musman24","sanitized":"username=[REDACTED_USERNAME]","categories":["USERNAME"],"redactionCount":1}
{"input":"user_name=alice_dev","sanitized":"user_name=[REDACTED_USERNAME]","categories":["USERNAME"],"redactionCount":1}
{"input":"user=bob-admin","sanitized":"user=[REDACTED_USERNAME]","categories":["USERNAME"],"redactionCount":1}
{"input":"{\"username\":\"musman24\",\"role\":\"admin\"}","sanitized":"{\"username\":\"[REDACTED_USERNAME]\",\"role\":\"admin\"}","categories":["USERNAME"],"redactionCount":1}
{"input":"name=Muhammad","sanitized":"name=Muhammad","categories":[],"redactionCount":0}
{"input":"User alice reported that the service failed after deployment.","sanitized":"User alice reported that the service failed after deployment.","categories":[],"redactionCount":0}
{"input":"release=1.2.3.4","sanitized":"release=1.2.3.4","categories":[],"redactionCount":0}
{"input":"version=10.20.30.40","sanitized":"version=10.20.30.40","categories":[],"redactionCount":0}
{"input":"app_version=2.4.6.8","sanitized":"app_version=2.4.6.8","categories":[],"redactionCount":0}
{"input":"software_version=3.5.7.9","sanitized":"software_version=3.5.7.9","categories":[],"redactionCount":0}
{"input":"client_ip=10.20.30.40","sanitized":"client_ip=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"server_ip=8.8.8.8","sanitized":"server_ip=[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
```
