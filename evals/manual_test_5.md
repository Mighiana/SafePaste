# Manual Test 5 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 5, followed by local reproduction against the then-current sanitizer before code changes.

## Regression Passes Observed By User

- Structured usernames redacted.
- JSON usernames redacted.
- Normal names and display names preserved.
- Emails and credentials redacted.
- Version fields preserved.
- Natural-language `Version`/`Release` IPv4-shaped values preserved.
- Explicit client/server/source/destination IP fields redacted.
- `Client 8.8.8.8` prose IP redacted.
- `Server 10.10.10.10` prose IP redacted.
- All `127.0.0.0/8` loopback examples preserved.
- Malformed and larger dotted sequences preserved.
- Windows/Linux home usernames redacted consistently.
- System paths preserved.
- Harmless IDs preserved.
- Normal prose names/usernames preserved.
- HTML/script input remained literal.
- Unicode preserved.

## Before Results Reproduced Locally

Command:

```text
@('Connection received from 192.168.20.50.','Connection received from 192.168.20.50','Request originated at 10.1.2.3.','Remote host 172.16.4.20 disconnected.','Peer address: 8.8.8.8','Version 3.4.5.6 deployed.','Release 5.6.7.8 passed QA.','127.0.0.1','1.2.3.4.5','https://10.20.30.40.example.com/status') | ForEach-Object { $env:SAFEP_INPUT=$_; node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); const input=process.env.SAFEP_INPUT; const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount}));" }
```

Observed output before fix:

```text
{"input":"Connection received from 192.168.20.50.","sanitized":"Connection received from 192.168.20.50.","categories":[],"redactionCount":0}
{"input":"Connection received from 192.168.20.50","sanitized":"Connection received from [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Request originated at 10.1.2.3.","sanitized":"Request originated at 10.1.2.3.","categories":[],"redactionCount":0}
{"input":"Remote host 172.16.4.20 disconnected.","sanitized":"Remote host [REDACTED_IP_ADDRESS] disconnected.","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Peer address: 8.8.8.8","sanitized":"Peer address: [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Version 3.4.5.6 deployed.","sanitized":"Version 3.4.5.6 deployed.","categories":[],"redactionCount":0}
{"input":"Release 5.6.7.8 passed QA.","sanitized":"Release 5.6.7.8 passed QA.","categories":[],"redactionCount":0}
{"input":"127.0.0.1","sanitized":"127.0.0.1","categories":[],"redactionCount":0}
{"input":"1.2.3.4.5","sanitized":"1.2.3.4.5","categories":[],"redactionCount":0}
{"input":"https://10.20.30.40.example.com/status","sanitized":"https://10.20.30.40.example.com/status","categories":[],"redactionCount":0}
```

## Finding

### F7: Standalone IPv4 False Negative

Input:

```text
Connection received from 192.168.20.50.
```

Actual before fix:

```text
Connection received from 192.168.20.50.
```

Expected:

```text
Connection received from [REDACTED_IP_ADDRESS].
```

Diagnosis:
The IPv4 regex required the character after an IP candidate not to be a dot. That correctly preserved larger dotted numeric sequences and hostname-embedded candidates, but it also treated a sentence-ending period as if it were part of a larger token. The same address without a trailing period was redacted, confirming that validation and non-loopback policy were not the cause.

Mapped requirement:
R6 requires valid non-loopback IPv4 detection and complete-token handling. F7 is a privacy/security failure because `192.168.20.50` is a valid standalone non-loopback IPv4 address in normal network prose and has no recognized preservation context.

## Regression Tests Added Before Fix

Added before changing production code:

- Unit regression: `redacts standalone IPv4 addresses before sentence periods`.
- Eval cases: EV-065 through EV-071.
- Automated grader coverage: EV-065, EV-069, EV-071.

First failing run after adding those tests and before changing `src/sanitizer.js`:

```text
node tests/test-sanitizer.js
36/37 tests passed
FAIL redacts standalone IPv4 addresses before sentence periods
AssertionError [ERR_ASSERTION]: Expected values to be strictly equal:
+ actual - expected

+ 'Connection received from 192.168.20.50.'
- 'Connection received from [REDACTED_IP_ADDRESS].'
```

```text
node evals/run-evals.js
Total eval cases: 71
Passed: 69
Failed: 2
Failure IDs: EV-065, EV-066
```

```text
node evals/graders/exact-property-grader.js
Cases graded: EV-001, EV-005, EV-013, EV-029, EV-039, EV-040, EV-041, EV-044, EV-046, EV-048, EV-049, EV-050, EV-052, EV-055, EV-058, EV-062, EV-065, EV-069, EV-071
Property checks: 80
Passed: 76
Failed: 4
Failing case: EV-065
```

## After Results

Focused reproduction after the fix:

```text
{"input":"Connection received from 192.168.20.50.","sanitized":"Connection received from [REDACTED_IP_ADDRESS].","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Connection received from 192.168.20.50","sanitized":"Connection received from [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Request originated at 10.1.2.3.","sanitized":"Request originated at [REDACTED_IP_ADDRESS].","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Remote host 172.16.4.20 disconnected.","sanitized":"Remote host [REDACTED_IP_ADDRESS] disconnected.","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Peer address: 8.8.8.8","sanitized":"Peer address: [REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"Version 3.4.5.6 deployed.","sanitized":"Version 3.4.5.6 deployed.","categories":[],"redactionCount":0}
{"input":"Release 5.6.7.8 passed QA.","sanitized":"Release 5.6.7.8 passed QA.","categories":[],"redactionCount":0}
{"input":"127.0.0.1","sanitized":"127.0.0.1","categories":[],"redactionCount":0}
{"input":"1.2.3.4.5","sanitized":"1.2.3.4.5","categories":[],"redactionCount":0}
{"input":"https://10.20.30.40.example.com/status","sanitized":"https://10.20.30.40.example.com/status","categories":[],"redactionCount":0}
```

Focused commands after the fix:

```text
node tests/test-sanitizer.js
37/37 tests passed

node evals/run-evals.js
Total eval cases: 71
Passed: 71
Failed: 0
Failure IDs: None

node evals/graders/exact-property-grader.js
Property checks: 80
Passed: 80
Failed: 0
```

## Implementation Change

The IPv4 detector now treats a trailing dot as sentence punctuation only when the dot is followed by the end of input, whitespace, or closing punctuation. It still rejects IPv4 candidates followed by a dot and another token character, preserving larger dotted numeric sequences and hostname-embedded values.

This was not treated as a new specification ambiguity. `SPEC_FINAL.md` already requires standalone valid non-loopback IPv4 addresses to redact, while preserving version contexts, loopback addresses, larger dotted numeric sequences, and hostname-embedded values.

Core sanitizer freeze:
After F7 and the full regression suite pass, the core sanitizer should remain frozen unless another high-severity privacy/security regression is found.
