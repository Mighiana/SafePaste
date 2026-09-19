# Manual Test 2 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 2, followed by local reproduction against the then-current sanitizer before code changes.

## Observed Manual Passes

- Email addresses were redacted.
- `192.168.10.44` was redacted.
- `8.8.8.8` was redacted.
- `256.10.20.30` was correctly preserved as invalid IPv4.
- Passwords were redacted.
- API keys were redacted.
- Authorization/Bearer token was redacted.
- AWS access key was redacted.
- Slack token was redacted.
- Windows home-path username was redacted.
- Harmless identifiers remained unchanged.
- HTML/script-like input remained literal text.
- Unicode remained intact.

## Before Results Reproduced Locally

Command:

```text
node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); for (const input of ['1.2.3.4.5','127.0.0.1','127.0.0.2','127.255.255.255','/home/usman/projects/safepaste/server.log','/var/log/nginx/error.log']) { const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount})); }"
```

Observed output before fixes:

```text
{"input":"1.2.3.4.5","sanitized":"[REDACTED_IP_ADDRESS].5","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"127.0.0.1","sanitized":"[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"127.0.0.2","sanitized":"[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"127.255.255.255","sanitized":"[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"/home/usman/projects/safepaste/server.log","sanitized":"/home/usman/projects/safepaste/server.log","categories":[],"redactionCount":0}
{"input":"/var/log/nginx/error.log","sanitized":"/var/log/nginx/error.log","categories":[],"redactionCount":0}
```

## Findings

### F1: IPv4 Substring False Positive

Input:

```text
1.2.3.4.5
```

Actual before fix:

```text
[REDACTED_IP_ADDRESS].5
```

Expected:

```text
1.2.3.4.5
```

Diagnosis:
The IPv4 detector matched a valid-looking four-octet substring inside a larger dotted numeric sequence.

### F2: Loopback Diagnostic-Usefulness Conflict

Input:

```text
127.0.0.1
```

Actual before policy refinement:

```text
[REDACTED_IP_ADDRESS]
```

Diagnosis:
This was not simply a coding bug. Automated privacy grading could reasonably consider the redaction successful, while human diagnostic-usefulness grading considered it unnecessarily destructive. The accepted policy after Manual Test 2 is to preserve IPv4 loopback addresses in `127.0.0.0/8`.

### F3: Linux Home Path Username Coverage

Input:

```text
/home/usman/projects/safepaste/server.log
```

Actual before fix:

```text
/home/usman/projects/safepaste/server.log
```

Expected:

```text
/home/[REDACTED_USER]/projects/safepaste/server.log
```

Diagnosis:
`SPEC_v1.md` included local file paths/usernames where reasonably detectable, and `SPEC_FINAL.md` included common user-directory path forms. The current implementation intended to support `/home/` paths, but the detector's leading word-boundary prevented a path starting with `/home/` from matching.

## After Results

Command:

```text
node tests/test-sanitizer.js
```

Result after sanitizer fix:

- Total unit tests: 28
- Passed: 28
- Failed: 0

Focused reproduction command:

```text
node -e "const {sanitize}=require('./SafePaste/src/sanitizer'); for (const input of ['1.2.3.4.5','127.0.0.1','127.0.0.2','127.255.255.255','192.168.10.44','8.8.8.8','/home/usman/projects/safepaste/server.log','/home/alice/project/error.log','/home/bob/','/var/log/nginx/error.log','/usr/local/bin']) { const r=sanitize(input); console.log(JSON.stringify({input, sanitized:r.sanitized, categories:r.categories, redactionCount:r.redactionCount})); }"
```

Observed output after fixes:

```text
{"input":"1.2.3.4.5","sanitized":"1.2.3.4.5","categories":[],"redactionCount":0}
{"input":"127.0.0.1","sanitized":"127.0.0.1","categories":[],"redactionCount":0}
{"input":"127.0.0.2","sanitized":"127.0.0.2","categories":[],"redactionCount":0}
{"input":"127.255.255.255","sanitized":"127.255.255.255","categories":[],"redactionCount":0}
{"input":"192.168.10.44","sanitized":"[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"8.8.8.8","sanitized":"[REDACTED_IP_ADDRESS]","categories":["IP_ADDRESS"],"redactionCount":1}
{"input":"/home/usman/projects/safepaste/server.log","sanitized":"/home/[REDACTED_USER]/projects/safepaste/server.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"/home/alice/project/error.log","sanitized":"/home/[REDACTED_USER]/project/error.log","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"/home/bob/","sanitized":"/home/[REDACTED_USER]/","categories":["PATH_OR_USERNAME"],"redactionCount":1}
{"input":"/var/log/nginx/error.log","sanitized":"/var/log/nginx/error.log","categories":[],"redactionCount":0}
{"input":"/usr/local/bin","sanitized":"/usr/local/bin","categories":[],"redactionCount":0}
```

## Regression Tests Added Before Fix

Command:

```text
node tests/test-sanitizer.js
```

Result before sanitizer fix:

- Total unit tests: 28
- Passed: 22
- Failed: 6

Failing tests:

- `preserves IPv4-like substrings inside larger dotted numeric sequences`
- `preserves 127.0.0.1 loopback by default`
- `preserves 127.0.0.2 loopback by default`
- `preserves 127.255.255.255 loopback by default`
- `redacts Linux home path username`
- `redacts Linux home path username with trailing slash`
