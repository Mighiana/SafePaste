# Manual Test 6 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 6, followed by local reproduction against the frozen core sanitizer.

## Regression Passes Observed By User

- Standalone valid non-loopback IPv4 addresses are redacted.
- `Connection received from 192.168.20.50` regression is fixed.
- Loopback `127.0.0.0/8` is preserved.
- Explicit software version/release contexts are preserved.
- Malformed and larger dotted sequences are preserved.
- IPv4-like strings embedded in hostnames are preserved.
- Structured usernames are redacted.
- Windows/Linux home usernames are redacted.
- Ordinary names and usernames in prose are preserved.
- Emails and credentials are redacted.
- Harmless identifiers remain unchanged.
- System paths remain unchanged.
- Unicode remains intact.

## Known Borderline Limitation

Input:

```text
Firmware 1.2.3.4 installed successfully.
```

Observed current output:

```text
Firmware [REDACTED_IP_ADDRESS] installed successfully.
```

Local reproduction:

```text
{"input":"Firmware 1.2.3.4 installed successfully.","sanitized":"Firmware [REDACTED_IP_ADDRESS] installed successfully.","categories":["IP_ADDRESS"],"redactionCount":1}
```

Human interpretation:
Likely a firmware version rather than an IP address.

Automated exact/property interpretation:
PASS under the current deterministic policy because `1.2.3.4` is a valid non-loopback IPv4-shaped token outside the narrow supported `Version`/`Release` contexts.

Human rubric interpretation:
NEEDS DISCUSSION because privacy is protected, but diagnostic usefulness and proportionality suffer if the value is truly firmware-version context.

Decision:
Do not add another keyword exception for `Firmware`. The core sanitizer is frozen unless a high-severity privacy/security failure appears. SafePaste intentionally uses narrow, auditable contextual rules rather than broad semantic/NLP classification. This reduces complexity and privacy risk, but some ambiguous IPv4-shaped version strings may be over-redacted.

Mapped requirement:
R6, R12, R14.

Evidence mapping:
EV-072 records the automated/current-policy behavior. `human-rubric.md` and `grader-comparison.md` record the human-vs-automated disagreement.
