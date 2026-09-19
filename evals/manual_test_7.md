# Manual Test 7 Evidence

Date:
2026-08-13

Source:
User-performed manual Test 7, followed by a local spot-check of the same IPv4 toggle semantics.

## Purpose

Evaluate product behavior and human control for the IPv4 redaction toggle. This test checks whether SafePaste gives users scoped control over the privacy-versus-diagnostic-usefulness trade-off without disabling unrelated sanitizer protections.

## Run A: IPv4 Redaction ON

User-confirmed results:

- Network IPv4 addresses were redacted.
- Loopback addresses were preserved.
- Other privacy categories continued to redact.

Local spot-check:

```text
Input:
client_ip=192.168.20.50 localhost=127.0.0.1 email=alex@example.com password=secret123

Output:
client_ip=[REDACTED_IP_ADDRESS] localhost=127.0.0.1 email=[REDACTED_EMAIL] password=[REDACTED_PASSWORD]

Categories:
EMAIL, IP_ADDRESS, PASSWORD

Redaction count:
3
```

Human-control judgment:
PASS. The default privacy-protective mode redacts redaction-eligible network IPv4 addresses while preserving lower-risk loopback debugging context and continuing unrelated protections.

## Run B: IPv4 Redaction OFF

User-confirmed results:

- Network IPv4 addresses remained visible.
- Email redaction continued to work.
- Disabling IPv4 protection did not disable unrelated sanitizer rules.

Local spot-check:

```text
Input:
client_ip=192.168.20.50 localhost=127.0.0.1 email=alex@example.com password=secret123

Output:
client_ip=192.168.20.50 localhost=127.0.0.1 email=[REDACTED_EMAIL] password=[REDACTED_PASSWORD]

Categories:
EMAIL, PASSWORD

Redaction count:
2
```

Human-control judgment:
PASS. The IPv4 toggle is scoped correctly: it lets the user preserve network IP context for troubleshooting while email and credential redaction continue to operate.

## Conclusion

The IPv4 toggle is scoped correctly and gives the user control over the privacy-versus-diagnostic-usefulness trade-off.

No sanitizer behavior was changed based on Manual Test 7.
