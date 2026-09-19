# Human Rubric

This rubric was created before applying manual case judgments for the Session 7 grader comparison. It is intended for human-in-the-loop review of sanitized SafePaste outputs, especially where deterministic privacy properties do not fully answer whether the result is useful or proportionate.

No external LLM or model-as-judge API is used. That choice preserves SafePaste's local-only privacy architecture. Exact/property grading is appropriate for deterministic security and privacy checks; diagnostic usefulness and proportionality require human judgment.

## Rubric Items

For each item, choose `PASS`, `FAIL`, or `UNSURE`.

| ID | Criterion | PASS | FAIL | UNSURE |
| --- | --- | --- | --- | --- |
| H1 Privacy | Sensitive information that should be protected is removed. | The sensitive value is absent or safely replaced. | Sensitive information remains visible. | It is unclear whether the value is sensitive or adequately protected. |
| H2 Diagnostic usefulness | Enough technical context remains to understand or troubleshoot the log. | The useful surrounding context remains. | Redaction removes information needed to understand the issue. | A domain expert would need to decide if the remaining context is enough. |
| H3 Readability | The sanitized result remains understandable. | The output is clear and readable. | The output is confusing or structurally broken. | The output is partly readable but may be ambiguous. |
| H4 Proportionality | The tool does not redact harmless information unnecessarily. | Redactions feel scoped to likely sensitive values. | Harmless or highly useful values are unnecessarily redacted. | The sensitivity/usefulness trade-off is unclear. |
| H5 Shareability | The evaluator would be comfortable sharing the sanitized output. | The output appears appropriate to share for support or AI assistance. | The output still seems unsafe or unusable to share. | The evaluator would ask for more context before sharing. |

Overall verdict:

- `PASS`: The sanitized output is privacy-protective and useful enough to share.
- `FAIL`: The output either leaks sensitive information or loses too much important context.
- `NEEDS DISCUSSION`: The output is not clearly wrong, but a human stakeholder decision is needed.

Confidence:

- 1: very low confidence
- 2: low confidence
- 3: moderate confidence
- 4: high confidence
- 5: very high confidence

## Manual Rubric Run

Evaluator:
AI-assisted development evaluator applying the human rubric manually. This is not an external user study, and a course human evaluator can override these judgments.

Date:
2026-08-13

| Case | Input | Current sanitized output | H1 Privacy | H2 Diagnostic usefulness | H3 Readability | H4 Proportionality | H5 Shareability | Overall verdict | Confidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| EV-001 | `api_key=abc1234567890SECRET request_id=req-42` | `api_key=[REDACTED_API_KEY] request_id=req-42` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Credential is removed and request context remains. |
| EV-005 | `{"apiKey":"abc1234567890SECRET","mode":"test"}` | `{"apiKey":"[REDACTED_API_KEY]","mode":"test"}` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | JSON structure and mode context remain readable. |
| EV-013 | `Parser saw 999.999.999.999 in a bad fixture` | `Parser saw 999.999.999.999 in a bad fixture` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | Invalid IP-like fixture is preserved, which supports false-positive control. |
| EV-029 | `Error opening C:\Users\usman\Desktop\secret.log` | `Error opening C:\Users\[REDACTED_USERNAME]\Desktop\secret.log` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | Username is protected while path shape and filename remain useful; current marker is standardized after Manual Test 4. |
| EV-039 | `PWD=/workspace/project npm test` | `PWD=/workspace/project npm test` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | `PWD` is interpreted as working-directory context, not a password. |
| EV-040 before Manual Test 2 refinement | `Localhost: 127.0.0.1` | `Localhost: [REDACTED_IP_ADDRESS]` | PASS | FAIL | PASS | FAIL | UNSURE | NEEDS DISCUSSION | 4 | This was the real grader disagreement: privacy behavior matched the automated IP rule, but localhost is often essential debugging context. |
| EV-040 after Manual Test 2 refinement | `Localhost: 127.0.0.1` | `Localhost: 127.0.0.1` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | The refined policy preserves loopback addresses. Privacy risk is judged lower than the diagnostic cost for 127.0.0.0/8. |
| EV-041 | `1.2.3.4.5` | `1.2.3.4.5` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Preserving the larger dotted numeric sequence avoids an IPv4 substring false positive. |
| EV-044 | `/home/alice/project/error.log` | `/home/[REDACTED_USERNAME]/project/error.log` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | Username is removed while the project path and filename remain useful; current marker is standardized after Manual Test 4. |
| EV-046 | `/var/log/nginx/error.log` | `/var/log/nginx/error.log` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Non-home system log path remains unchanged, supporting proportionality. |
| EV-048 before Manual Test 3 refinement | `username=musman24\nuser_name=alice_dev\nuser=bob-admin` | `username=musman24\nuser_name=alice_dev\nuser=bob-admin` | FAIL | PASS | PASS | PASS | FAIL | FAIL | 5 | Explicit account identifiers remained visible. This was a privacy failure. |
| EV-048 after Manual Test 3 refinement | `username=musman24\nuser_name=alice_dev\nuser=bob-admin` | `username=[REDACTED_USERNAME]\nuser_name=[REDACTED_USERNAME]\nuser=[REDACTED_USERNAME]` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Account identifiers are removed while field names remain useful. |
| EV-049 | `{"username":"musman24","role":"admin"}` | `{"username":"[REDACTED_USERNAME]","role":"admin"}` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | JSON structure and harmless role context remain. |
| EV-050 | `name=Muhammad` | `name=Muhammad` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | Generic `name=` is preserved because arbitrary personal-name detection is out of scope. |
| EV-052 before Manual Test 3 refinement | `release=1.2.3.4` | `release=[REDACTED_IP_ADDRESS]` | PASS | FAIL | PASS | FAIL | FAIL | FAIL | 5 | This was the F5 disagreement: syntactic IP privacy looked successful, but release version context was unnecessarily removed. |
| EV-052 after Manual Test 3 refinement | `release=1.2.3.4` | `release=1.2.3.4` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Version context is preserved after the narrow version-field policy refinement. |
| EV-055 | `client_ip=10.20.30.40` | `client_ip=[REDACTED_IP_ADDRESS]` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | The version-field exception remains narrow; explicit IP fields still redact. |
| EV-058 before Manual Test 4 refinement | `Release 1.2.3.4 passed QA yesterday.` | `Release [REDACTED_IP_ADDRESS] passed QA yesterday.` | PASS | FAIL | PASS | FAIL | FAIL | FAIL | 5 | This was the F6 disagreement: syntactic IP privacy looked successful, but obvious release-version context was removed. |
| EV-058 after Manual Test 4 refinement | `Release 1.2.3.4 passed QA yesterday.` | `Release 1.2.3.4 passed QA yesterday.` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Direct prose release context is preserved after the narrow Manual Test 4 refinement. |
| EV-062 | `Server 10.20.30.40 failed` | `Server [REDACTED_IP_ADDRESS] failed` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Non-version network prose remains redaction-eligible. |
| EV-065 before Manual Test 5 fix | `Connection received from 192.168.20.50.` | `Connection received from 192.168.20.50.` | FAIL | PASS | PASS | PASS | FAIL | FAIL | 5 | This was F7: a standalone valid non-loopback IPv4 address remained visible before sentence punctuation. |
| EV-065 after Manual Test 5 fix | `Connection received from 192.168.20.50.` | `Connection received from [REDACTED_IP_ADDRESS].` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Privacy is restored while the sentence punctuation and surrounding network context remain readable. |
| EV-069 | `Version 3.4.5.6 deployed.` | `Version 3.4.5.6 deployed.` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Version context remains visible after the F7 boundary fix. |
| EV-071 | `https://10.20.30.40.example.com/status` | `https://10.20.30.40.example.com/status` | PASS | PASS | PASS | PASS | PASS | PASS | 4 | Hostname-embedded IPv4-shaped text remains visible; a domain expert could still request stricter URL handling later. |
| EV-072 Manual Test 6 borderline limitation | `Firmware 1.2.3.4 installed successfully.` | `Firmware [REDACTED_IP_ADDRESS] installed successfully.` | PASS | FAIL | PASS | FAIL | UNSURE | NEEDS DISCUSSION | 4 | Likely firmware-version context is over-redacted, but this is intentionally recorded as a known limitation rather than a new keyword exception. |
| MT-7A IPv4 redaction ON | `client_ip=192.168.20.50 localhost=127.0.0.1 email=alex@example.com password=secret123` | `client_ip=[REDACTED_IP_ADDRESS] localhost=127.0.0.1 email=[REDACTED_EMAIL] password=[REDACTED_PASSWORD]` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | Default mode redacts network IPv4, email, and password while preserving loopback debugging context. |
| MT-7B IPv4 redaction OFF | `client_ip=192.168.20.50 localhost=127.0.0.1 email=alex@example.com password=secret123` | `client_ip=192.168.20.50 localhost=127.0.0.1 email=[REDACTED_EMAIL] password=[REDACTED_PASSWORD]` | PASS | PASS | PASS | PASS | PASS | PASS | 5 | The user-controlled IPv4 opt-out preserves network IP context without disabling unrelated email or credential protections. |
