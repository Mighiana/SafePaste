# Grader Comparison

SafePaste uses two grader styles for selected evaluation cases:

- Automated exact/property grader: deterministic checks against sanitizer output properties.
- Human rubric grader: manual judgment over privacy, diagnostic usefulness, readability, proportionality, and shareability.

No external model-as-judge API was added. That would conflict with SafePaste's local-only privacy architecture unless explicitly approved.

## Cases Graded By Both Approaches

| Case | Automated verdict | Human verdict | Agreement/disagreement | Why | What this reveals about the specification |
| --- | --- | --- | --- | --- | --- |
| EV-001 | PASS | PASS | Agreement | API key value is removed while request ID context remains. | Deterministic property grading is well-suited to clear credential cases. |
| EV-005 | PASS | PASS | Agreement | JSON API key is removed and JSON context remains readable. | The post-v1 JSON credential fix is both machine-checkable and human-acceptable. |
| EV-013 | PASS | PASS | Agreement | Invalid IP-like fixture is preserved. | False-positive requirements can be expressed as exact preservation properties. |
| EV-029 | PASS | PASS | Agreement | Username is redacted while path shape remains useful. | Narrow path redaction supports both privacy and troubleshooting; current marker is standardized on `[REDACTED_USERNAME]`. |
| EV-039 | PASS | PASS | Agreement | `PWD=/workspace/project` is preserved. | The v1.3 change reduced a false positive that mattered to human usefulness. |
| EV-040 before Manual Test 2 refinement | PASS | NEEDS DISCUSSION | Disagreement | Automated grading confirmed valid IPv4 redaction. Human rubric found that redacting `127.0.0.1` removed important localhost debugging context. | The specification treated loopback as part of default IP redaction, but the grader disagreement exposed a real spec refinement need. |
| EV-040 after Manual Test 2 refinement | PASS | PASS | Agreement after spec change | Automated grading now checks preservation of loopback. Human rubric agrees diagnostic usefulness is improved. | The spec now distinguishes loopback from other valid IPv4 addresses. |
| EV-041 | PASS | PASS | Agreement | Automated and human graders both preserve `1.2.3.4.5`. | IPv4 detection must require complete IPv4 tokens, not substrings inside larger dotted numeric sequences. |
| EV-044 | PASS | PASS | Agreement | Automated and human graders both redact only the username segment in `/home/alice/...`. | Linux home paths are covered by the accepted local path/username policy. |
| EV-046 | PASS | PASS | Agreement | Automated and human graders both preserve `/var/log/nginx/error.log`. | The path policy must stay narrow and avoid broad Linux path redaction. |
| EV-048 before Manual Test 3 refinement | FAIL | FAIL | Agreement | The added property grader failed because structured username values remained visible; the human rubric also failed privacy/shareability. | `SPEC_v1.md` was ambiguous about explicit structured username fields, so `SPEC_FINAL.md` needed a narrow account-identifier policy. |
| EV-048 after Manual Test 3 refinement | PASS | PASS | Agreement after spec change | Structured username values are redacted while field names remain. | Explicit account fields have enough privacy signal to redact without arbitrary name detection. |
| EV-049 | PASS | PASS | Agreement | Quoted JSON username value is redacted and `role` context remains. | JSON username fields are practical to support with the same structured-field policy. |
| EV-050 | PASS | PASS | Agreement | `name=Muhammad` remains unchanged. | The username policy must not become arbitrary personal-name detection. |
| EV-052 before Manual Test 3 refinement | PASS under syntactic IP property; FAIL under updated preservation property | FAIL | Disagreement | The old syntactic IP interpretation treated `release=1.2.3.4` as successful IPv4 redaction, but the human rubric found that version context was unnecessarily removed. | The specification needed a narrow contextual exception for version-related fields. |
| EV-052 after Manual Test 3 refinement | PASS | PASS | Agreement after spec change | The version-shaped value is preserved in `release=` context. | Context can matter even when a token is syntactically IPv4-shaped. |
| EV-055 | PASS | PASS | Agreement | `client_ip=10.20.30.40` is still redacted. | The version-field exception is narrow and does not disable general IPv4 redaction. |
| EV-058 before Manual Test 4 refinement | PASS under syntactic IP property; FAIL under updated preservation property | FAIL | Disagreement | The old syntactic IP interpretation treated `Release 1.2.3.4...` as successful IPv4 redaction, but the human rubric found obvious release-version context was removed. | The specification needed to clarify direct prose version context without adding broad NLP. |
| EV-058 after Manual Test 4 refinement | PASS | PASS | Agreement after spec change | The version-shaped value is preserved in direct `Release` prose context. | The version exception now covers direct prose version keywords as well as key/value fields. |
| EV-062 | PASS | PASS | Agreement | `Server 10.20.30.40 failed` still redacts. | The prose version exception remains narrow and does not disable IP protection in ordinary network prose. |
| EV-065 before Manual Test 5 fix | FAIL | FAIL | Agreement | The automated property grader failed because `192.168.20.50` remained visible; the human rubric also failed privacy/shareability. | The final spec already required standalone non-loopback IPv4 redaction. The implementation boundary treated sentence punctuation too much like hostname or dotted-token syntax. |
| EV-065 after Manual Test 5 fix | PASS | PASS | Agreement after implementation fix | The IP is redacted and the sentence-ending period remains. | This was an implementation bug, not a new specification gap. |
| EV-069 | PASS | PASS | Agreement | `Version 3.4.5.6 deployed.` remains unchanged. | The F7 fix does not weaken the narrow prose version exception. |
| EV-071 | PASS | PASS | Agreement | `https://10.20.30.40.example.com/status` remains unchanged. | The F7 fix still preserves IPv4-shaped substrings embedded inside hostnames. |
| EV-072 Manual Test 6 | PASS | NEEDS DISCUSSION | Disagreement | Automated grading passes because the valid non-loopback IPv4-shaped token is redacted under the narrow deterministic policy. Human review sees `Firmware 1.2.3.4` as likely version context, so diagnostic usefulness and proportionality suffer. | Contextual disambiguation is intentionally best-effort rather than exhaustive. The sanitizer remains frozen instead of adding a speculative `Firmware` keyword exception. |

## Automated Exact/Property Grader Run

Command:

```text
node evals/graders/exact-property-grader.js
```

Summary:

- Cases graded after final regression F8: 21
- Property checks: 91
- Passed: 91
- Failed: 0

| Case ID | Expected property | Actual behavior | Result | Reason |
| --- | --- | --- | --- | --- |
| EV-001 | Original sensitive value no longer appears: `abc1234567890SECRET` | Value absent from sanitized output. | PASS | Sensitive value was removed. |
| EV-001 | Expected marker or harmless context appears: `api_key=` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-001 | Expected marker or harmless context appears: `[REDACTED_API_KEY]` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-001 | Expected marker or harmless context appears: `request_id=req-42` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-001 | Detected category includes `API_KEY` | Categories: `API_KEY` | PASS | Expected category was reported. |
| EV-001 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched. |
| EV-005 | Original sensitive value no longer appears: `abc1234567890SECRET` | Value absent from sanitized output. | PASS | Sensitive value was removed. |
| EV-005 | Expected marker or harmless context appears: `"apiKey"` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-005 | Expected marker or harmless context appears: `[REDACTED_API_KEY]` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-005 | Expected marker or harmless context appears: `"mode":"test"` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-005 | Detected category includes `API_KEY` | Categories: `API_KEY` | PASS | Expected category was reported. |
| EV-005 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched. |
| EV-013 | Must preserve values: sanitized output equals input | `Parser saw 999.999.999.999 in a bad fixture` | PASS | Output preserved exactly as required. |
| EV-013 | Detected category excludes `IP_ADDRESS` | Categories: none | PASS | Unexpected category was absent. |
| EV-013 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched. |
| EV-029 | Original sensitive value no longer appears: `usman` | Value absent from sanitized output. | PASS | Sensitive value was removed. |
| EV-029 | Expected marker or harmless context appears: `C:\Users\[REDACTED_USERNAME]` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-029 | Expected marker or harmless context appears: `\Desktop\secret.log` | Expected text present. | PASS | Required marker/context was preserved. |
| EV-029 | Detected category includes `PATH_OR_USERNAME` | Categories: `PATH_OR_USERNAME` | PASS | Expected category was reported. |
| EV-029 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched. |
| EV-039 | Must preserve values: sanitized output equals input | `PWD=/workspace/project npm test` | PASS | Output preserved exactly as required. |
| EV-039 | Detected category excludes `PASSWORD` | Categories: none | PASS | Unexpected category was absent. |
| EV-039 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched. |
| EV-040 | Must preserve values: sanitized output equals input | `Localhost: 127.0.0.1` | PASS | Output preserved exactly as required after policy refinement. |
| EV-041 | Must preserve values: sanitized output equals input | `1.2.3.4.5` | PASS | Output preserved exactly as required. |
| EV-044 | Original sensitive value no longer appears: `alice` | Value absent from sanitized output. | PASS | Username was removed. |
| EV-046 | Must preserve values: sanitized output equals input | `/var/log/nginx/error.log` | PASS | Non-home system path remained unchanged. |
| EV-048 | Original sensitive username values no longer appear | Values absent from sanitized output. | PASS | Structured username values were removed. |
| EV-048 | Required field names and `[REDACTED_USERNAME]` markers appear | Expected text present. | PASS | Field context was preserved. |
| EV-049 | JSON username value no longer appears | Value absent from sanitized output. | PASS | Structured JSON username value was removed. |
| EV-049 | JSON role context remains | `"role":"admin"` present. | PASS | Harmless context was preserved. |
| EV-050 | Must preserve values: sanitized output equals input | `name=Muhammad` | PASS | Arbitrary name field remained unchanged. |
| EV-052 | Must preserve values: sanitized output equals input | `release=1.2.3.4` | PASS | Version-field IPv4-shaped value remained unchanged. |
| EV-055 | Original IP value no longer appears | Value absent from sanitized output. | PASS | Explicit IP field was redacted. |
| EV-055 | Expected marker and field context appear | `client_ip=[REDACTED_IP_ADDRESS]` present. | PASS | Required context was preserved. |
| EV-058 | Must preserve values: sanitized output equals input | `Release 1.2.3.4 passed QA yesterday.` | PASS | Prose version-context IPv4-shaped value remained unchanged. |
| EV-062 | Original IP value no longer appears | Value absent from sanitized output. | PASS | Non-version prose IP address was redacted. |
| EV-062 | Expected marker and prose context appear | `Server [REDACTED_IP_ADDRESS] failed` present. | PASS | Required context was preserved. |
| EV-065 | Original IP value no longer appears | Value absent from sanitized output. | PASS | Standalone sentence-final IP address was redacted. |
| EV-065 | Expected marker and sentence punctuation appear | `Connection received from [REDACTED_IP_ADDRESS].` present. | PASS | Required context and punctuation were preserved. |
| EV-069 | Must preserve values: sanitized output equals input | `Version 3.4.5.6 deployed.` | PASS | Prose version-context IPv4-shaped value remained unchanged. |
| EV-071 | Must preserve values: sanitized output equals input | `https://10.20.30.40.example.com/status` | PASS | Hostname-embedded IPv4-shaped value remained unchanged. |
| EV-072 | Original IPv4-shaped value no longer appears | Value absent from sanitized output. | PASS | Current deterministic policy redacted the ambiguous firmware value. |
| EV-072 | Expected marker and firmware context appear | `Firmware [REDACTED_IP_ADDRESS] installed successfully.` present. | PASS | Required current-policy context was preserved. |
| EV-073 | Original structured secret value no longer appears | Value absent from sanitized output. | PASS | Final regression F8 sensitive value was removed. |
| EV-073 | Expected marker and field context appear | `secret=[REDACTED_SECRET]` present. | PASS | Required current-policy context was preserved. |

## Human Rubric Summary

The human rubric was applied manually in [human-rubric.md](human-rubric.md).

- Current cases graded: 20
- Current overall PASS: 19
- Current overall NEEDS DISCUSSION: 1
- Overall FAIL: 0
- Preserved before-refinement judgments: EV-040 NEEDS DISCUSSION, EV-048 FAIL, EV-052 FAIL, EV-058 FAIL, EV-065 FAIL

## Disagreement Analysis

EV-040 was the key disagreement before Manual Test 2 policy refinement.

Input:

```text
Localhost: 127.0.0.1
```

Before Manual Test 2 policy refinement:

```text
Localhost: [REDACTED_IP_ADDRESS]
```

After Manual Test 2 policy refinement:

```text
Localhost: 127.0.0.1
```

Original automated grader result:
PASS, because the valid IPv4 value is removed, the redaction marker appears, the `Localhost:` label remains, the `IP_ADDRESS` category is reported, and the redaction count is 1.

Human rubric result:
NEEDS DISCUSSION, because localhost is often important debugging context and does not carry the same privacy risk as many public or private network addresses.

Specification inspection:
Manual Test 2 showed this was more than a communication gap. The final policy now preserves IPv4 loopback addresses in `127.0.0.0/8`, while continuing to redact other valid IPv4 addresses when IPv4 redaction is enabled.

EV-052 was the key disagreement before Manual Test 3 policy refinement.

Input:

```text
release=1.2.3.4
```

Before Manual Test 3 policy refinement:

```text
release=[REDACTED_IP_ADDRESS]
```

After Manual Test 3 policy refinement:

```text
release=1.2.3.4
```

Pre-refinement automated syntactic interpretation:
PASS, because `1.2.3.4` is a valid non-loopback IPv4-shaped token and was removed.

Human rubric result:
FAIL, because `release=1.2.3.4` is more plausibly software version context than an address to contact or identify a network participant.

Specification inspection:
Manual Test 3 showed a real specification gap. The final policy now preserves IPv4-shaped values only when they are immediately associated with narrow version-related fields such as `release=`, `version=`, `app_version=`, or `software_version=`, while continuing to redact explicit IP fields.

EV-058 was the key disagreement before Manual Test 4 policy refinement.

Input:

```text
Release 1.2.3.4 passed QA yesterday.
```

Before Manual Test 4 policy refinement:

```text
Release [REDACTED_IP_ADDRESS] passed QA yesterday.
```

After Manual Test 4 policy refinement:

```text
Release 1.2.3.4 passed QA yesterday.
```

Pre-refinement automated syntactic interpretation:
PASS, because `1.2.3.4` is a valid non-loopback IPv4-shaped token and was removed.

Human rubric result:
FAIL, because the word `Release` directly before the value makes software-version context obvious enough that redaction harms diagnostic usefulness.

Specification inspection:
Manual Test 4 clarified that the version-context exception should include direct `Version` and `Release` prose associations, case-insensitively, while avoiding broad NLP and continuing to redact non-version prose IP addresses.

EV-065 was the key Manual Test 5 privacy failure. It was not a grader disagreement after the F7 property was added.

Input:

```text
Connection received from 192.168.20.50.
```

Before Manual Test 5 fix:

```text
Connection received from 192.168.20.50.
```

After Manual Test 5 fix:

```text
Connection received from [REDACTED_IP_ADDRESS].
```

Automated property result before fix:
FAIL, because the sensitive IPv4 value remained visible, the expected redaction marker was absent, the `IP_ADDRESS` category was absent, and the redaction count was 0 instead of 1.

Human rubric result before fix:
FAIL, because the output leaked a standalone valid non-loopback IPv4 address in ordinary network prose.

Specification inspection:
Manual Test 5 did not expose a new ambiguity. The final specification already required standalone valid non-loopback IPv4 addresses to redact unless they were loopback, version context, inside a larger dotted numeric token, or embedded in a hostname. The fix adjusted token-boundary handling so sentence-ending periods are preserved as punctuation rather than blocking the IP match.

EV-072 is the Manual Test 6 known borderline limitation and current grader disagreement.

Input:

```text
Firmware 1.2.3.4 installed successfully.
```

Current output:

```text
Firmware [REDACTED_IP_ADDRESS] installed successfully.
```

Automated property result:
PASS, because the current deterministic policy redacts valid non-loopback IPv4-shaped values unless they are in a narrow supported preservation context.

Human rubric result:
NEEDS DISCUSSION, because `Firmware 1.2.3.4` is likely a firmware version and redaction removes useful diagnostic context.

Specification inspection:
This is a known limitation rather than a new product change. SafePaste uses narrow, auditable contextual rules instead of general semantic or NLP classification. Adding every plausible version keyword would increase complexity and false-negative risk. The final specification now clarifies that contextual disambiguation is best-effort and not exhaustive.

Action taken:

- Updated EV-040 to require loopback preservation.
- Added EV-041 through EV-047 for Manual Test 2 findings.
- Added loopback, dotted-sequence, and Linux path regression tests.
- Added EV-048 through EV-057 for Manual Test 3 findings.
- Added structured username, arbitrary-name preservation, version-field, and explicit-IP-field regression tests.
- Added EV-058 through EV-064 for Manual Test 4 findings.
- Added direct prose version-context and non-version prose IP regression tests.
- Standardized current username markers on `[REDACTED_USERNAME]` while preserving historical evidence files.
- Added EV-065 through EV-071 for Manual Test 5 findings and preservation guards.
- Added sentence-final IPv4 boundary regression tests.
- Added EV-072 for the Manual Test 6 firmware-version known limitation and grader disagreement.
- Added EV-073 for the final regression F8 structured-secret privacy failure. This case was added to the automated exact/property grader; no human-rubric verdict is claimed for EV-073.
- Updated `SPEC_FINAL.md` for earlier spec refinements; Manual Test 5 required `CHANGELOG.md`, `DESIGN_DECISIONS.md`, and `AI_WORKLOG.md` updates but no `SPEC_FINAL.md` change.
- Reran unit tests, evals, and the automated exact/property grader.

## Unresolved Judgment Call

SafePaste now preserves IPv4 loopback addresses by default. A security/privacy evaluator may prefer uniform IP masking, but the accepted final policy prioritizes diagnostic usefulness for `127.0.0.0/8` because it usually identifies the local machine rather than a remote person or organization.

SafePaste also preserves IPv4-shaped values in a short list of version-related contexts. Future stakeholders may ask for additional field names or prose forms, but the current policy keeps the exception narrow to avoid weakening IP redaction.

SafePaste now also preserves direct `Version` and `Release` prose associations. Ambiguous prose outside those keywords remains governed by ordinary IPv4 redaction.

After Manual Test 5, the core sanitizer is frozen unless another high-severity privacy/security regression is found.

Manual Test 6 confirms the sanitizer remains frozen. `Firmware 1.2.3.4` is intentionally documented as a borderline limitation rather than a new keyword exception.
