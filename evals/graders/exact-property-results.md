# Exact/Property Grader Results

Grader type: automated exact/property checks over deterministic sanitizer output.

Cases graded: EV-001, EV-005, EV-013, EV-029, EV-039, EV-040, EV-041, EV-044, EV-046, EV-048, EV-049, EV-050, EV-052, EV-055, EV-058, EV-062, EV-065, EV-069, EV-071, EV-072, EV-073
Property checks: 91
Passed: 91
Failed: 0

| Case ID | Expected property | Actual behavior | Result | Reason |
| --- | --- | --- | --- | --- |
EV-001 | Original sensitive value no longer appears: abc1234567890SECRET | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-001 | Expected marker or harmless context appears: api_key= | Expected text present. | PASS | Required marker/context was preserved.
EV-001 | Expected marker or harmless context appears: [REDACTED_API_KEY] | Expected text present. | PASS | Required marker/context was preserved.
EV-001 | Expected marker or harmless context appears: request_id=req-42 | Expected text present. | PASS | Required marker/context was preserved.
EV-001 | Detected category includes API_KEY | Categories: API_KEY | PASS | Expected category was reported.
EV-001 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-005 | Original sensitive value no longer appears: abc1234567890SECRET | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-005 | Expected marker or harmless context appears: "apiKey" | Expected text present. | PASS | Required marker/context was preserved.
EV-005 | Expected marker or harmless context appears: [REDACTED_API_KEY] | Expected text present. | PASS | Required marker/context was preserved.
EV-005 | Expected marker or harmless context appears: "mode":"test" | Expected text present. | PASS | Required marker/context was preserved.
EV-005 | Detected category includes API_KEY | Categories: API_KEY | PASS | Expected category was reported.
EV-005 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-013 | Must preserve values: sanitized output equals input | Parser saw 999.999.999.999 in a bad fixture | PASS | Output preserved exactly as required.
EV-013 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-013 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-029 | Original sensitive value no longer appears: usman | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-029 | Expected marker or harmless context appears: C:\Users\[REDACTED_USERNAME] | Expected text present. | PASS | Required marker/context was preserved.
EV-029 | Expected marker or harmless context appears: \Desktop\secret.log | Expected text present. | PASS | Required marker/context was preserved.
EV-029 | Detected category includes PATH_OR_USERNAME | Categories: PATH_OR_USERNAME | PASS | Expected category was reported.
EV-029 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-039 | Must preserve values: sanitized output equals input | PWD=/workspace/project npm test | PASS | Output preserved exactly as required.
EV-039 | Detected category excludes PASSWORD | Categories: none | PASS | Unexpected category was absent.
EV-039 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-040 | Must preserve values: sanitized output equals input | Localhost: 127.0.0.1 | PASS | Output preserved exactly as required.
EV-040 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-040 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-041 | Must preserve values: sanitized output equals input | 1.2.3.4.5 | PASS | Output preserved exactly as required.
EV-041 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-041 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-044 | Original sensitive value no longer appears: alice | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-044 | Expected marker or harmless context appears: /home/[REDACTED_USERNAME]/project/error.log | Expected text present. | PASS | Required marker/context was preserved.
EV-044 | Detected category includes PATH_OR_USERNAME | Categories: PATH_OR_USERNAME | PASS | Expected category was reported.
EV-044 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-046 | Must preserve values: sanitized output equals input | /var/log/nginx/error.log | PASS | Output preserved exactly as required.
EV-046 | Detected category excludes PATH_OR_USERNAME | Categories: none | PASS | Unexpected category was absent.
EV-046 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-048 | Original sensitive value no longer appears: musman24 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-048 | Original sensitive value no longer appears: alice_dev | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-048 | Original sensitive value no longer appears: bob-admin | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-048 | Expected marker or harmless context appears: username=[REDACTED_USERNAME] | Expected text present. | PASS | Required marker/context was preserved.
EV-048 | Expected marker or harmless context appears: user_name=[REDACTED_USERNAME] | Expected text present. | PASS | Required marker/context was preserved.
EV-048 | Expected marker or harmless context appears: user=[REDACTED_USERNAME] | Expected text present. | PASS | Required marker/context was preserved.
EV-048 | Detected category includes USERNAME | Categories: USERNAME | PASS | Expected category was reported.
EV-048 | Redaction count is 3 | Redaction count: 3 | PASS | Redaction count matched.
EV-049 | Original sensitive value no longer appears: musman24 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-049 | Expected marker or harmless context appears: "username":"[REDACTED_USERNAME]" | Expected text present. | PASS | Required marker/context was preserved.
EV-049 | Expected marker or harmless context appears: "role":"admin" | Expected text present. | PASS | Required marker/context was preserved.
EV-049 | Detected category includes USERNAME | Categories: USERNAME | PASS | Expected category was reported.
EV-049 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-050 | Must preserve values: sanitized output equals input | name=Muhammad | PASS | Output preserved exactly as required.
EV-050 | Detected category excludes USERNAME | Categories: none | PASS | Unexpected category was absent.
EV-050 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-052 | Must preserve values: sanitized output equals input | release=1.2.3.4 | PASS | Output preserved exactly as required.
EV-052 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-052 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-055 | Original sensitive value no longer appears: 10.20.30.40 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-055 | Expected marker or harmless context appears: client_ip= | Expected text present. | PASS | Required marker/context was preserved.
EV-055 | Expected marker or harmless context appears: [REDACTED_IP_ADDRESS] | Expected text present. | PASS | Required marker/context was preserved.
EV-055 | Detected category includes IP_ADDRESS | Categories: IP_ADDRESS | PASS | Expected category was reported.
EV-055 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-058 | Must preserve values: sanitized output equals input | Release 1.2.3.4 passed QA yesterday. | PASS | Output preserved exactly as required.
EV-058 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-058 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-062 | Original sensitive value no longer appears: 10.20.30.40 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-062 | Expected marker or harmless context appears: Server  | Expected text present. | PASS | Required marker/context was preserved.
EV-062 | Expected marker or harmless context appears: [REDACTED_IP_ADDRESS] | Expected text present. | PASS | Required marker/context was preserved.
EV-062 | Expected marker or harmless context appears:  failed | Expected text present. | PASS | Required marker/context was preserved.
EV-062 | Detected category includes IP_ADDRESS | Categories: IP_ADDRESS | PASS | Expected category was reported.
EV-062 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-065 | Original sensitive value no longer appears: 192.168.20.50 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-065 | Expected marker or harmless context appears: Connection received from  | Expected text present. | PASS | Required marker/context was preserved.
EV-065 | Expected marker or harmless context appears: [REDACTED_IP_ADDRESS]. | Expected text present. | PASS | Required marker/context was preserved.
EV-065 | Detected category includes IP_ADDRESS | Categories: IP_ADDRESS | PASS | Expected category was reported.
EV-065 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-069 | Must preserve values: sanitized output equals input | Version 3.4.5.6 deployed. | PASS | Output preserved exactly as required.
EV-069 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-069 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-071 | Must preserve values: sanitized output equals input | https://10.20.30.40.example.com/status | PASS | Output preserved exactly as required.
EV-071 | Detected category excludes IP_ADDRESS | Categories: none | PASS | Unexpected category was absent.
EV-071 | Redaction count is 0 | Redaction count: 0 | PASS | Redaction count matched.
EV-072 | Original sensitive value no longer appears: 1.2.3.4 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-072 | Expected marker or harmless context appears: Firmware  | Expected text present. | PASS | Required marker/context was preserved.
EV-072 | Expected marker or harmless context appears: [REDACTED_IP_ADDRESS] | Expected text present. | PASS | Required marker/context was preserved.
EV-072 | Expected marker or harmless context appears:  installed successfully. | Expected text present. | PASS | Required marker/context was preserved.
EV-072 | Detected category includes IP_ADDRESS | Categories: IP_ADDRESS | PASS | Expected category was reported.
EV-072 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
EV-073 | Original sensitive value no longer appears: FakeSecretValue987 | Value absent from sanitized output. | PASS | Sensitive value was removed.
EV-073 | Expected marker or harmless context appears: secret= | Expected text present. | PASS | Required marker/context was preserved.
EV-073 | Expected marker or harmless context appears: [REDACTED_SECRET] | Expected text present. | PASS | Required marker/context was preserved.
EV-073 | Detected category includes SECRET | Categories: SECRET | PASS | Expected category was reported.
EV-073 | Redaction count is 1 | Redaction count: 1 | PASS | Redaction count matched.
