# SafePaste Final Evaluation Results

Refreshed after final regression F8 fix on 2026-08-13.

## Commands Run

```text
node tests/test-sanitizer.js
node evals/run-evals.js --write evals/results_final.md
node evals/graders/exact-property-grader.js --write evals/graders/exact-property-results.md
requested six-case final regression sweep
```

## Final Regression F8 Results

- Pre-fix unit result after adding the regression test: 37/38 tests passed; `redacts explicit structured secret fields` failed.
- Pre-fix eval result after adding EV-073: 72/73 eval cases passed; failure ID EV-073.
- Unit tests after fix: 38/38 passed.
- Eval cases after fix: 73/73 passed.
- Automated exact/property grader after fix: 21 cases, 91/91 property checks passed.
- Requested regression sweep after fix: 6/6 passed.
- Remaining failures from executed checks: none.

# SafePaste Evaluation Results

## Summary

- Total eval cases: 73
- Passed: 73
- Failed: 0
- Failure IDs: None

## Case Results

| ID | Layer | Category | Stakeholder | Requirement | Result |
| --- | --- | --- | --- | --- | --- |
EV-001 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
EV-002 | product | secret/api-key | Person whose data appears in the logs | R5, R12 | PASS
EV-003 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
EV-004 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
EV-005 | product | secret/api-key | Security / compliance team | R5, R12 | PASS
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
EV-037 | product | authentication/token | Security / compliance team | R5 | PASS
EV-038 | product | authentication/token | Security / compliance team | R5 | PASS
EV-039 | product | false-positive | Developer / IT support engineer | R12, R14 | PASS
EV-040 | product | borderline/ip-diagnostic | Developer / IT support engineer | R6, R10, R12 | PASS
EV-041 | product | false-positive/ip | Developer / IT support engineer | R6, R12, R14 | PASS
EV-042 | product | borderline/ip-diagnostic | Developer / IT support engineer | R6, R10, R12 | PASS
EV-043 | product | borderline/ip-diagnostic | Developer / IT support engineer | R6, R10, R12 | PASS
EV-044 | product | path-or-username | Person whose data appears in the logs | R13, R12 | PASS
EV-045 | product | path-or-username | Person whose data appears in the logs | R13, R12 | PASS
EV-046 | product | false-positive/path | Support recipient | R12, R14 | PASS
EV-047 | product | false-positive/path | Support recipient | R12, R14 | PASS
EV-048 | product | structured-username | Person whose data appears in the logs | R13, R12 | PASS
EV-049 | product | structured-username | Person whose data appears in the logs | R13, R12 | PASS
EV-050 | product | false-positive/username | Developer / IT support engineer | R12, R14 | PASS
EV-051 | product | false-positive/username | Developer / IT support engineer | R12, R14 | PASS
EV-052 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-053 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-054 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-055 | product | ip | Security / compliance team | R6, R12 | PASS
EV-056 | product | ip | Security / compliance team | R6, R12 | PASS
EV-057 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-058 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-059 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-060 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-061 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-062 | product | ip | Security / compliance team | R6, R12 | PASS
EV-063 | product | ip | Security / compliance team | R6, R12 | PASS
EV-064 | product | ip | Security / compliance team | R6, R12 | PASS
EV-065 | product | ip | Security / compliance team | R6, R12 | PASS
EV-066 | product | ip | Security / compliance team | R6, R12 | PASS
EV-067 | product | ip | Security / compliance team | R6, R12 | PASS
EV-068 | product | ip | Security / compliance team | R6, R12 | PASS
EV-069 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-070 | product | false-positive/ip-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-071 | product | false-positive/ip-hostname | Developer / IT support engineer | R6, R12, R14 | PASS
EV-072 | product | known-limitation/ip-firmware-version | Developer / IT support engineer | R6, R12, R14 | PASS
EV-073 | product | secret/generic-structured | Security / compliance team | R5, R12 | PASS
