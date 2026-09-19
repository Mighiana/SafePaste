# Stakeholder Map

SafePaste serves people who need to share technical text without leaking credentials, personal data, or environment details. The product deliberately avoids claiming that automated redaction is perfect; its purpose is to support a human review step before sharing.

## Stakeholders

| Stakeholder | Wants | Fears | Design Implication |
| --- | --- | --- | --- |
| Developer / IT support engineer | Useful diagnostic information, fast sanitization, minimal false positives, readable logs, convenient copying | Over-redaction, loss of debugging details, incorrect detection | Preserve surrounding context, show categories, make output reviewable before copying |
| Person whose data appears in the logs | Privacy, credentials protected, personal information not exposed | Email, IP, username, or token leaks; confidential data sent onward | Default to redacting high-risk values and never transmit pasted content |
| Security / compliance team | Aggressive secret detection, predictable behavior, no network transmission, secure defaults | False negatives, credential leaks, unsafe AI-generated implementation | Keep local-only architecture, write tests and static checks for security invariants |
| Support recipient | Enough technical context to solve the issue | Logs so heavily sanitized that troubleshooting becomes impossible | Use category labels and scoped replacements instead of deleting entire lines |

## Required Conflicts

### Conflict A: Privacy vs Diagnostic Usefulness

Aggressive redaction protects people whose data appears in logs, but it can also remove information needed to diagnose a technical problem. For example, replacing every IP address may protect network details, but it can make routing, binding, or firewall problems harder to understand.

SafePaste balances this by preserving surrounding text, using descriptive replacement labels, and keeping the user in control before sharing.

### Conflict B: Detection Sensitivity vs False Positives

Security and compliance stakeholders prefer broad detection because missing a secret can be costly. Developers and support recipients need ordinary identifiers, build IDs, and harmless technical strings to remain intact.

SafePaste balances this by requiring stronger evidence for generic secrets, validating IPv4 octets, and documenting unresolved borderline cases instead of pretending they do not exist.

## Stakeholder Priority Notes

Credential protection is prioritized over preserving exact secret values. Diagnostic usefulness is preserved where practical by retaining log structure, keys, timestamps, messages, and non-sensitive values.
