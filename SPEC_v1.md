# SafePaste Specification v1

This specification was written before product implementation. It must remain preserved after implementation begins.

## 1. Product Description

SafePaste is a local browser-based log sanitizer for people who need to share technical text without exposing sensitive values. A user pastes logs into the page, runs deterministic local detection rules, reviews the sanitized output, and copies the sanitized text if satisfied. The app does not use a backend, login, database, analytics, external AI API, or remote scripts. SafePaste is a review aid, not a guarantee that every secret has been removed.

## 2. Intended Users

Primary users:

- developers
- IT support engineers
- technical students
- technical users preparing logs for support, AI tools, GitHub issues, chat, email, or forums

Secondary users:

- people whose personal data appears in logs
- security or compliance reviewers
- support recipients who need enough context to troubleshoot

## 3. Stakeholder Map

The stakeholder map is documented in [docs/STAKEHOLDER_MAP.md](docs/STAKEHOLDER_MAP.md). Key conflicts are privacy vs diagnostic usefulness, and detection sensitivity vs false positives.

## 4. Functional Requirements

- R1: Application works entirely client-side.
- R2: User can paste arbitrary text.
- R3: Application produces sanitized output.
- R4: Application detects email addresses.
- R5: Application detects common credentials and tokens.
- R6: Application detects valid IPv4 addresses and does not classify invalid octets as IPv4.
- R7: Application shows detected sensitive-data categories.
- R8: Application shows a redaction count.
- R9: User can copy sanitized output.
- R10: Application includes a clear/reset action.
- R11: User can review original and sanitized text before sharing.
- R12: Application preserves non-sensitive context where practical.
- R13: Local file paths and usernames may be redacted only when reasonably detectable.
- R14: Ordinary short identifiers such as `abc123xyz` should normally remain unchanged unless there is strong evidence they are sensitive.

## 5. Privacy And Security Requirements

- PS1: Pasted user content must never be sent over the network.
- PS2: Pasted logs must not be stored in localStorage, sessionStorage, cookies, IndexedDB, backend storage, or other persistence.
- PS3: The app must not include tracking, analytics, telemetry, third-party scripts, remote fonts, or remote CDN libraries.
- PS4: User-controlled content must be handled with safe DOM APIs; prefer `textContent` over `innerHTML`.
- PS5: The repository must not hardcode API keys, passwords, secrets, or credentials.
- PS6: Failing tests must not be removed or weakened merely because they fail.
- PS7: Expected outputs must not be hardcoded just to satisfy evaluations.
- PS8: Packages must not be installed silently.
- PS9: External services must not be added without explicit human approval.
- PS10: Destructive actions must require confirmation.

## 6. Accessibility Requirements

- A1: The app must be keyboard usable.
- A2: Form controls must have proper labels.
- A3: The page must use semantic HTML landmarks and headings.
- A4: Focus indicators must be visible.
- A5: Status updates must be understandable without relying solely on color.
- A6: Buttons must have clear accessible names.

## 7. AI Development Rules

- AI1: Never add network calls.
- AI2: Never persist pasted text.
- AI3: Never delete or weaken failing tests to get a pass.
- AI4: Ask before adding dependencies or package installation.
- AI5: Never bypass security hooks.
- AI6: Prefer safe DOM APIs for user-controlled content.
- AI7: Run sanitizer tests after modifying sanitizer logic.
- AI8: Surface ambiguous requirements instead of silently resolving all trade-offs.
- AI9: Preserve `SPEC_v1.md` after implementation begins.
- AI10: Record real failures and do not fabricate development history.

## 8. Principles

Principle 1: Protect privacy without unnecessarily destroying diagnostic usefulness.

Principle 2: The user remains the final decision-maker before sharing output.

Principle 3: Security controls should be enforceable and testable, not aspirational.

## 9. Borderline Case

The log contains:

```text
127.0.0.1
```

Should it always be redacted? Redacting it protects consistency and avoids leaking network-related information, but localhost is often essential debugging context and usually does not identify a remote person or organization. This specification leaves the exact treatment of localhost visible as an open product question for testing and iteration.

## 10. TODO / Open Questions

- Should localhost and private IP ranges be redacted by default, made optional, or preserved?
- How aggressively should local usernames in paths be redacted?
- How should SafePaste communicate that it cannot guarantee every secret is detected?
- Should future versions support user-controlled category toggles, or would that increase accidental leaks?
