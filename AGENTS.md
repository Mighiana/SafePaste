# AGENTS.md

SafePaste is a local-only browser log sanitizer for removing likely sensitive data before a human shares logs. The app must remain small, deterministic, and auditable.

## Architecture

- `index.html`, `styles.css`, and `app.js` provide the UI.
- `src/sanitizer.js` owns detection, redaction, and match metadata.
- `tests/test-sanitizer.js` verifies deterministic sanitizer behavior.
- `evals/run-evals.js` runs specification-linked evaluation cases.

## Privacy Invariants

- No network calls.
- No backend.
- No analytics, telemetry, third-party scripts, remote fonts, or remote CDN libraries.
- No persistence of pasted logs in localStorage, sessionStorage, cookies, IndexedDB, or files.
- User-controlled log text must be displayed with safe DOM APIs such as `textContent`.

## Security Rules

- Never hardcode credentials or realistic secrets.
- Do not introduce dependencies without explicit human approval.
- Do not delete failing tests or weaken assertions to force a pass.
- Do not hardcode expected outputs inside implementation logic.
- Destructive actions require confirmation.

## Testing Expectations

- Run unit tests after sanitizer changes.
- Run evals after behavior changes.
- Run static privacy/security checks before finalizing.
- Record real failures in `evals/results_v1.md`, `evals/results_final.md`, `RED_TEAM.md`, and `AI_WORKLOG.md` as appropriate.

## Ambiguity Handling

If a requirement is ambiguous, document the trade-off and choose the most conservative local-only behavior that preserves user review. Do not rewrite `SPEC_v1.md` after implementation begins.
