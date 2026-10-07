# SafePaste Final Specification

This final specification reflects implementation, v1 evaluation, red-team testing, and security review. `SPEC_v1.md` remains preserved as the pre-implementation baseline.

## 1. Product Description

SafePaste is a local browser-based log sanitizer for people who need to share technical text while reducing the risk of leaking sensitive information. A user pastes logs, runs local deterministic detection rules, reviews the original and sanitized text side by side, and copies sanitized text only after review. The app has no backend, no database, no login, no analytics, no remote resources, and no external AI API. SafePaste remains a review aid rather than a guarantee that all secrets are detected.

## 2. Intended Users

Primary users:

- developers
- IT support engineers
- technical students
- technical users preparing logs for AI tools, support systems, issue trackers, chat, email, or forums

Secondary users:

- people whose data appears in logs
- security and compliance reviewers
- support recipients who need enough context to troubleshoot

## 3. Stakeholder Map

The stakeholder map remains in [docs/STAKEHOLDER_MAP.md](docs/STAKEHOLDER_MAP.md). The final implementation keeps the two key conflicts visible:

- Privacy vs diagnostic usefulness: non-loopback IPv4 addresses are redacted by default, IPv4 loopback addresses in `127.0.0.0/8` are preserved for diagnostic usefulness, and IPv4-shaped values in narrow version-related contexts are preserved as software version context.
- Detection sensitivity vs false positives: high-risk credential contexts and explicit structured username fields are redacted, while ordinary build IDs, UUID-like trace IDs, semantic versions, arbitrary prose names, and `PWD` path values are preserved.

## 4. Functional Requirements

- R1: Application works entirely client-side.
- R2: User can paste arbitrary text.
- R3: Application produces sanitized output.
- R4: Application detects email addresses.
- R5: Application detects common credentials and tokens, including key/value secrets, explicit structured `secret` fields, quoted JSON credential keys, JWTs, Bearer tokens, Basic/Token Authorization headers, AWS-style access keys, and recognizable Slack-style tokens.
- R6: Application detects valid non-loopback IPv4 addresses, does not classify invalid octets as IPv4, does not redact IPv4-like substrings inside larger dotted numeric sequences, and preserves IPv4-shaped values in narrow version-related contexts.
- R7: Application shows detected sensitive-data categories.
- R8: Application shows a redaction count.
- R9: User can copy sanitized output.
- R10: User can choose whether redaction-eligible IPv4 addresses are redacted.
- R11: User can review original and sanitized text before sharing.
- R12: Application preserves non-sensitive context where practical.
- R13: Usernames are redacted only when they appear in common user-directory path forms or explicit structured username fields that are reasonably detectable. Current product output uses `[REDACTED_USERNAME]` for both forms.
- R14: Ordinary short identifiers such as `abc123xyz`, UUID-like trace IDs, semantic versions, arbitrary prose names, and path-like `PWD` values remain unchanged unless there is stronger evidence they are sensitive.
- R15: The app provides a clear/reset action.
- R16: The app may provide a visual preview of redaction locations, but copied output must remain the stable sanitized plain-text representation.
- R17: The UI may group detailed sanitizer categories into broader visual chips, such as credentials, tokens, email, usernames, and IPv4, while preserving detailed categories in eval evidence.
- R18: Local drag-and-drop loading is allowed only through browser `FileReader` for text-like files; it must not upload or persist file contents.
- R19: Keyboard shortcuts may supplement native controls when they do not replace visible buttons or hijack high-conflict browser shortcuts.

## 5. Privacy And Security Requirements

- PS1: Pasted user content must never be sent over the network by the production app.
- PS2: Pasted logs must not be stored in localStorage, sessionStorage, cookies, IndexedDB, backend storage, or other persistence.
- PS3: The app must not include tracking, analytics, telemetry, third-party scripts, remote fonts, or remote CDN libraries.
- PS4: User-controlled content must be handled with safe DOM APIs; use textarea values, `textContent`, and node creation rather than `innerHTML`.
- PS5: Production files must not hardcode API keys, passwords, secrets, or credentials.
- PS6: Failing tests must not be removed or weakened merely because they fail.
- PS7: Expected outputs must not be hardcoded just to satisfy evaluations.
- PS8: Packages must not be installed silently.
- PS9: External services must not be added without explicit human approval.
- PS10: Destructive actions must require confirmation.

## 6. Accessibility Requirements

- A1: The app must be keyboard usable through native controls.
- A2: Textareas and controls must have visible labels or clear accessible names.
- A3: The page must use semantic header, main, section, heading, button, textarea, label, and status patterns.
- A4: Focus indicators must be visible.
- A5: Status updates must be understandable without relying solely on color.
- A6: Buttons must have clear accessible names.
- A7: Output tabs and optional preview controls must use native buttons or equivalent accessible controls.

## 7. AI Development Rules

- AI1: Never add production network calls.
- AI2: Never persist pasted text.
- AI3: Never delete or weaken failing tests to get a pass.
- AI4: Ask before adding dependencies or package installation.
- AI5: Never bypass security hooks.
- AI6: Prefer safe DOM APIs for user-controlled content.
- AI7: Run sanitizer tests after modifying sanitizer logic.
- AI8: Surface ambiguous requirements and document trade-offs.
- AI9: Preserve `SPEC_v1.md` after implementation begins.
- AI10: Record real failures and do not fabricate development history.

## 8. Finalized Borderline Decisions

### Localhost and Private IPs

Public IPv4 addresses and private non-loopback IPv4 ranges are redacted by default because IP information may reveal environment or user details. IPv4 loopback addresses in `127.0.0.0/8` are preserved by default because Manual Test 2 showed that redacting localhost can be unnecessarily destructive for troubleshooting and usually identifies the local machine rather than a remote person or organization.

Session 7 grader finding:
The exact/property grader originally passed `Localhost: 127.0.0.1` because default IPv4 redaction behaved as specified. The human rubric marked the same case as `NEEDS DISCUSSION` because localhost is often valuable debugging context and carries less privacy risk than many external IP addresses. Manual Test 2 resolved this as a specification refinement: preserve IPv4 loopback addresses, continue redacting other valid IPv4 addresses when IPv4 redaction is enabled, and keep the user-controlled IPv4 opt-out for broader network debugging cases.

### IPv4 Token Boundaries

IPv4 redaction only applies when the candidate is a complete IPv4 token. A valid-looking four-octet substring inside a larger dotted numeric sequence, such as `1.2.3.4.5`, must remain unchanged.

### Version-Related IPv4-Shaped Values

IPv4-shaped values are preserved when they are clearly associated with narrow version-related contexts. Supported structured forms include `version=`, `release=`, `app_version=`, `app-version=`, `software_version=`, or `software-version=`, including quoted JSON-style keys where the same immediate field context is present. Supported prose forms are direct `Version 1.2.3.4` and `Release 1.2.3.4` style associations, case-insensitive. This is a contextual exception to IP redaction, not a general opt-out.

Manual Test 3 grader finding:
The automated syntactic IP interpretation could treat `release=1.2.3.4` as successful IPv4 redaction, but the human rubric judged that output as a diagnostic-usefulness failure because release version context was removed. Manual Test 4 extended the same finding to prose: `Release 1.2.3.4 passed QA yesterday.` The final policy preserves narrow version contexts while continuing to redact explicit IP fields and ordinary network prose such as `Server 10.20.30.40 failed`, `Client 8.8.8.8 disconnected`, and `Remote address: 172.20.10.15`.

Manual Test 6 grader finding:
`Firmware 1.2.3.4 installed successfully.` remains redacted under the current deterministic policy even though human review considers it likely firmware-version context. This is a known limitation rather than a trigger for another keyword exception. Contextual disambiguation is best-effort and intentionally not exhaustive.

### `PWD=` Values

`PWD=/some/path` is not treated as a password because `PWD` commonly means present working directory in shell logs. The final sanitizer preserves `PWD` values and handles usernames through the narrower path detector.

### Linux Home Paths

Recognized local home-directory forms include Windows `C:\Users\name\...`, macOS `/Users/name/...`, and Linux `/home/name/...`. SafePaste redacts only the username segment in those forms. It does not redact general system paths such as `/var/log/nginx/error.log` or `/usr/local/bin`.

### Structured Username Fields

Explicit structured username fields are redacted because they strongly indicate account identifiers. Supported key forms include `username=`, `user_name=`, `user-name=`, and `user=`, plus quoted JSON equivalents such as `"username":"..."` or `"user":"..."` when the value is a simple account-like token.

SafePaste does not attempt arbitrary personal-name detection in prose or generic `name=` fields. For example, `name=Muhammad` and `User alice reported that the service failed after deployment.` remain unchanged. This preserves diagnostic usefulness and avoids broad personal-name false positives.

Manual Test 4 consistency review:
Earlier current outputs used `[REDACTED_USER]` for home-path usernames and `[REDACTED_USERNAME]` for structured username fields. These represent the same conceptual category, so current product output standardizes on `[REDACTED_USERNAME]`. Historical evidence files preserve the exact labels observed at the time they were recorded.

### JSON Credential Keys

Quoted JSON keys such as `"password":"..."`, `"apiKey":"..."`, and `"client_secret":"..."` are in scope because JSON logs and config snippets are common.

### Structured Secret Fields

Explicit `secret` fields such as `secret=value`, `secret: value`, and `"secret":"value"` are in scope because the field name provides strong evidence that the value is sensitive. SafePaste redacts these values with `[REDACTED_SECRET]`.

Final regression F8:
`secret=FakeSecretValue987` remained visible during final regression testing. This was treated as a high-severity privacy failure and fixed narrowly for explicit `secret` fields only. The fix does not add arbitrary secret guessing and does not change IPv4, version, username, path, or firmware-limitation behavior.

## 9. Known Limitations

- Detection is deterministic and pattern-based; it cannot prove that every secret is removed.
- The app does not parse all programming languages, structured logs, or custom secret formats.
- Local path detection is intentionally narrow to reduce false positives.
- Structured username detection is intentionally limited to explicit account-like fields and does not attempt general personal-name recognition.
- Natural-language version handling is intentionally limited to direct `Version` and `Release` associations. Other ambiguous IPv4-shaped version strings, such as firmware versions, may be over-redacted because SafePaste avoids broad semantic/NLP classification.
- The app distinguishes loopback from other IPv4 addresses, but it does not separately classify public and private non-loopback ranges.
- Browser-level OS clipboard permission, viewport rendering, tab traversal, and screen-reader announcement quality were not verified because browser automation did not return readable page state in this environment. Local harnesses verified the Clipboard API call, static accessibility structure, and responsive CSS rules.
- A temporary local verification server exists under `evals/` for testing only. The production app remains static and can be opened directly from `index.html`.

## 10. Changes From v1

- Added explicit JSON credential coverage after unit/eval/red-team failures.
- Added Basic and Token Authorization header coverage after security review.
- Removed broad `pwd` password alias after security review found path false positives.
- Expanded static privacy eval scanning to recursively scan production code files.
- Updated the pre-commit hook to avoid `grep` dependency and fixed temp files.
- Added Session 7 grader methodology and documented localhost redaction as a human-in-the-loop judgment call.
- Refined Manual Test 2 policy so `127.0.0.0/8` loopback addresses are preserved by default.
- Added complete-token IPv4 detection to avoid redacting substrings inside larger dotted numeric sequences.
- Fixed Linux `/home/name/...` username redaction while preserving non-home Linux paths.
- Added Manual Test 3 structured username redaction for explicit account fields while preserving arbitrary names.
- Added Manual Test 3 version-field context so IPv4-shaped software versions are preserved while explicit IP fields still redact.
- Added Manual Test 4 prose version context for direct `Version` and `Release` associations.
- Standardized current username replacement markers on `[REDACTED_USERNAME]`.
- Adopted the approved Claude-generated visual concept as the final UI shell while preserving `src/sanitizer.js` as the sole behavioral source of truth.
- Added editor-style panes, line gutters, sanitized/preview output tabs, grouped category chips, visual redaction bars, local FileReader drag-and-drop for text-like files, and non-conflicting keyboard shortcuts.
- Removed all external font/resource references from the UI integration and kept system/local font stacks.
- Added narrow final-regression coverage for explicit structured `secret` fields, using `[REDACTED_SECRET]`.

## 11. Later Extension Addendum (October 2026)

Sections 1–10 describe the academic base version and are kept as written. The later
security/privacy engineering extension (phases 2–12) adds the following; details
and current evidence are in README.md, docs/ENGINE_API.md and docs/EXTENSION_REPORT.md.

- Modules: `src/sanitizer.js` remains the single behavioral source of truth and is
  shared by the browser UI, the local Web Worker `src/worker.js` and the CLI
  `bin/safepaste.js`. The engine adds bounded format parsing (JSON, env, HTTP
  headers, logfmt), a 26-entry detector catalog, profiles (strict, support,
  incident, custom, legacy), review overrides, session-local pseudonyms and a
  metadata-only privacy report.
- Network policy: IPv6 and MAC addresses are network identifiers governed by the
  same network control as IPv4; profiles classify loopback and private ranges.
  This supersedes the "does not separately classify public and private" limitation
  for the extension profiles only; the legacy mode keeps the section 8 behavior.
- Explicit user-driven exports (clarifies PS2 and R18): the user may copy the
  reviewed sanitized text and download `sanitized.log` or the metadata-only
  `privacy-report.json`; the CLI writes only files named with `-o`/`--report` and
  never overwrites. These happen only on an explicit action. The original input is
  never exported, and nothing is persisted automatically (no storage APIs, no
  autosave, text fields use `autocomplete="off"`).
- Zero egress is enforced by a meta CSP with `connect-src 'none'`, a static privacy
  checker and the pre-commit gate (docs/ZERO_EGRESS.md).
- Human review stays required: credentials, tokens and secrets cannot be kept;
  Preview masks every finding, including KEEP decisions.
