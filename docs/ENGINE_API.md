# Shared core engine (later extension)

UMD entry point remains `src/sanitizer.js`: `SafePasteSanitizer` in the browser,
`require('./src/sanitizer')` in Node. No package install or additional browser
scripts are required. Phase 5's browser UI consumes the review/policy API;
see `REVIEW_UI_STAGE_RESULT.md` for that consumer's privacy and state contract.

## Detection/review API

### Phase 6: session-local pseudonymization

`mode: 'redaction'` is the default; `'pseudonymization'` replaces only supported
context identifiers (email, account username, home-path username, network) with
category-specific `[EMAIL_n]`, `[USERNAME_n]`, `[PATH_n]`, `[IP_n]` markers.
Credentials/tokens/secrets always use full redaction markers and still reject KEEP.
`policy.mode` and `report.mode` make the selected mode inspectable. Actions remain
REDACT/KEEP: REDACT uses the selected replacement; KEEP explicitly returns originals.

`createSession()` exposes `createReview(input, options)`, `clear()` and the
resolved `limits`. `createSession({ limits: "large" })` (phase 9, used by the local
worker and CLI) raises input to 16,777,216 code units and fields to 1,048,576; any
other session option fails with `INVALID_SESSION_OPTIONS`. See docs/PERFORMANCE.md. Its maps
survive review edits/individual review.clear() until session.clear(), which resets
numbering and clears all active reviews. The browser owns one such session per tab;
Clear and page exit reset it. Reload constructs a fresh session. Standalone
`createReview`, `analyze`, and `sanitize` use isolated per-call maps.

Raw mapping keys remain private closure memory, never findings/report or storage.
JSON-decoded values share mappings with literal equivalents; Unicode usernames in
parsed fields use bounded letters/numbers/marks/dot/underscore/hyphen syntax.
Comparisons are exact decoded strings, not case folding or Unicode normalization.
Home-path and account categories deliberately have separate namespaces. Existing
well-shaped redaction/pseudonym markers are opaque and idempotent. Markers already
present when allocated (including decoded JSON) reserve their numbers. Arbitrary
future input can contain an earlier marker: markers are not authenticated and
cannot prove provenance. Pseudonyms reveal relationships, not anonymization.
Session reserved markers/allocated values are bounded at 100,000, then
`SESSION_LIMIT` returns no output; Clear releases references, not secure JS erasure.

- `inspectDetectors()` returns an immutable catalog with IDs, category/control,
  severity, description, reason, replacement, context requirements and KEEP
  eligibility. `certainty` means deterministic rule match, not ML probability.
- `getCapabilities()` returns immutable hard bounds: 2,097,152 UTF-16 code units,
  100,000 candidate findings, 64 JSON container levels, 50,000 parsed fields.
  These are guardrails, not performance/support claims for multi-megabyte files.
- `analyze(input, options)` returns `{findings, report}` without original values.
- `createReview(input, options)` retains input only in a closure and exposes
  immutable `{findings, report, policy, apply(overrides), clear()}`. `apply()` returns
  `{sanitized, findings, report}`. It never scans generated replacements.
  `clear()` releases the retained source reference and disables apply. This is
  not a guarantee of secure memory erasure by the JavaScript runtime.
- `sanitize(input, {redactIpAddresses})` remains the compatibility adapter with
  `{original, sanitized, matches, categories, redactionCount}`. **Do not export
  this result as a privacy report**: `original` and `matches[].text` contain raw
  input. New reports/findings do not. Match offsets now refer to original input;
  matches describe replacement spans, not whole headers/home paths. With an
  explicit profile, legacy counts/categories/matches include only REDACT actions.

Findings have deterministic positional IDs (`finding-1`, etc.), rule IDs,
category/control/severity/reason/description, marker replacement, action, KEEP
eligibility and an exclusive `[start,end)` source span. Offsets and 1-based
line/column positions count UTF-16 code units (not graphemes); LF, CRLF and CR
are line breaks. IDs are local to one review, not global identifiers.

All detections operate on the original source. Connected overlapping intervals
are coalesced, using the strongest explicit credential rule (then deterministic
source order for ties), so partial overlaps cannot reveal a candidate suffix.
Replacement is a single forward pass. Home-path spans cover only the username.
The free-text version lookbehind is bounded to 160 code units; unusually distant
prose context may be redacted conservatively. Email components are bounded to
avoid unbounded repeated scans of hostile dotted input.

## Phase 7 high-confidence detectors

Added 14 catalog entries (catalog is now 26; the original 12 keep their order and
markers). All use bounded scanners/validators, never entropy guessing. Overlaps are
merged by priority: `PRIVATE_KEY` (120) outranks everything, so secrets inside a
key block produce one finding/replacement. Credentials/tokens/secrets stay locked
(REDACT only, never pseudonymized); IPv6/MAC are `network` review identifiers.
Report `engineVersion` was 7 for phase 7; it is 8 since the phase 11 fixes below.

| Category | Exact rule | Marker |
|---|---|---|
| GITHUB_TOKEN | `gh[pousr]_` + exactly 36 alphanumerics, or `github_pat_` + 22 + `_` + 59, word-bounded | `[REDACTED_GITHUB_TOKEN]` |
| GOOGLE_API_KEY | `AIza` + exactly 35 of `[0-9A-Za-z_-]`, bounded | `[REDACTED_GOOGLE_API_KEY]` |
| CLOUD_CREDENTIAL | AccountKey / SharedAccessKey / SharedAccessSignature in a `;`-chain (value >= 8), or explicit aws_secret_access_key / secret_access_key / aws_session_token field (16-4096 base64 chars) | `[REDACTED_CLOUD_CREDENTIAL]` |
| URL_CREDENTIALS | `scheme://user:password@` userinfo (non-empty password; empty user allowed); host/port/path kept | `[REDACTED_URL_CREDENTIALS]` |
| CONNECTION_STRING_PASSWORD | Password / Pwd / Passwd only inside a `;`-chain of >= 2 pairs that contains Driver, DSN, Server, Data Source, Provider, Database, Initial Catalog, Host, Hostname, Address/Addr or Network Address; `{...}` and quoted values; JDBC `;` `?` `&` params; Oracle `jdbc:oracle:thin:user/pass@`. Uid / User Id / User / Username there become USERNAME | `[REDACTED_PASSWORD]` |
| PRIVATE_KEY | `-----BEGIN [RSA, DSA, EC, OPENSSH, ENCRYPTED, PGP ]PRIVATE KEY[ BLOCK]-----` through the matching END line; no END redacts conservatively to end of input, except inside a JSON string where it stops at the end of that value | `[REDACTED_PRIVATE_KEY]` |
| SESSION_TOKEN | explicit session, session_id/token/key, sessionid, jsessionid, phpsessid, asp.net_sessionid, csrf_token, xsrf_token field with token-like value (8+ chars with letter and digit, or 24+ chars) | `[REDACTED_SESSION_TOKEN]` |
| COOKIE_VALUE | each value in a `Cookie:` header; only the first pair of `Set-Cookie:` (attributes kept); structured Cookie fields | `[REDACTED_COOKIE]` |
| HEADER_CREDENTIAL | x-auth-token, auth-token, x-access-token, x-session-token, x-csrf-token, x-xsrf-token, x-amz-security-token, x-goog-api-key (x-api-key keeps legacy `[REDACTED_API_KEY]`) | `[REDACTED_HEADER_CREDENTIAL]` |
| BASIC_CREDENTIALS | `Basic <base64>` anywhere that a bounded decoder turns into printable ASCII `user:password`, both sides non-empty. Authorization / Proxy-Authorization headers keep the legacy whole-header marker | `[REDACTED_BASIC_CREDENTIALS]` |
| WEBHOOK_SECRET | path after hooks.slack.com/services, /workflows or /triggers; discord(app).com/api/[vN/]webhooks; *.webhook.office.com/webhookb2; outlook.office(365).com/webhook (>= 8 chars) | `[REDACTED_WEBHOOK_SECRET]` |
| URL_QUERY_SECRET | value of exact query keys token, access_token, refresh_token, id_token, auth_token, api_key, apikey, client_secret, secret, password, passwd, sig, signature, x-amz-signature, x-amz-security-token, x-goog-signature, session, sessionid, session_id, jsessionid (>= 4 chars) | `[REDACTED_URL_SECRET]` |
| IPV6_ADDRESS | RFC 4291 text parsed into 8 hextets (one `::`, optional dotted IPv4 tail, 2-45 chars, contains a decimal digit, not all-zero); bracketed URL hosts; link-local `%zone` included | `[REDACTED_IPV6_ADDRESS]` / `[IPV6_n]` |
| MAC_ADDRESS | six hex octets, one consistent `:` or `-` separator, at least one A-F letter | `[REDACTED_MAC_ADDRESS]` / `[MAC_n]` |

.env-style secret-suffix keys map to existing categories: `*_PASSWORD`/`*_PASSWD` ->
PASSWORD; `*_API_KEY`, `*_SECRET_KEY`, `*_ACCESS_TOKEN`, `*_CLIENT_SECRET` -> API_KEY;
`*_SECRET`, `*_AUTH_TOKEN`, `*_REFRESH_TOKEN`, `*_PRIVATE_KEY` -> SECRET. Bare `PWD` is
never classified as a password: `PWD=/home/<user>/...` keeps the legacy path rule.

IPv6 `networkKind`: loopback (::1), unique-local (fc00::/7), link-local (fe80::/10);
IPv4-mapped (::ffff:a.b.c.d) uses the IPv4 class; otherwise other. MAC is hardware.
Omitted profile (legacy) preserves ::1 like 127/8; support preserves loopback, private
and unique-local; incident preserves network evidence; strict redacts all.
`redactIpAddresses:false` also disables IPv6/MAC. Pseudonyms normalize IPv6 (case, zero
compression) and MAC (case, separator), so equivalent forms share a number. Explicit
version/release and request/trace/build ID fields exempt network identifiers.

Limitations: unknown token formats, other webhook providers, connection strings
without a recognised marker key or not `;`-delimited, and other header/cookie key names
are not detected. Unbracketed `addr:port` after IPv6 (`2001:db8::1:8080`) is read as one
address. All-decimal MACs (`10:20:30:40:50:60`), dot-separated Cisco MACs and hex-word
IPv6 without digits (`dead::beef`) are deliberately not flagged. A URL whose password
is already a marker is left unchanged (idempotence), so its username stays visible.
A detected user:password URL drops weaker matches starting inside the userinfo so the
host stays readable. Prefixed tokens are length-checked only; no checksum validation.

## Structured parsing (phase 3)

`options.format` is `auto` (default), `text`, `json`, `env`, `headers`, or
`logfmt`. Auto recognizes JSON containers/quoted scalars, complete assignment
lines, header lines, then mixed key=value logs. Explicit `env` handles unquoted
values with spaces. Ambiguous mixed prose defaults to narrow token scanning,
not semantic inference. Explicit `text` uses only the original text detectors.
YAML and general embedded JSON *structure* parsing are not implemented. Since
phase 11 (engineVersion 8), every non-`text` format, including the
malformed-JSON fallback, also lexes JSON-style `"key":"value"` pairs embedded in
log lines, NDJSON or truncated JSON. Their values are decoded with JSON escapes
so that spaces and escaped quotes cannot split a credential. Pair units feed the
same `explicitCategory` and detector scan as other fields and count toward
`maxFields`. Under an explicit credential/identity key, an unterminated quoted
value (`password="...`, a truncated line) or an invalid JSON string
conservatively covers the rest of its line. Under other keys it is skipped and
later fields still parse. The text rules for password/passwd/secret/API keys also
accept an end-of-line close for an opened quote and treat backslash escapes as part
of the value. Both are needed so explicit `text` cannot leave the tail of
`"Fake\"Tail"` visible. A one-letter key followed by `:\` or `:/` is a
Windows drive path, not an HTTP header. Explicit `text` still does not lex
pairs, so a quoted value containing spaces is a known text-mode miss.

JSON parsing validates grammar and bounds nesting before detection. Escaped
keys are recognized; decoded value characters map to original source spans
(including Unicode escapes, escaped quotes, backslashes and surrogate units).
All string keys/values and scalar values are scanned, without reserialization.
Duplicate keys and original spacing/order remain. Numeric/boolean credential
replacements are quoted so valid JSON stays valid; consumers must tolerate
that type change. Null/empty values are not treated as credentials. Redacting
object keys can collapse distinct keys; this is best-effort sharing output,
not an unchanged application data structure.

Supported field aliases remain narrow: password/passwd; api_key/access_token/
secret_key/client_secret (optional underscores/hyphens); secret; username/
user_name/user; authorization. Explicit credentials consume the full parsed
scalar, including spaces/escaping, rather than leaking a partial value.
Username syntax remains the existing 3–64-character account-identifier syntax;
emails in user fields remain email findings. Arrays/objects directly under a
secret-named key are not wholly redacted as a unit. Unknown names/secret formats
and general natural-language identities remain limitations.

Version/release/app_version/software_version and request_id/trace_id/build_id
fields preserve only IPv4-shaped diagnostic values; they do not exempt emails
or tokens. Arbitrary free-text IDs receive no blanket exemption. `PWD` remains
a path context, not a password alias. HTTP headers and quoted logfmt/env values
are scanned as scalar units; comments/layout/line separators remain intact.
Single-quoted env values are literal; common double-quoted/logfmt escapes are
decoded, with unknown escapes retained literally for Windows paths. This is a
bounded lexical parser, not a shell evaluator (no expansion or multiline env).

`report.format` and `report.parseStatus` show parser selection. Malformed JSON
falls back to text/assignment detection with `malformed-json-fallback`; escaped
bypasses in malformed JSON may be missed. Unterminated quoted fields fall back
to raw text rules. Limits count parsed scalar units, including JSON keys.

Errors have stable `code` values and no input excerpts: `INPUT_LIMIT`,
`FINDING_LIMIT`, `FIELD_LIMIT`, `DEPTH_LIMIT`, `UNKNOWN_FORMAT`,
`REVIEW_CLEARED`. No partial output is returned on a limit/option error.
Inspect metadata before a human explicitly chooses to share output; deterministic
rules do not guarantee detection of unknown secrets.

## Inspectable policy and override API (phase 4)

No profile is silently activated: omitting `profile` retains `legacy`, including
loopback preservation and `{redactIpAddresses:false}`. Explicit profiles detect
all supported IPv4, even values kept by policy, so reviewers can override them.
Legacy excludes loopback/disabled IP findings to preserve historical behavior.
Version/diagnostic field exceptions exclude those IPv4-shaped candidates in all
profiles; they cannot be overridden without changing context/review input.

| Explicit `profile` | Credentials/tokens/secrets | Email/username/home identity | IPv4 |
| --- | --- | --- | --- |
| `strict` | REDACT (locked) | REDACT | REDACT, including loopback |
| `support` | REDACT (locked) | REDACT | KEEP RFC1918 private and 127/8 loopback; REDACT other |
| `incident` | REDACT (locked) | REDACT | KEEP network evidence; **not for public sharing by default** |
| `custom` | REDACT (locked) | REDACT unless explicitly configured | REDACT unless explicitly configured |

`inspectPolicies()` returns deeply immutable default configurations for these
four profiles. `inspectPolicy(options)` resolves/validates the exact options
used by review, including legacy. Reports include this complete resolved policy.
`getCapabilities()` also exposes formats, profiles, controls, actions,
`lockedCategories`, and `maxOverrides` (100,000).

Custom options use control names, not individual detector names:

```js
const engine = require('../src/sanitizer');
const options = {
  profile: 'custom',
  format: 'auto',
  categories: { email: 'REDACT', usernames: 'REDACT', paths: 'REDACT', network: 'REDACT' },
  network: { preserveLoopback: true, preservePrivate: false }
};
const session = engine.createReview('client_ip=127.0.0.1 user=alice', options);
// These contain no original values:
console.log(session.policy, session.findings);
const ip = session.findings.find(finding => finding.control === 'network');
// Only explicitly requested apply produces output. Consumers own copying/export.
const result = session.apply({ [ip.id]: 'REDACT' });
// Export result.report only, not the session or the legacy sanitize result.
session.clear();
```

Controls are `credentials`, `tokens`, `secrets`, `email`, `usernames`, `paths`,
`network`. AWS keys belong to locked credentials; no general cloud-identifier
detector/control has been added. Locked controls may be explicitly REDACT but
never KEEP. Unknown option/control/profile names fail closed; combining explicit
profiles with the legacy IPv4 flag fails as ambiguous, rather than ignoring it.
Category/network settings are custom-only. No arbitrary replacement strings,
pseudonyms or unbounded user rules are accepted.

`session.apply({[findingId]:'KEEP'|'REDACT'})` applies a complete *per-call*
override map. Omitted IDs take the initial policy action; calls do not accumulate
state. Applying identical overrides is deterministic. A rejected override returns
no output and does not mutate the review. Unknown IDs/actions, non-plain-object
maps and KEEP on a high-risk/overlapping credential finding are rejected. IDs
belong to that review's original source; never reuse them after editing input.
KEEP may reveal original text in the **explicitly returned output**, not in
findings/report metadata. The phase 5 UI makes that choice explicit, masks all
detected values in Preview, and uses the reviewed result for Copy/downloads.

Final findings include `action`, `policyReason` (category/network/human decision),
`allowKeep`, and IPv4 `networkKind`: `loopback`, `private` (RFC1918), `other`.
Other does not claim an address is publicly routable; link-local, multicast,
documentation and special-use ranges remain other. No IPv6 was added here.
Reports include input code-unit length/physical line count, detected/redacted/
kept totals, immutable per-control counts, final findings, active policy and
engine-local `networkEgress:'none'`, `persistentStorage:'none'`. These are not a
guarantee about browser extensions, recipient behavior or unknown leaked secrets.

Additional option/override errors: `INVALID_OPTIONS`, `UNKNOWN_OPTION`,
`UNKNOWN_PROFILE`, `AMBIGUOUS_POLICY`, `CUSTOM_ONLY`, `INVALID_CATEGORIES`,
`UNKNOWN_CATEGORY`, `INVALID_ACTION`, `INVALID_NETWORK_POLICY`, `KEEP_FORBIDDEN`,
`INVALID_OVERRIDES`, `OVERRIDE_LIMIT`, `UNKNOWN_FINDING`.

## Bounded scanning and stage evidence

The inherited JWT regex exhibited quadratic failure on hyphen-separated repeated
`eyJ` prefixes. Detection now lexes maximal token runs and walks dot-component
windows in linear scanning work before resolving overlaps. Existing JWT syntax
and marker behavior are retained; the regression suite includes a 440,000-code-
unit malformed prefix run. Parser/string walks are bounded and linear; candidate
sorting and interval lookup are O(n log n), not repeated replacement/rescanning.
This is not the later large-file worker/performance feature, nor a comprehensive
ReDoS audit. Multi-megabyte browser responsiveness remains unmeasured.
