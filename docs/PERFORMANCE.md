# Performance and resource limits (phase 9)

All numbers below were produced by `node evals/run-benchmarks.js --full` on the
development VM, engine-only (no DOM, no browser), one run per case, with
synthetic generated input. They are not browser measurements; real-browser
timing, memory and UI responsiveness are validated by the parent browser stage.
Re-run the command to regenerate them; `--write <file>` refuses to overwrite.

## Limits

| Tier | Used by | maxInputLength (UTF-16 units) | maxFields | maxCandidates (findings) |
| --- | --- | --- | --- | --- |
| standard | synchronous fallback, standalone `createReview`, default `createSession()` | 2,097,152 (2 MiB) | 50,000 | 100,000 |
| large | local worker (`createSession({ limits: "large" })`), CLI | 16,777,216 (16 MiB) | 1,048,576 | 100,000 |

Every limit fails closed with a coded error (`INPUT_LIMIT`, `FIELD_LIMIT`,
`FINDING_LIMIT`, `SESSION_LIMIT`); there is no truncated or partially
sanitized output. The browser checks `file.size` (bytes, which is never less
than the UTF-16 length) before reading, and pasted/typed text length before
analysis. Above 16 MiB nothing is supported: 25 MiB and 50 MiB inputs are
measured only to confirm they are refused immediately.

Browser DOM bounds (exports are never cut): the visual preview renders at most
1,048,576 characters or 5,000 masked markers and then shows an explicit
"Preview display limit reached" notice; the line gutter numbers at most 10,000
lines followed by an ellipsis while the pane meta keeps the real line count;
findings render 50 per page.

## Measured results

"sparse" = realistic logfmt lines with one email per 200 lines; "dense" = an
email, username and private IPv4 on every line. "text" forces plain-text
detection; "auto" adds structured logfmt field parsing (slower, more context).

Node v22.20.0, linux/x64, 8 CPU, engine-only (no DOM), single run per case, full mode.

| Kind | Input | Format | Limits | MiB | Outcome | ms |
| --- | --- | --- | --- | --- | --- | --- |
| pathological | repeated a | text | standard | 1.81 | ok, 0 findings | 342 |
| pathological | repeated a | auto | standard | 1.81 | ok, 0 findings | 333 |
| pathological | repeated colons | text | standard | 1.81 | ok, 0 findings | 53 |
| pathological | repeated colons | auto | standard | 1.81 | ok, 0 findings | 44 |
| pathological | hex-colon runs | text | standard | 1.81 | ok, 0 findings | 98 |
| pathological | hex-colon runs | auto | standard | 1.81 | ok, 0 findings | 204 |
| pathological | dotted numerics | text | standard | 1.81 | ok, 0 findings | 663 |
| pathological | dotted numerics | auto | standard | 1.81 | ok, 0 findings | 628 |
| pathological | malformed bearer | text | standard | 1.81 | fail-closed FINDING_LIMIT | 132 |
| pathological | malformed bearer | auto | standard | 1.81 | fail-closed FINDING_LIMIT | 174 |
| pathological | unterminated quotes | text | standard | 1.81 | ok, 95000 findings | 232 |
| pathological | unterminated quotes | auto | standard | 1.81 | ok, 95000 findings | 231 |
| pathological | deep JSON strings | text | standard | 1.81 | ok, 0 findings | 79 |
| pathological | deep JSON strings | auto | standard | 1.81 | ok, 0 findings | 68 |
| pathological | one long line | text | standard | 1.81 | ok, 0 findings | 225 |
| pathological | one long line | auto | standard | 1.81 | ok, 0 findings | 461 |
| pathological | unicode separators | text | standard | 1.81 | ok, 0 findings | 108 |
| pathological | unicode separators | auto | standard | 1.81 | ok, 0 findings | 130 |
| pathological | PEM-like block | text | standard | 1.81 | ok, 1 findings | 155 |
| pathological | PEM-like block | auto | standard | 1.81 | ok, 1 findings | 199 |
| pathological | credential URLs | text | standard | 1.81 | fail-closed FINDING_LIMIT | 134 |
| pathological | credential URLs | auto | standard | 1.81 | fail-closed FINDING_LIMIT | 157 |
| pathological | email-like runs | text | standard | 1.81 | ok, 0 findings | 131 |
| pathological | email-like runs | auto | standard | 1.81 | ok, 0 findings | 135 |
| sparse | synthetic logfmt | text | standard | 1 | ok, 56 findings | 73 |
| sparse | synthetic logfmt | text | large | 1 | ok, 56 findings | 79 |
| sparse | synthetic logfmt | auto | standard | 1 | fail-closed FIELD_LIMIT | 51 |
| sparse | synthetic logfmt | auto | large | 1 | ok, 56 findings | 281 |
| dense | synthetic logfmt | text | standard | 1 | ok, 41717 findings | 170 |
| dense | synthetic logfmt | text | large | 1 | ok, 41717 findings | 152 |
| dense | synthetic logfmt | auto | standard | 1 | fail-closed FIELD_LIMIT | 36 |
| dense | synthetic logfmt | auto | large | 1 | ok, 41717 findings | 447 |
| sparse | synthetic logfmt | text | standard | 10 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | text | large | 10 | ok, 553 findings | 696 |
| sparse | synthetic logfmt | auto | standard | 10 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | large | 10 | ok, 553 findings | 2808 |
| dense | synthetic logfmt | text | standard | 10 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | large | 10 | fail-closed FINDING_LIMIT | 788 |
| dense | synthetic logfmt | auto | standard | 10 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | large | 10 | fail-closed FINDING_LIMIT | 1364 |
| sparse | synthetic logfmt | text | standard | 16 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | text | large | 16 | ok, 881 findings | 1104 |
| sparse | synthetic logfmt | auto | standard | 16 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | large | 16 | ok, 881 findings | 4496 |
| dense | synthetic logfmt | text | standard | 16 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | large | 16 | fail-closed FINDING_LIMIT | 1212 |
| dense | synthetic logfmt | auto | standard | 16 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | large | 16 | fail-closed FIELD_LIMIT | 724 |
| sparse | synthetic logfmt | text | standard | 25 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | text | large | 25 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | standard | 25 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | large | 25 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | standard | 25 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | large | 25 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | standard | 25 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | large | 25 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | text | standard | 50 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | text | large | 50 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | standard | 50 | fail-closed INPUT_LIMIT | 0 |
| sparse | synthetic logfmt | auto | large | 50 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | standard | 50 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | text | large | 50 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | standard | 50 | fail-closed INPUT_LIMIT | 0 |
| dense | synthetic logfmt | auto | large | 50 | fail-closed INPUT_LIMIT | 0 |


## Phase 11 re-run (engineVersion 8, 2026-10-07)

The table above was measured at engineVersion 7 (phase 9) and is kept as it was
recorded. After the phase 11 detection fixes, `/usr/bin/time -v node
evals/run-benchmarks.js --full` was re-run on the same kind of VM (Node v22.20.0,
linux/x64, Intel Xeon Platinum 8375C, 8 vCPU, 31 GiB; single run): **PASS, 64 cases
within bounds**, wall clock 24.5 s, peak RSS 766,628 KB. Selected rows (ms):

| Case | Phase 9 (v7) | Phase 11 (v8) |
| --- | --- | --- |
| sparse 1 MiB, auto, large | 281 | 335 |
| dense 1 MiB, text, large (41,717 findings) | 152 | 167 |
| dense 1 MiB, auto, large (41,717 findings) | 447 | 466 |
| sparse 10 MiB, text, large | 696 | 990 |
| sparse 10 MiB, auto, large | 2808 | 3256 |
| sparse 16 MiB, text, large | 1104 | 1388 |
| sparse 16 MiB, auto, large | 4496 | 5093 |

Fail-closed results did not change (dense 10/16 MiB: `FINDING_LIMIT`/`FIELD_LIMIT`;
25/50 MiB: `INPUT_LIMIT`; standard-tier 1 MiB auto: `FIELD_LIMIT`). Sparse large
inputs are roughly 10-40% slower; the likely cause is the extra embedded JSON-pair
lexing and suffix-key rules, but run-to-run noise was not controlled, so this is
not a precise attribution. Phase 11 ReDoS fixture timings are in
[TESTING.md](TESTING.md).

## What is claimed (phase 9 wording; still holds at engineVersion 8)

- Pathological inputs (~1.8 MiB each: repeated characters, colon and hex-colon
  runs, dotted numerics, malformed bearer headers, unterminated quotes, escaped
  JSON strings, one long line, Unicode separators, a large PEM-like block,
  credential URLs, email-like runs) complete in well under the 5 s regression
  bound used by the quick benchmark; no super-linear regex backtracking was
  observed. Dense pathological cases above 100,000 findings fail closed with
  `FINDING_LIMIT`.
- Sparse logs up to 16 MiB complete in the worker tier (auto-format 16 MiB is
  the slowest measured case; see the table). Dense logs fail closed with
  `FINDING_LIMIT`/`FIELD_LIMIT` before 10 MiB.
- Peak resident memory for the whole `--full` run was about 820 MB in Node
  (measured once with `/usr/bin/time -v`); browser memory is not measured here.
- Nothing above 16 MiB is supported.
