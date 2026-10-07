# SafePaste CLI (phase 10)

`bin/safepaste.js` is a dependency-free Node.js (>= 18) command that calls the
same `src/sanitizer.js` engine as the browser, using the large limit tier
(`createSession({ limits: "large" })`). It requires only `fs`, `path`, the
engine. It has no network modules and stores nothing; the
static privacy gate (`evals/run-static-privacy-checks.js`) enforces this for
`bin/` and `cli/`.

```text
node bin/safepaste.js server.log                      # sanitized text to stdout
node bin/safepaste.js server.log --profile support
cat server.log | node bin/safepaste.js --mode pseudonymization
node bin/safepaste.js --check server.log              # automation gate
node bin/safepaste.js server.log -o server.sanitized.log --report privacy-report.json
node bin/safepaste.js --profile custom --category email=KEEP --preserve-private app.log
```

Nothing has to be installed. There is deliberately no `package.json` (and so no
`npm` `bin` entry): eval EV-034 requires that the repository contain no dependency
manifest. To get a `safepaste` command, add a shell alias or symlink to
`bin/safepaste.js`, which is executable and has a `node` shebang.

## Behavior

- Input: one file argument, `-`, or piped stdin. A terminal stdin without a file
  is a usage error rather than a hang. Input must be valid UTF-8 (a BOM is kept);
  invalid bytes fail with `INVALID_ENCODING` instead of being replaced.
- Default policy: `--profile strict --mode redaction --format auto`. The CLI
  does not expose the legacy browser compatibility profile.
- Output: sanitized text goes to stdout unless `--output` is given. `--check`
  never prints sanitized text. A metadata summary (counts per category, no
  values) goes to stderr unless `-q`.
- `--report` writes `result.report`: the same metadata-only privacy report the
  browser exports (policy, counts, finding metadata, `networkEgress: "none"`,
  `persistentStorage: "none"`); no original values.
- Files are created with `open(..., "wx", 0o600)`: an existing path, including
  the input file or a symlink, is never overwritten. `--output` and `--report`
  must differ from each other and from the input. Both are written only after
  analysis succeeds; if either write fails, every file created by this run is
  removed.
- Limits: 16,777,216 bytes (checked with `fstat` before reading a file and while
  streaming stdin), then the engine's 16 MiB / 1,048,576 field / 100,000
  finding limits. Every limit fails closed with no output.
- Errors print `safepaste: error <CODE> (<detail>)`. The detail is limited to
  option names, caller-supplied output paths or fixed text; input text, raw
  exception messages and stacks are never printed.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. With `--check`: no finding is redacted under the active policy. |
| 1 | `--check` only: at least one finding has effective action REDACT (redaction or pseudonym replacement). |
| 2 | Usage error, unreadable/oversized/invalid input, existing output path, write failure, or engine error (e.g. `UNKNOWN_PROFILE`, `KEEP_FORBIDDEN`, `FINDING_LIMIT`). |

`--check` counts effective policy findings (`report.redacted`), not
detections kept by policy. For example, `client_ip=192.168.10.20` exits 1
under `strict` and 0 under `support`, which keeps RFC1918 addresses.

## CI use (example only)

```text
BUILD LOG -> safepaste --check -> redactable findings? yes: block publication (exit 1)
                                                      no:  continue (exit 0)
                                  error/limit (exit 2): block, treat as unknown
```

Run it only on logs produced inside the same runner, never upload private
logs elsewhere, and treat exit 2 as a failure. A clean `--check` means no
*supported* pattern matched; it does not prove a log is free of secrets.

## Tests

`node tests/test-cli.js` runs the real executable as a child process with
synthetic input: stdin/file parity with the engine API across all profiles and
modes, `--check` exit codes including KEEP-by-policy, custom categories,
exclusive output/report creation and rollback, symlink refusal, usage errors,
I/O/encoding/size/finding limits, a 3 MiB input above the browser fallback
limit, and dependency/local-only source checks.
