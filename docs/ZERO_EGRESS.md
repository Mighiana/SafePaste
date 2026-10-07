# Zero-egress and no-persistence controls (phase 8)

Later privacy-engineering extension, October 2026. Not part of the academic base.

SafePaste claims **no network egress** and **no persistent log storage** as
architecture properties. They are enforced by three layers. None of them is a
proof against a modified browser, malicious extensions, or OS-level capture.

## 1. Content Security Policy (`index.html` meta)

```text
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';
font-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none';
frame-src 'none'; child-src 'none'; worker-src 'self'; manifest-src 'none';
base-uri 'none'; form-action 'none'
```

- No `'unsafe-inline'`, `'unsafe-eval'`, hashes, nonces, wildcards, `data:`,
  `blob:` or remote hosts. The page has no inline scripts, styles, `style=`
  attributes or event-handler attributes; the static checker enforces that.
- `connect-src 'none'` blocks `fetch`, XHR, WebSocket, EventSource and
  `sendBeacon` from the page **and from the local worker** (dedicated workers
  inherit the document policy). `worker-src 'self'` allows only the local
  `src/worker.js`.
- `form-action 'none'` and `base-uri 'none'` block form submission and base
  URL rewriting. There are no forms.
- Explicit downloads use `<a download>` with a `blob:` URL. That is a
  user-initiated download, not a fetch; CSP does not govern it.

### What a meta CSP cannot do (header-only limits)

Browsers ignore these directives in `<meta>`, so they are deliberately **not**
in the meta tag (the checker rejects them there):

| Directive / header | Effect | Where it applies |
| --- | --- | --- |
| `frame-ancestors 'none'` | Anti-framing / clickjacking | `evals/static-server.js` header only |
| `sandbox` | Origin sandboxing | Not used |
| `report-uri` / `report-to` | Violation reports (would be egress) | Never used |
| `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP | Hardening | `evals/static-server.js` header only |

A meta CSP only applies from the point it is parsed, so it is the first
element after `<meta charset>`, before any stylesheet or script. Opening the
file directly therefore gives **no anti-framing protection**.

### Direct `file://` usage

Opening `index.html` from disk remains supported. Browsers treat `file:`
origins inconsistently: some match `'self'` against local files, some treat
each file as an opaque origin, and Chromium-based browsers refuse to start
`new Worker()` from `file:`. SafePaste never depends on the worker: when
construction or startup fails (CSP, `file:` restrictions, no Worker support) it
uses an honest **synchronous fallback** on the main thread with a smaller input
limit and says so in the status line (see phase 9). Real-browser `file://` and
served behavior is validated by the parent browser test stage, not here.

## 2. Static checks (`node evals/run-static-privacy-checks.js`)

Recursively scans production assets (everything outside `tests/`, `evals/`,
`docs/`, `history/`, `.git`, `.github`, `.claude`, `node_modules`) with
extensions `.html .js .mjs .cjs .css .json`. Comments are blanked before
matching; string literals are kept so remote URLs remain visible. Output is
rule id plus `file:line` only, never matched text.

| Group | Rules |
| --- | --- |
| Network | `fetch(`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`, WebRTC, WebTransport, `serviceWorker`, dynamic `import(`, `.src/.srcset/.action/.ping =`, `location.assign/replace/href`, `window.open`, cross-window `postMessage`, form submit |
| Storage | `localStorage`, `sessionStorage`, `indexedDB`/`IDB*`, `document.cookie`/`cookieStore`, `caches.`/`CacheStorage`, `navigator.storage`, file-system/WebSQL APIs |
| Unsafe DOM | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, HTML parsers/`srcdoc`, `eval`/`new Function`/string timers, `setAttribute('style'/'on*')`, `console.*` (prevents logging input) |
| Script loaders | `new Worker`/`importScripts` only with literal local relative paths; no `type: 'module'`; no remote URL strings |
| HTML | exactly one early CSP meta with the exact directive set above, no unsafe sources, no header-only directives, no inline script/style/handlers, no `javascript:`, iframes/objects/forms/`<base>`, prefetch/preconnect/icon/manifest links, `ping`; every `src`/`href` is local and exists; every `<textarea>` and text/search `<input>` has `autocomplete="off"` (phase 12) so browsers do not restore or autofill log text |
| CSS | no `@import`, `@font-face`, `url(` or `image-set(` |
| CLI (`cli/`, `bin/`) | no network/child-process Node modules, `fetch`, `eval`/`vm`; no `writeFile*`, `appendFile*`, `createWriteStream`, `rename`, `copyFile`, `symlink`; `openSync` only with `'r'` or exclusive `'wx'` |
| Package | `package.json` has no dependency maps, no install/prepare scripts, no `npx`/`npm install`/`curl` scripts |
| Files | symlinked production assets and missing required assets fail closed |

Regex scanning can be evaded by obfuscated code (`window["fe"+"tch"]`). It is
a regression gate for this small hand-written codebase, not a sandbox.
`tests/test-static-privacy.js` proves each rule fires on a mutated copy.

## 3. Pre-commit gate (`sh .claude/hooks/pre-commit.sh`)

Runs on the **staged snapshot** (not the working tree) and never prints matched
values. Works for this standalone repository and for a nested `SafePaste/`
layout (the earlier path rewrite only targeted the nested layout).

1. Production files: credential patterns (AWS, Slack, `sk-`, GitHub, Google,
   PEM private-key headers, `password=`/`api_key=` assignments) block.
2. Fixtures (`tests/`, `evals/`, `docs/`, `history/`, `*.md`) are scanned
   separately instead of skipped: high-confidence token formats and private-key
   bodies must carry an explicit synthetic marker (`FAKE`, `SYNTHETIC`,
   `EXAMPLE`, `TEST`, `DUMMY`, `SAMPLE`, `DEMO`, `PLACEHOLDER`, `NOT_A_REAL`,
   or eight zeros). Fixtures still never influence production detection.
3. Staged changes or deletions under `history/` or to `SPEC_v1.md` block.
4. The staged `evals/run-static-privacy-checks.js` runs against a temporary
   checkout of the index; a missing checker in an app snapshot blocks.

Binary blobs and submodules are skipped. The hook cannot inspect commits made
with `--no-verify`; CI reruns the static checks.
