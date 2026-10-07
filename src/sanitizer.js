(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.SafePasteSanitizer = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  const REDACTION_LABELS = {
    AUTHORIZATION_HEADER: "[REDACTED_AUTHORIZATION_HEADER]",
    BEARER_TOKEN: "[REDACTED_BEARER_TOKEN]",
    JWT: "[REDACTED_JWT]",
    AWS_ACCESS_KEY: "[REDACTED_AWS_ACCESS_KEY]",
    SLACK_TOKEN: "[REDACTED_SLACK_TOKEN]",
    API_KEY: "[REDACTED_API_KEY]",
    SECRET: "[REDACTED_SECRET]",
    PASSWORD: "[REDACTED_PASSWORD]",
    EMAIL: "[REDACTED_EMAIL]",
    USERNAME: "[REDACTED_USERNAME]",
    IP_ADDRESS: "[REDACTED_IP_ADDRESS]",
    PATH_OR_USERNAME: "[REDACTED_USERNAME]",
    GITHUB_TOKEN: "[REDACTED_GITHUB_TOKEN]",
    GOOGLE_API_KEY: "[REDACTED_GOOGLE_API_KEY]",
    CLOUD_CREDENTIAL: "[REDACTED_CLOUD_CREDENTIAL]",
    URL_CREDENTIALS: "[REDACTED_URL_CREDENTIALS]",
    CONNECTION_STRING_PASSWORD: "[REDACTED_PASSWORD]",
    PRIVATE_KEY: "[REDACTED_PRIVATE_KEY]",
    SESSION_TOKEN: "[REDACTED_SESSION_TOKEN]",
    COOKIE_VALUE: "[REDACTED_COOKIE]",
    HEADER_CREDENTIAL: "[REDACTED_HEADER_CREDENTIAL]",
    BASIC_CREDENTIALS: "[REDACTED_BASIC_CREDENTIALS]",
    WEBHOOK_SECRET: "[REDACTED_WEBHOOK_SECRET]",
    URL_QUERY_SECRET: "[REDACTED_URL_SECRET]",
    IPV6_ADDRESS: "[REDACTED_IPV6_ADDRESS]",
    MAC_ADDRESS: "[REDACTED_MAC_ADDRESS]"
  };

  function isValidIpv4(candidate) {
    const parts = candidate.split(".");
    if (parts.length !== 4) {
      return false;
    }

    return parts.every(function (part) {
      if (!/^\d{1,3}$/.test(part)) {
        return false;
      }
      const value = Number(part);
      return value >= 0 && value <= 255;
    });
  }

  function isLoopbackIpv4(candidate) {
    return isValidIpv4(candidate) && candidate.split(".")[0] === "127";
  }

  function hasVersionFieldPrefix(source, candidateIndex) {
    const beforeCandidate = source.slice(Math.max(0, candidateIndex - 160), candidateIndex);
    return /(?:^|[^A-Za-z0-9_-])["']?(?:version|release)["']?(?:\s*[:=]\s*|\s+)["']?$/i.test(beforeCandidate) ||
      /(?:^|[^A-Za-z0-9_-])["']?(?:app[_-]?version|software[_-]?version)["']?\s*[:=]\s*["']?$/i.test(beforeCandidate);
  }

  function isRedactableIpv4(candidate, context) {
    return isValidIpv4(candidate) &&
      !isLoopbackIpv4(candidate) &&
      !(context && hasVersionFieldPrefix(context.source, context.index));
  }

  function buildRules(options) {
    const redactIpAddresses = options.redactIpAddresses !== false;

    const rules = [
      {
        category: "AUTHORIZATION_HEADER",
        label: REDACTION_LABELS.AUTHORIZATION_HEADER,
        pattern: /\b(Authorization\s*:\s*)(?:(?:Bearer|Basic|Token)\s+)?[A-Za-z0-9._~+/=-]{8,}/gi
      },
      {
        category: "BEARER_TOKEN",
        label: REDACTION_LABELS.BEARER_TOKEN,
        pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/g
      },
      {
        category: "JWT",
        label: REDACTION_LABELS.JWT,
        pattern: /[A-Za-z0-9_.-]+/g
      },
      {
        category: "AWS_ACCESS_KEY",
        label: REDACTION_LABELS.AWS_ACCESS_KEY,
        pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g
      },
      {
        category: "SLACK_TOKEN",
        label: REDACTION_LABELS.SLACK_TOKEN,
        pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g
      },
      {
        category: "API_KEY",
        label: REDACTION_LABELS.API_KEY,
        pattern: /((?:["']?)\b(?:[A-Za-z][A-Za-z0-9_.-]{0,62}_)?(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{12,})(\2|(?=[\r\n]|$))/gi
      },
      {
        category: "SECRET",
        label: REDACTION_LABELS.SECRET,
        pattern: /((?:["']?)\b(?:(?:[A-Za-z][A-Za-z0-9_.-]{0,62}_)?secret|[A-Za-z][A-Za-z0-9_.-]{0,62}_(?:auth_token|refresh_token|private_key))\b(?:["']?)\s*[:=]\s*)(["']?)((?:[^"'\s,;}{\\]|\\[^\r\n]|\\(?![^\r\n])){3,})(\2|(?=[\r\n]|$))/gi
      },
      {
        category: "PASSWORD",
        label: REDACTION_LABELS.PASSWORD,
        pattern: /((?:["']?)\b(?:[A-Za-z][A-Za-z0-9_.-]{0,62}_)?(?:password|passwd)\b(?:["']?)\s*[:=]\s*)(["']?)((?:[^"'\s,;}{\\]|\\[^\r\n]|\\(?![^\r\n])){3,})(\2|(?=[\r\n]|$))/gi
      },
      {
        category: "EMAIL",
        label: REDACTION_LABELS.EMAIL,
        pattern: /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b/gi
      },
      {
        category: "USERNAME",
        label: REDACTION_LABELS.USERNAME,
        pattern: /((?:["']?)\b(?:username|user[_-]?name|user)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9][A-Za-z0-9._-]{2,63})(\2)(?=$|[\s,;}\])<>(!?&|"'*])/gi
      },
      {
        category: "PATH_OR_USERNAME",
        label: REDACTION_LABELS.PATH_OR_USERNAME,
        pattern: /(^|[^A-Za-z0-9/\\._-])((?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)([A-Za-z0-9._-]+)([^\s"'<>]*))/g
      }
    ];

    if (redactIpAddresses) {
      rules.push({
        category: "IP_ADDRESS",
        label: REDACTION_LABELS.IP_ADDRESS,
        pattern: /(^|[^A-Za-z0-9_.-])((?:\d{1,3}\.){3}\d{1,3})(?=$|[^A-Za-z0-9_.-]|\.(?=$|[\s"')\]}]))/g,
        validator: function (candidate, context) {
          return options.includeLoopback ? isValidIpv4(candidate) && !hasVersionFieldPrefix(context.source, context.index) : isRedactableIpv4(candidate, context);
        }
      });
    }

    return rules;
  }

  const LIMITS = Object.freeze({ maxInputLength: 2097152, maxCandidates: 100000,
    maxJsonDepth: 64, maxFields: 50000 });
  // Opt-in session tier for the local worker and CLI; bounds are measured by evals/run-benchmarks.js.
  const LARGE_LIMITS = Object.freeze({ maxInputLength: 16777216, maxCandidates: 100000,
    maxJsonDepth: 64, maxFields: 1048576 });
  const DEFINITIONS = [
    ["AUTHORIZATION_HEADER", "credentials", "high", "Authorization value", "Explicit Authorization header", 100],
    ["BEARER_TOKEN", "tokens", "high", "Bearer token", "Bearer scheme with token syntax", 80],
    ["JWT", "tokens", "high", "JSON Web Token", "Three-part JWT syntax", 80],
    ["AWS_ACCESS_KEY", "credentials", "high", "AWS access key", "AWS access-key prefix and length", 80],
    ["SLACK_TOKEN", "tokens", "high", "Slack token", "Slack token prefix and length", 80],
    ["API_KEY", "credentials", "high", "API credential", "Explicit credential field", 100],
    ["SECRET", "secrets", "high", "Secret value", "Explicit secret field", 100],
    ["PASSWORD", "credentials", "high", "Password", "Explicit password field", 100],
    ["EMAIL", "email", "medium", "Email address", "Email-address syntax", 60],
    ["USERNAME", "usernames", "medium", "Account identity", "Explicit username field", 60],
    ["PATH_OR_USERNAME", "paths", "medium", "Home-directory identity", "Username component in a home-directory path", 60],
    ["IP_ADDRESS", "network", "review", "IPv4 address", "Validated IPv4 syntax; contextual policy required", 20],
    ["GITHUB_TOKEN", "tokens", "high", "GitHub token", "GitHub token prefix with exact length (gh[pousr]_ + 36, github_pat_ 22_59)", 85],
    ["GOOGLE_API_KEY", "credentials", "high", "Google API key", "AIza prefix with exact 39-character key length", 85],
    ["CLOUD_CREDENTIAL", "credentials", "high", "Cloud credential", "Azure AccountKey/SharedAccessKey/SharedAccessSignature field or explicit AWS secret/session field", 95],
    ["URL_CREDENTIALS", "credentials", "high", "URL credentials", "user:password@ userinfo in a scheme:// URL such as a database URL", 95],
    ["CONNECTION_STRING_PASSWORD", "credentials", "high", "Connection-string password", "Password/Pwd field inside a structured JDBC URL or ;-delimited ODBC/ADO connection string", 95],
    ["PRIVATE_KEY", "secrets", "high", "Private key block", "Private-key BEGIN marker through matching END; unclosed blocks redact to end of input (or JSON string value)", 120],
    ["SESSION_TOKEN", "tokens", "high", "Session credential", "Explicit session/CSRF field with token-like value", 90],
    ["COOKIE_VALUE", "tokens", "high", "Cookie value", "Value inside an explicit Cookie or Set-Cookie header", 90],
    ["HEADER_CREDENTIAL", "credentials", "high", "Header credential", "Explicit API-key or auth-token header", 95],
    ["BASIC_CREDENTIALS", "credentials", "high", "Basic credentials", "Basic scheme value that decodes to printable user:password", 95],
    ["WEBHOOK_SECRET", "tokens", "high", "Webhook secret", "Secret path of a Slack, Discord or Microsoft Teams/Office 365 webhook URL", 90],
    ["URL_QUERY_SECRET", "tokens", "high", "URL secret parameter", "Explicit secret query parameter (token, signature, password...) in a URL", 75],
    ["IPV6_ADDRESS", "network", "review", "IPv6 address", "Validated RFC 4291 IPv6 text syntax; contextual policy required", 21],
    ["MAC_ADDRESS", "network", "review", "MAC address", "Six hex octets with one consistent separator", 21]
  ];
  const DETECTORS = Object.freeze(DEFINITIONS.map(function (item) {
    return Object.freeze({ id: item[0].toLowerCase(), category: item[0], control: item[1],
      severity: item[2], description: item[3], reason: item[4], priority: item[5],
      replacement: REDACTION_LABELS[item[0]], replacementPolicy: "stable-marker",
      certainty: "deterministic-rule-match", contextRequirements: item[4],
      allowKeep: item[2] !== "high" });
  }));
  const BY_CATEGORY = Object.create(null);
  DETECTORS.forEach(function (detector) { BY_CATEGORY[detector.category] = detector; });
  const CONTROLS = Object.freeze(["credentials", "tokens", "secrets", "email", "usernames", "paths", "network"]);
  const LOCKED = Object.freeze(["credentials", "tokens", "secrets"]);
  const PROFILE_NAMES = Object.freeze(["strict", "support", "incident", "custom"]);
  const FORMATS = Object.freeze(["auto", "text", "json", "env", "headers", "logfmt"]);
  const MODES = Object.freeze(["redaction", "pseudonymization"]);
  const MARKER = /\[(?:REDACTED_[A-Z_]+|(?:EMAIL|USERNAME|PATH|IP|IPV6|MAC)_[1-9][0-9]{0,9})\]/g;
  const LEADING_MARKER = new RegExp("^" + MARKER.source);

  function existingMarker(value) {
    MARKER.lastIndex = 0;
    const match = MARKER.exec(value);
    return Boolean(match && match.index === 0 && match[0].length === value.length);
  }

  function plainObject(value) {
    if (value === null || typeof value !== "object") return false;
    const prototype = Object.getPrototypeOf(value);
    if (prototype === null) return true;
    const constructor = Object.getOwnPropertyDescriptor(prototype, "constructor");
    // Accept native Object prototypes from other realms, not custom prototypes.
    return Boolean(constructor && typeof constructor.value === "function" &&
      constructor.value.prototype === prototype &&
      Function.prototype.toString.call(constructor.value) === Function.prototype.toString.call(Object));
  }

  function inspectPolicy(options) {
    const settings = options === undefined ? {} : options;
    if (!plainObject(settings)) fail("INVALID_OPTIONS");
    const allowed = ["profile", "format", "redactIpAddresses", "categories", "network", "mode"];
    if (Object.keys(settings).some(function (key) { return allowed.indexOf(key) === -1; })) fail("UNKNOWN_OPTION");
    const mode = settings.mode === undefined ? "redaction" : settings.mode;
    if (MODES.indexOf(mode) === -1) fail("UNKNOWN_MODE");
    const name = settings.profile === undefined ? "legacy" : settings.profile;
    if (name !== "legacy" && PROFILE_NAMES.indexOf(name) === -1) fail("UNKNOWN_PROFILE");
    if (name !== "legacy" && settings.redactIpAddresses !== undefined) fail("AMBIGUOUS_POLICY");
    if (name !== "custom" && (settings.categories !== undefined || settings.network !== undefined)) fail("CUSTOM_ONLY");
    const categories = {};
    CONTROLS.forEach(function (control) { categories[control] = "REDACT"; });
    if (name === "incident" || (name === "legacy" && settings.redactIpAddresses === false)) categories.network = "KEEP";
    const network = { preserveLoopback: name === "support" || name === "legacy",
      preservePrivate: name === "support" };
    if (name === "custom") {
      if (settings.categories !== undefined) {
        if (!plainObject(settings.categories)) fail("INVALID_CATEGORIES");
        Object.keys(settings.categories).forEach(function (control) {
          if (CONTROLS.indexOf(control) === -1) fail("UNKNOWN_CATEGORY");
          const action = settings.categories[control];
          if (action !== "REDACT" && action !== "KEEP") fail("INVALID_ACTION");
          if (action === "KEEP" && LOCKED.indexOf(control) !== -1) fail("KEEP_FORBIDDEN");
          categories[control] = action;
        });
      }
      if (settings.network !== undefined) {
        if (!plainObject(settings.network)) fail("INVALID_NETWORK_POLICY");
        Object.keys(settings.network).forEach(function (key) {
          if (!(key === "preserveLoopback" || key === "preservePrivate") || typeof settings.network[key] !== "boolean") fail("INVALID_NETWORK_POLICY");
          network[key] = settings.network[key];
        });
      }
    }
    const descriptions = {
      legacy: "Compatibility: preserve loopback; redact other IPv4 (plus IPv6/MAC) unless explicitly disabled.",
      strict: "Redact all supported sensitive categories including loopback IPv4/IPv6.",
      support: "Redact credentials/identity; preserve RFC1918 private, IPv6 unique-local and loopback addresses for troubleshooting.",
      incident: "Redact credentials/identity; preserve IPv4/IPv6/MAC network evidence. Not a public-sharing default.",
      custom: "Explicit category/network controls; credentials, tokens and secrets remain locked to REDACT."
    };
    return Object.freeze({ name: name, mode: mode, description: descriptions[name],
      categories: Object.freeze(categories), network: Object.freeze(network), lockedCategories: LOCKED,
      networkClassification: "loopback 127/8 and ::1; private RFC1918; unique-local fc00::/7; link-local fe80::/10; IPv4-mapped IPv6 uses the IPv4 class; MAC hardware; other (not a routability claim)",
      diagnosticExceptions: "Explicit version/release and parsed request/trace/build ID fields exempt network identifiers (IPv4/IPv6/MAC) only" });
  }

  function ipv4Kind(value) {
    const octets = value.split(".").map(Number);
    if (octets[0] === 127) return "loopback";
    if (octets[0] === 10 || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)) return "private";
    return "other";
  }

  function hextets(part) {
    if (part === "") return [];
    const pieces = part.split(":");
    const groups = [];
    for (let index = 0; index < pieces.length; index += 1) {
      const piece = pieces[index];
      if (index === pieces.length - 1 && piece.indexOf(".") !== -1) {
        if (!isValidIpv4(piece)) return null;
        const octets = piece.split(".").map(Number);
        groups.push(octets[0] * 256 + octets[1], octets[2] * 256 + octets[3]);
      } else if (/^[0-9A-Fa-f]{1,4}$/.test(piece)) {
        groups.push(parseInt(piece, 16));
      } else {
        return null;
      }
    }
    return groups;
  }

  // Bounded RFC 4291 text parser: returns eight 16-bit groups or null.
  function parseIpv6(text) {
    if (text.length < 2 || text.length > 45) return null;
    const double = text.indexOf("::");
    if (double === -1) {
      const groups = hextets(text);
      return groups && groups.length === 8 ? groups : null;
    }
    if (text.indexOf("::", double + 1) !== -1 || text.slice(0, double).indexOf(".") !== -1) return null;
    const left = hextets(text.slice(0, double));
    const right = hextets(text.slice(double + 2));
    if (!left || !right || left.length + right.length > 7) return null;
    return left.concat(new Array(8 - left.length - right.length).fill(0), right);
  }

  function ipv6Kind(groups) {
    const prefixZero = groups.slice(0, 5).every(function (group) { return group === 0; });
    if (prefixZero && groups[5] === 0 && groups[6] === 0 && groups[7] === 1) return "loopback";
    if (prefixZero && groups[5] === 0xffff) {
      return ipv4Kind([groups[6] >> 8, groups[6] & 255, groups[7] >> 8, groups[7] & 255].join("."));
    }
    if ((groups[0] & 0xffc0) === 0xfe80) return "link-local";
    if ((groups[0] & 0xfe00) === 0xfc00) return "unique-local";
    return "other";
  }

  function fail(code) {
    const error = new Error("SafePaste: " + code);
    error.code = code;
    throw error;
  }

  function checkInput(input, limits) {
    const source = String(input || "");
    if (source.length > (limits || LIMITS).maxInputLength) fail("INPUT_LIMIT");
    return source;
  }

  function readQuoted(source, start, json) {
    const quote = source[start];
    let index = start + 1;
    const parts = [];
    const starts = [];
    const ends = [];
    while (index < source.length) {
      const origin = index;
      let character = source[index++];
      if (character === quote) return { start: start + 1, end: index - 1, next: index,
        value: parts.join(""), starts: starts, ends: ends, quoted: true };
      if (json && character.charCodeAt(0) < 32) fail("JSON_SYNTAX");
      if (!json && (character === "\n" || character === "\r")) fail("FIELD_SYNTAX");
      if (character === "\\" && (json || quote !== "'")) {
        const escaped = source[index++];
        const escapes = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (json && escaped === "u") {
          const hex = source.slice(index, index + 4);
          if (!/^[0-9a-f]{4}$/i.test(hex)) fail("JSON_SYNTAX");
          character = String.fromCharCode(parseInt(hex, 16));
          index += 4;
        } else if (Object.prototype.hasOwnProperty.call(escapes, escaped)) {
          character = escapes[escaped];
        } else if (json) {
          fail("JSON_SYNTAX");
        } else {
          // Unknown logfmt/env escapes stay literal (notably Windows paths).
          character = "\\" + (escaped || "");
        }
      }
      for (let part = 0; part < character.length; part += 1) {
        parts.push(character[part]); starts.push(origin); ends.push(index);
      }
    }
    fail(json ? "JSON_SYNTAX" : "FIELD_SYNTAX");
  }

  function parseJson(source, limits) {
    let index = 0;
    const units = [];
    function whitespace() { while (/[\x20\t\r\n]/.test(source[index] || "X")) index += 1; }
    function add(unit, key, isKey) {
      if (units.length >= limits.maxFields) fail("FIELD_LIMIT");
      unit.key = key;
      unit.isKey = isKey;
      units.push(unit);
    }
    function value(key, depth) {
      whitespace();
      const character = source[index];
      if (character === '"') {
        const unit = readQuoted(source, index, true);
        index = unit.next; add(unit, key, false); return;
      }
      if (character === "{" || character === "[") {
        if (depth >= limits.maxJsonDepth) fail("DEPTH_LIMIT");
        const object = character === "{";
        const close = object ? "}" : "]";
        index += 1; whitespace();
        if (source[index] === close) { index += 1; return; }
        while (index < source.length) {
          let childKey = null;
          if (object) {
            if (source[index] !== '"') fail("JSON_SYNTAX");
            const keyUnit = readQuoted(source, index, true);
            index = keyUnit.next; childKey = keyUnit.value; add(keyUnit, null, true);
            whitespace();
            if (source[index++] !== ":") fail("JSON_SYNTAX");
          }
          value(childKey, depth + 1); whitespace();
          if (source[index] === close) { index += 1; return; }
          if (source[index++] !== ",") fail("JSON_SYNTAX");
          whitespace();
        }
        fail("JSON_SYNTAX");
      }
      const start = index;
      while (index < source.length && !/[\s,}\]]/.test(source[index])) index += 1;
      const token = source.slice(start, index);
      if (!/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)$/.test(token)) fail("JSON_SYNTAX");
      add({ start: start, end: index, value: token, quoted: false }, key, false);
    }
    value(null, 0); whitespace();
    if (index !== source.length) fail("JSON_SYNTAX");
    return units;
  }

  function parseFields(source, format, limits) {
    const units = [];
    const assignments = /(?:^|[\s,;])(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]{0,63})[ \t]*=[ \t]*/g;
    const headers = /(?:^|[\r\n])([A-Za-z][A-Za-z0-9_-]{0,63})[ \t]*:[ \t]*/g;
    function add(unit, key) {
      if (units.length >= limits.maxFields) fail("FIELD_LIMIT");
      unit.key = key; units.push(unit);
    }
    function scan(pattern, header) {
      let match;
      while ((match = pattern.exec(source)) !== null) {
        const start = pattern.lastIndex;
        // A one-letter "header" followed by a slash is a Windows drive path (C:\Users\...), not a header.
        if (header && match[1].length === 1 && source[start - 1] === ":" && /[\\/]/.test(source[start] || "")) continue;
        let unit;
        if (!header && (source[start] === '"' || source[start] === "'")) {
          try { unit = readQuoted(source, start, false); }
          catch (error) {
            if (error.code !== "FIELD_SYNTAX") throw error;
            unit = unterminated(source, start, match[1]);
            if (!unit) continue;
          }
          pattern.lastIndex = unit.next;
        } else {
          let end = start;
          const fullLine = header || format === "env";
          while (end < source.length && (fullLine ? !/[\r\n]/.test(source[end]) : !/[\s,;]/.test(source[end]))) {
            if (!header && fullLine && source[end] === "#" && (end === start || /[ \t]/.test(source[end - 1]))) break;
            end += 1;
          }
          while (end > start && /[ \t]/.test(source[end - 1])) end -= 1;
          unit = { start: start, end: end, value: source.slice(start, end), quoted: false };
          pattern.lastIndex = Math.max(pattern.lastIndex, end);
        }
        add(unit, match[1]);
      }
    }
    if (format !== "headers") scan(assignments, false);
    if (format !== "env" && format !== "logfmt") scan(headers, true);
    units.sort(function (a, b) { return a.start - b.start || b.end - a.end; });
    return nonOverlapping(units);
  }

  function nonOverlapping(units) {
    let coveredEnd = -1;
    return units.filter(function (unit) {
      if (unit.start < coveredEnd) return false;
      coveredEnd = unit.end;
      return true;
    });
  }

  // An unterminated quoted value (e.g. a truncated log line) under an explicit credential or identity
  // key conservatively covers the rest of its line; other keys are skipped as before.
  function unterminated(source, quote, key) {
    if (!explicitCategory(key)) return null;
    let end = quote + 1;
    while (end < source.length && source[end] !== "\n" && source[end] !== "\r") end += 1;
    return { start: quote + 1, end: end, next: end, value: source.slice(quote + 1, end), quoted: false };
  }

  // JSON-style "key":"value" pairs embedded in non-JSON input (log lines, NDJSON, truncated JSON).
  // Values are decoded with JSON escapes so escaped quotes and spaces cannot split a credential;
  // an unterminated or invalid string under an explicit key extends to the end of its line.
  function parseJsonPairs(source, limits, used) {
    const pairs = [];
    const pattern = /"((?:[^"\\\r\n]|\\[^\r\n]){1,128})"[ \t]*:[ \t]*"/g;
    let match;
    while ((match = pattern.exec(source)) !== null) {
      let key;
      try { key = readQuoted(source, match.index, true).value; }
      catch (error) { if (error.code !== "JSON_SYNTAX") throw error; pattern.lastIndex = match.index + 1; continue; }
      const quote = pattern.lastIndex - 1;
      let unit;
      try { unit = readQuoted(source, quote, true); }
      catch (error) {
        if (error.code !== "JSON_SYNTAX") throw error;
        unit = unterminated(source, quote, key);
        if (!unit) { pattern.lastIndex = quote + 1; continue; }
      }
      if (used + pairs.length >= limits.maxFields) fail("FIELD_LIMIT");
      unit.key = key; pairs.push(unit);
      pattern.lastIndex = unit.next;
    }
    return nonOverlapping(pairs);
  }

  function parseInput(source, requested, limits) {
    if (FORMATS.indexOf(requested) === -1) fail("UNKNOWN_FORMAT");
    let format = requested;
    if (format === "auto") {
      const trimmed = source.trimStart();
      // SafePaste's own output may start with a marker (e.g. a redacted PEM block); that is not JSON.
      if (/^[{[\"]/.test(trimmed) && !LEADING_MARKER.test(trimmed)) format = "json";
      else {
        const lines = source.split(/\r\n|[\r\n]/).filter(function (line) { return line.trim() && !/^\s*#/.test(line); });
        if (lines.length && lines.every(function (line) { return /^(?:export[ \t]+)?[A-Za-z_][\w.-]{0,63}[ \t]*=[ \t]*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'#]*)(?:[ \t]+#[^\r\n]*)?[ \t]*$/.test(line); })) format = "env";
        else if (lines.length && lines.every(function (line) { return /^(?![A-Za-z]:[\\/])[A-Za-z][\w-]{0,63}[ \t]*:/.test(line); })) format = "headers";
        else if (/(?:^|\s)[A-Za-z_][\w.-]{0,63}[ \t]*=/.test(source)) format = "logfmt";
        else format = "text";
      }
    }
    if (format === "json") {
      try { return { format: format, status: "parsed", units: parseJson(source, limits), pairs: [] }; }
      catch (error) {
        if (error.code !== "JSON_SYNTAX") throw error;
        const fallback = parseFields(source, "text", limits);
        return { format: "text", status: "malformed-json-fallback", units: fallback,
          pairs: parseJsonPairs(source, limits, fallback.length) };
      }
    }
    const units = requested === "text" ? [] : parseFields(source, format, limits);
    return { format: format, status: format === "text" ? "text" : "parsed", units: units,
      pairs: requested === "text" ? [] : parseJsonPairs(source, limits, units.length) };
  }

  function explicitCategory(key) {
    if (!key) return null;
    if (/^(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)$/i.test(key)) return "API_KEY";
    if (/^(?:password|passwd)$/i.test(key)) return "PASSWORD";
    if (/^secret$/i.test(key)) return "SECRET";
    if (/^(?:username|user[_-]?name|user)$/i.test(key)) return "USERNAME";
    if (/^authorization$/i.test(key)) return "AUTHORIZATION_HEADER";
    if (/^proxy-authorization$/i.test(key)) return "AUTHORIZATION_HEADER";
    if (/^(?:aws_secret_access_key|secret_access_key|aws_session_token|accountkey|sharedaccesskey|sharedaccesssignature)$/i.test(key)) return "CLOUD_CREDENTIAL";
    if (/^(?:x-api-key|x-auth-token|auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token|x-amz-security-token|x-goog-api-key)$/i.test(key)) return "HEADER_CREDENTIAL";
    if (/^(?:session(?:[_-]?(?:id|token|key))?|sessionid|jsessionid|phpsessid|asp\.net_sessionid|csrf[_-]?token|xsrf[_-]?token)$/i.test(key)) return "SESSION_TOKEN";
    if (/^(?:set-)?cookie$/i.test(key)) return "COOKIE";
    // Explicit secret-suffix assignments (.env style); bare PWD and *_TOKENS stay unclassified.
    if (/^[A-Za-z][A-Za-z0-9_.-]{0,62}_(?:PASSWORD|PASSWD)$/i.test(key)) return "PASSWORD";
    if (/^[A-Za-z][A-Za-z0-9_.-]{0,62}_(?:API_?KEY|SECRET_KEY|ACCESS_TOKEN|CLIENT_SECRET)$/i.test(key)) return "API_KEY";
    if (/^[A-Za-z][A-Za-z0-9_.-]{0,62}_(?:SECRET|AUTH_TOKEN|REFRESH_TOKEN|PRIVATE_KEY)$/i.test(key)) return "SECRET";
    return null;
  }

  function diagnosticKey(key) {
    return /^(?:version|release|app[_-]?version|software[_-]?version|request[_-]?id|trace[_-]?id|build[_-]?id)$/i.test(key || "");
  }

  function collectParsed(source, options, parsed) {
    function within(units, candidate) {
      let low = 0; let high = units.length;
      while (low < high) {
        const middle = Math.floor((low + high) / 2);
        if (units[middle].end <= candidate.start) low = middle + 1;
        else high = middle;
      }
      return low < units.length && units[low].start <= candidate.start && units[low].end >= candidate.end;
    }
    function overlapsUnit(candidate) { return within(parsed.units, candidate) || within(parsed.pairs, candidate); }
    // Context-dependent detectors (chains, cookies, URLs, blocks) keep source-level matches; overlaps merge later.
    const candidates = parsed.format === "json" ? [] : collect(source, options).filter(function (candidate) { return candidate.contextual || !overlapsUnit(candidate); });
    parsed.units.concat(parsed.pairs).forEach(function (unit) {
      function add(start, end, detector, networkKind, value) {
        if (candidates.length >= LIMITS.maxCandidates) fail("FINDING_LIMIT");
        candidates.push({ start: unit.starts ? unit.starts[start] : unit.start + start,
          end: unit.ends ? unit.ends[end - 1] : unit.start + end, detector: detector, networkKind: networkKind,
          value: value === undefined ? unit.value.slice(start, end) : value,
          replacement: parsed.format === "json" && !unit.quoted ? JSON.stringify(detector.replacement) : detector.replacement });
      }
      const category = explicitCategory(unit.key);
      const minimum = category === "API_KEY" ? 12 : ["AUTHORIZATION_HEADER", "HEADER_CREDENTIAL", "CLOUD_CREDENTIAL"].indexOf(category) !== -1 ? 8 : 3;
      // A username followed by markup/punctuation (e.g. "alice</b>", "alice)") keeps only the identity part.
      const identity = category === "USERNAME" ? /^[\p{L}\p{N}][\p{L}\p{N}\p{M}._-]{2,63}(?=$|[\])<>(!?&|"'*])/u.exec(unit.value) : null;
      const validIdentity = category !== "USERNAME" || Boolean(identity);
      const valueEnd = identity ? identity[0].length : unit.value.length;
      const validToken = category !== "SESSION_TOKEN" || tokenLike(unit.value);
      if (category === "COOKIE" && !unit.isKey) {
        scanCookies(unit.value, 0, /^set-/i.test(unit.key), function (start, end, name) { add(start, end, BY_CATEGORY[name]); });
      } else if (category && !existingMarker(unit.value) && validIdentity && validToken && unit.value.length >= minimum && !(parsed.format === "json" && unit.value === "null" && !unit.quoted)) {
        add(0, valueEnd, BY_CATEGORY[category]);
      }
      collect(unit.value, options).forEach(function (candidate) {
        if (candidate.detector.control === "network" && diagnosticKey(unit.key)) return;
        add(candidate.start, candidate.end, candidate.detector, candidate.networkKind, candidate.value);
      });
    });
    return candidates;
  }

  function collectJwtToken(token, offset, candidates) {
    let firstStart = 0;
    let firstEnd = token.indexOf(".");
    if (firstEnd === -1) return;
    let secondEnd = token.indexOf(".", firstEnd + 1);
    while (secondEnd !== -1) {
      let thirdEnd = token.indexOf(".", secondEnd + 1);
      if (thirdEnd === -1) thirdEnd = token.length;
      const first = token.slice(firstStart, firstEnd);
      const second = token.slice(firstEnd + 1, secondEnd);
      let signatureEnd = thirdEnd;
      while (signatureEnd > secondEnd + 1 && token[signatureEnd - 1] === "-") signatureEnd -= 1;
      const header = /(?:^|-)(eyJ[A-Za-z0-9_-]{8,})$/.exec(first);
      if (header && /^eyJ[A-Za-z0-9_-]{8,}$/.test(second) && signatureEnd - secondEnd - 1 >= 8) {
        if (candidates.length >= LIMITS.maxCandidates) fail("FINDING_LIMIT");
        candidates.push({ start: offset + firstEnd - header[1].length,
          end: offset + signatureEnd, detector: BY_CATEGORY.JWT });
      }
      firstStart = firstEnd + 1;
      firstEnd = secondEnd;
      secondEnd = thirdEnd === token.length ? -1 : thirdEnd;
    }
  }

  const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const CONNECTION_MARKERS = new Set(["driver", "dsn", "server", "data source", "provider", "database",
    "initial catalog", "host", "hostname", "address", "addr", "network address"]);
  const CONNECTION_PASSWORDS = new Set(["password", "pwd", "passwd"]);
  const CONNECTION_USERS = new Set(["uid", "user id", "user", "username"]);
  const AZURE_KEYS = new Set(["accountkey", "sharedaccesskey", "sharedaccesssignature"]);
  const QUERY_SECRETS = new Set(["token", "access_token", "refresh_token", "id_token", "auth_token", "api_key",
    "apikey", "client_secret", "secret", "password", "passwd", "sig", "signature", "x-amz-signature",
    "x-amz-security-token", "x-goog-signature", "session", "sessionid", "session_id", "jsessionid"]);
  const TEXT_FIELDS = [
    [/((?:^|[^A-Za-z0-9_.-])["']?(?:aws_secret_access_key|secret_access_key|aws_session_token)["']?[ \t]*[:=][ \t]*)(["']?)([A-Za-z0-9/+=]{16,4096})/gi, "CLOUD_CREDENTIAL"],
    [/((?:^|[^A-Za-z0-9_-])["']?(?:x-api-key|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token|x-amz-security-token|x-goog-api-key|auth-token)["']?[ \t]*[:=][ \t]*)(["']?)([A-Za-z0-9._~+/=:-]{8,8192})/gi, "HEADER_CREDENTIAL"],
    [/((?:^|[^A-Za-z0-9_.-])["']?(?:session(?:[_-]?(?:id|token|key))?|sessionid|jsessionid|phpsessid|asp\.net_sessionid|csrf[_-]?token|xsrf[_-]?token)["']?[ \t]*[:=][ \t]*)(["']?)([A-Za-z0-9._~+/=%-]{8,4096})/gi, "SESSION_TOKEN"]
  ];

  function tokenLike(value) {
    return value.length >= 8 && value.length <= 4096 && /^[A-Za-z0-9._~+/=%:-]+$/.test(value) &&
      ((/[0-9]/.test(value) && /[A-Za-z]/.test(value)) || value.length >= 24);
  }

  function decodesToBasicPair(text) {
    const body = text.replace(/=+$/, "");
    if (body.length % 4 === 1 || (body.length !== text.length && text.length % 4 !== 0)) return false;
    let buffer = 0;
    let bits = 0;
    let decoded = "";
    for (let index = 0; index < body.length; index += 1) {
      buffer = (buffer << 6) | BASE64.indexOf(body[index]);
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        const code = (buffer >> bits) & 255;
        if (code < 32 || code > 126) return false;
        decoded += String.fromCharCode(code);
      }
      buffer &= (1 << bits) - 1;
    }
    const colon = decoded.indexOf(":");
    return colon > 0 && colon < decoded.length - 1;
  }

  function scanCookies(text, index, setCookie, push) {
    const pair = /[ \t]*([^\s=;,"]{1,256})=/y;
    while (index < text.length) {
      pair.lastIndex = index;
      if (!pair.exec(text)) return;
      let start = pair.lastIndex;
      const quoted = text[start] === '"';
      if (quoted) start += 1;
      let end = start;
      while (end < text.length && !/[\s";,\\]/.test(text[end])) end += 1;
      if (quoted && text[end] !== '"') return;
      if (end > start && !existingMarker(text.slice(start, end))) push(start, end, "COOKIE_VALUE");
      index = quoted ? end + 1 : end;
      if (setCookie || text[index] !== ";") return;
      index += 1;
    }
  }

  // Reads a contiguous ;-delimited key=value chain (ODBC/ADO/Azure syntax).
  function readChain(text, index) {
    const pairs = [];
    const keyPattern = /([A-Za-z][A-Za-z0-9 _.]{0,31}?)[ \t]*=[ \t]*/y;
    while (pairs.length < 64) {
      keyPattern.lastIndex = index;
      const match = keyPattern.exec(text);
      if (!match) break;
      let start = keyPattern.lastIndex;
      let end;
      let next;
      const open = text[start];
      if (open === "{" || open === '"' || open === "'") {
        const close = open === "{" ? "}" : open;
        end = start + 1;
        while (end < text.length && text[end] !== "\n" && text[end] !== "\r" &&
          !(text[end] === close && text[end + 1] !== close)) end += text[end] === close ? 2 : 1;
        if (text[end] !== close) break;
        next = end + 1;
        start += 1;
      } else {
        end = start;
        let space = -1;
        while (end < text.length && !/[;\r\n"'`]/.test(text[end])) {
          if (text[end] === " " || text[end] === "\t") { if (space === -1) space = end; }
          else if (text[end] === "=" && space !== -1) { end = space; break; }
          end += 1;
        }
        next = end;
        while (end > start && (text[end - 1] === " " || text[end - 1] === "\t")) end -= 1;
      }
      pairs.push({ key: match[1].trim().toLowerCase(), start: start, end: end });
      index = next;
      while (text[index] === " " || text[index] === "\t") index += 1;
      if (text[index] !== ";") break;
      index += 1;
      while (text[index] === " " || text[index] === "\t") index += 1;
    }
    return { pairs: pairs, end: index };
  }

  function scanConnectionStrings(text, push) {
    const starts = /[\s"'`({,][A-Za-z]/g;
    let index = /^[A-Za-z]/.test(text) ? 0 : -1;
    let match;
    while (true) {
      if (index === -1) {
        match = starts.exec(text);
        if (!match) break;
        index = match.index + 1;
      }
      const chain = readChain(text, index);
      starts.lastIndex = Math.max(starts.lastIndex, chain.end, index);
      index = -1;
      const connection = chain.pairs.length >= 2 && chain.pairs.some(function (pair) { return CONNECTION_MARKERS.has(pair.key); });
      chain.pairs.forEach(function (pair) {
        const value = text.slice(pair.start, pair.end);
        if (!value || existingMarker(value)) return;
        if (AZURE_KEYS.has(pair.key) && value.length >= 8) push(pair.start, pair.end, "CLOUD_CREDENTIAL");
        else if (connection && CONNECTION_PASSWORDS.has(pair.key)) push(pair.start, pair.end, "CONNECTION_STRING_PASSWORD");
        else if (connection && CONNECTION_USERS.has(pair.key) && /^[\p{L}\p{N}][\p{L}\p{N}\p{M}._@\\-]{1,127}$/u.test(value)) push(pair.start, pair.end, "USERNAME");
      });
    }
    const jdbc = /\bjdbc:[A-Za-z0-9]{1,32}:[^\s"'<>`]{1,8192}/gi;
    while ((match = jdbc.exec(text)) !== null) {
      const token = match[0];
      const offset = match.index;
      const oracle = /^jdbc:oracle:(?:thin|oci):([^\/@\s;:]{1,128})\/([^@\s]{1,256})@/i.exec(token);
      if (oracle) {
        const passwordStart = offset + oracle[0].length - 1 - oracle[2].length;
        push(passwordStart - 1 - oracle[1].length, passwordStart - 1, "USERNAME");
        push(passwordStart, passwordStart + oracle[2].length, "CONNECTION_STRING_PASSWORD");
      }
      const parameter = /[;?&]([A-Za-z][A-Za-z0-9_.-]{0,31})=([^;&\s]*)/g;
      let found;
      while ((found = parameter.exec(token)) !== null) {
        const key = found[1].toLowerCase();
        const start = offset + found.index + found[0].length - found[2].length;
        if (!found[2] || existingMarker(found[2])) continue;
        if (CONNECTION_PASSWORDS.has(key)) push(start, start + found[2].length, "CONNECTION_STRING_PASSWORD");
        else if (CONNECTION_USERS.has(key)) push(start, start + found[2].length, "USERNAME");
      }
    }
  }

  function webhookPrefix(host, path) {
    let match = null;
    if (host === "hooks.slack.com") match = /^\/(?:services|workflows|triggers)\//.exec(path);
    else if (/^(?:(?:ptb|canary)\.)?discord(?:app)?\.com$/.test(host)) match = /^\/api\/(?:v\d{1,2}\/)?webhooks\//.exec(path);
    else if (/\.webhook\.office\.com$/.test(host)) match = /^\/webhookb2\//.exec(path);
    else if (host === "outlook.office.com" || host === "outlook.office365.com") match = /^\/webhook\//.exec(path);
    return match ? match[0].length : -1;
  }

  function scanUrls(text, push) {
    const url = /([A-Za-z][A-Za-z0-9+.-]{1,31}):\/\/([^\s"'<>\\`]{1,8192})/g;
    let match;
    while ((match = url.exec(text)) !== null) {
      const base = match.index + match[1].length + 3;
      const body = match[2].replace(/[.,;:!?)\]}]+$/, "");
      let authorityEnd = body.search(/[/?#]/);
      if (authorityEnd === -1) authorityEnd = body.length;
      const authority = body.slice(0, authorityEnd);
      const at = authority.lastIndexOf("@");
      if (at > 0) {
        const colon = authority.indexOf(":");
        if (colon !== -1 && colon < at - 1 && !existingMarker(authority.slice(0, at)) && !existingMarker(authority.slice(colon + 1, at))) push(base, base + at, "URL_CREDENTIALS");
      }
      const host = authority.slice(at + 1).replace(/:\d{1,5}$/, "").toLowerCase();
      let pathEnd = body.slice(authorityEnd).search(/[?#]/);
      pathEnd = pathEnd === -1 ? body.length : authorityEnd + pathEnd;
      const prefix = webhookPrefix(host, body.slice(authorityEnd, pathEnd));
      if (prefix !== -1 && pathEnd - authorityEnd - prefix >= 8) push(base + authorityEnd + prefix, base + pathEnd, "WEBHOOK_SECRET");
      if (body[pathEnd] !== "?") continue;
      const queryEnd = body.indexOf("#", pathEnd) === -1 ? body.length : body.indexOf("#", pathEnd);
      let cursor = pathEnd + 1;
      while (cursor < queryEnd) {
        let next = body.indexOf("&", cursor);
        if (next === -1 || next > queryEnd) next = queryEnd;
        const equals = body.indexOf("=", cursor);
        if (equals !== -1 && equals < next) {
          const value = body.slice(equals + 1, next);
          if (QUERY_SECRETS.has(body.slice(cursor, equals).toLowerCase()) && value.length >= 4 && !existingMarker(value)) {
            push(base + equals + 1, base + next, "URL_QUERY_SECRET");
          }
        }
        cursor = next + 1;
      }
    }
  }

  function scanNetwork(text, options, push) {
    const word = /[A-Za-z0-9_]/;
    const run = /[0-9A-Fa-f:.]{2,}/g;
    let match;
    while ((match = run.exec(text)) !== null) {
      let start = match.index;
      let value = match[0];
      const first = value.indexOf(":");
      if (first === -1 || value.indexOf(":", first + 1) === -1) continue;
      if (value[0] === ":" && value[1] !== ":") { start += 1; value = value.slice(1); }
      value = value.replace(/\.+$/, "");
      if (/[^:]:$/.test(value)) value = value.slice(0, -1);
      let end = start + value.length;
      if (word.test(text[start - 1] || "") || hasVersionFieldPrefix(text, start)) continue;
      if (/^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/.test(value)) {
        // All-decimal sextets are ambiguous with build/time IDs and stay unflagged.
        if (/[A-Fa-f]/.test(value) && !word.test(text[end] || "")) push(start, end, "MAC_ADDRESS", "hardware", value.toLowerCase());
        continue;
      }
      const groups = parseIpv6(value);
      // Require a decimal digit so hex-word scopes such as dead::beef or cafe::face stay unflagged.
      if (!/[0-9]/.test(value) || !groups || groups.every(function (group) { return group === 0; })) continue;
      const kind = ipv6Kind(groups);
      if (kind === "link-local" && text[end] === "%") {
        const zone = /^%[A-Za-z0-9_-]{1,32}/.exec(text.slice(end, end + 34));
        if (zone) end += zone[0].length;
      }
      if (word.test(text[end] || "") || (kind === "loopback" && !options.includeLoopback)) continue;
      push(start, end, "IPV6_ADDRESS", kind, groups.map(function (group) { return group.toString(16); }).join(":"));
    }
    const dashed = /(^|[^A-Za-z0-9_-])([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})(?![A-Za-z0-9_-])/g;
    while ((match = dashed.exec(text)) !== null) {
      const start = match.index + match[1].length;
      if (!/[A-Fa-f]/.test(match[2]) || hasVersionFieldPrefix(text, start)) continue;
      push(start, start + match[2].length, "MAC_ADDRESS", "hardware", match[2].toLowerCase().replace(/-/g, ":"));
    }
  }

  function scanPrivateKeys(text, push) {
    const begin = /-----BEGIN ((?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/g;
    let match;
    while ((match = begin.exec(text)) !== null) {
      const closing = "-----END " + match[1] + "-----";
      const found = text.indexOf(closing, begin.lastIndex);
      const end = found === -1 ? text.length : found + closing.length;
      push(match.index, end, "PRIVATE_KEY");
      begin.lastIndex = end;
    }
  }

  function collectExtended(text, options, push) {
    let match;
    scanPrivateKeys(text, push);
    const github = /(^|[^A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?![A-Za-z0-9_])/g;
    while ((match = github.exec(text)) !== null) push(match.index + match[1].length, match.index + match[0].length, "GITHUB_TOKEN");
    const google = /(^|[^A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g;
    while ((match = google.exec(text)) !== null) push(match.index + match[1].length, match.index + match[0].length, "GOOGLE_API_KEY");
    TEXT_FIELDS.forEach(function (field) {
      const pattern = field[0];
      pattern.lastIndex = 0;
      while ((match = pattern.exec(text)) !== null) {
        if (field[1] === "SESSION_TOKEN" && !tokenLike(match[3])) continue;
        if (existingMarker(match[3])) continue;
        const start = match.index + match[1].length + match[2].length;
        push(start, start + match[3].length, field[1]);
      }
    });
    const basic = /\bBasic[ \t]+([A-Za-z0-9+/]{8,4096}={0,2})(?![A-Za-z0-9+/=])/gi;
    while ((match = basic.exec(text)) !== null) {
      if (decodesToBasicPair(match[1])) push(match.index + match[0].length - match[1].length, match.index + match[0].length, "BASIC_CREDENTIALS");
    }
    const cookie = /(^|[^A-Za-z0-9_-])((?:set-)?cookie)[ \t]*:[ \t]*/gi;
    while ((match = cookie.exec(text)) !== null) scanCookies(text, cookie.lastIndex, /^set-/i.test(match[2]), push);
    scanConnectionStrings(text, push);
    scanUrls(text, push);
    if (options.redactIpAddresses !== false) scanNetwork(text, options, push);
  }

  function collect(source, options) {
    const candidates = [];
    function push(start, end, category, networkKind, value) {
      if (end <= start) return;
      if (candidates.length >= LIMITS.maxCandidates) fail("FINDING_LIMIT");
      candidates.push({ start: start, end: end, detector: BY_CATEGORY[category], networkKind: networkKind,
        value: value, contextual: !networkKind });
    }
    collectExtended(source, options, push);
    buildRules(options).forEach(function (rule) {
      let match;
      while ((match = rule.pattern.exec(source)) !== null) {
        if (rule.category === "JWT") {
          collectJwtToken(match[0], match.index, candidates);
          continue;
        }
        let start = match.index;
        let value = match[0];
        if (rule.category === "AUTHORIZATION_HEADER") {
          start += match[1].length;
          value = match[0].slice(match[1].length);
        } else if (["API_KEY", "SECRET", "PASSWORD", "USERNAME"].indexOf(rule.category) !== -1) {
          start += match[1].length + match[2].length;
          value = match[3];
        } else if (rule.category === "PATH_OR_USERNAME") {
          start += match[1].length + /^(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)/.exec(match[2])[0].length;
          value = match[3];
        } else if (rule.category === "IP_ADDRESS") {
          start += match[1].length;
          value = match[2];
        }
        if (rule.validator && !rule.validator(value, { source: source, index: start })) continue;
        if (candidates.length >= LIMITS.maxCandidates) fail("FINDING_LIMIT");
        candidates.push({ start: start, end: start + value.length, detector: BY_CATEGORY[rule.category],
          networkKind: rule.category === "IP_ADDRESS" ? ipv4Kind(value) : undefined });
      }
    });
    const markers = Array.from(source.matchAll(new RegExp(MARKER.source, "g")));
    let markerIndex = 0;
    return candidates.sort(function (a, b) { return a.start - b.start; }).filter(function (candidate) {
      while (markerIndex < markers.length && markers[markerIndex].index + markers[markerIndex][0].length <= candidate.start) markerIndex += 1;
      const marker = markers[markerIndex];
      return !marker || !(candidate.start >= marker.index && candidate.end <= marker.index + marker[0].length);
    });
  }

  function resolve(candidates) {
    candidates.sort(function (a, b) {
      return a.start - b.start || b.detector.priority - a.detector.priority || b.end - a.end;
    });
    const resolved = [];
    // URL userinfo is a closed span: weaker matches starting inside it (e.g. pass@host read as an
    // email) are dropped instead of widening the replacement over the host/port context.
    let closed = null;
    candidates.forEach(function (candidate) {
      const previous = resolved[resolved.length - 1];
      if (closed && candidate !== closed && candidate.start < closed.end && candidate.detector.priority < closed.detector.priority) return;
      if (candidate.detector.category === "URL_CREDENTIALS" && (!closed || candidate.end > closed.end)) closed = candidate;
      if (previous && candidate.start < previous.end) {
        previous.end = Math.max(previous.end, candidate.end);
        if (candidate.detector.priority > previous.detector.priority) {
          previous.detector = candidate.detector;
          previous.replacement = candidate.replacement;
          previous.networkKind = candidate.networkKind;
          previous.value = candidate.value;
        }
      } else {
        resolved.push({ start: candidate.start, end: candidate.end, detector: candidate.detector,
          replacement: candidate.replacement, networkKind: candidate.networkKind, value: candidate.value });
      }
    });
    return resolved;
  }

  function lineStarts(source) {
    const starts = [0];
    for (let index = 0; index < source.length; index += 1) {
      if (source[index] === "\n" || source[index] === "\r") {
        if (source[index] === "\r" && source[index + 1] === "\n") index += 1;
        starts.push(index + 1);
      }
    }
    return starts;
  }

  function position(starts, offset) {
    let low = 0;
    let high = starts.length;
    while (low + 1 < high) {
      const middle = Math.floor((low + high) / 2);
      if (starts[middle] <= offset) low = middle;
      else high = middle;
    }
    return Object.freeze({ line: low + 1, column: offset - starts[low] + 1 });
  }

  function findingMetadata(candidates, starts, policy) {
    return Object.freeze(candidates.map(function (candidate, index) {
      const detector = candidate.detector;
      let action = policy.categories[detector.control];
      let policyReason = action === "KEEP" ? "category-preserved" : "category-redacted";
      if (detector.control === "network" && action === "REDACT" &&
        ((candidate.networkKind === "loopback" && policy.network.preserveLoopback) ||
        ((candidate.networkKind === "private" || candidate.networkKind === "unique-local") && policy.network.preservePrivate))) {
        action = "KEEP";
        policyReason = "network-context-preserved";
      }
      return Object.freeze({ id: "finding-" + (index + 1), ruleId: detector.id,
        category: detector.category, control: detector.control, severity: detector.severity,
        reason: detector.reason, description: detector.description,
        certainty: detector.certainty, replacementPolicy: detector.replacementPolicy,
        start: candidate.start, end: candidate.end,
        position: position(starts, candidate.start), endPosition: position(starts, candidate.end),
        replacement: candidate.replacement || detector.replacement, action: action,
        policyReason: policyReason, networkKind: detector.control === "network" ? candidate.networkKind : null,
        allowKeep: detector.allowKeep });
    }));
  }

  function applyFindings(source, findings) {
    const pieces = [];
    let cursor = 0;
    findings.forEach(function (finding) {
      pieces.push(source.slice(cursor, finding.start), finding.action === "KEEP" ? source.slice(finding.start, finding.end) : finding.replacement);
      cursor = finding.end;
    });
    pieces.push(source.slice(cursor));
    return pieces.join("");
  }

  function prepareReview(source, settings, policy, pseudonyms, limits) {
    const starts = lineStarts(source);
    const parsed = parseInput(source, settings.format === undefined ? "auto" : settings.format, limits);
    const detectionOptions = { redactIpAddresses: policy.name !== "legacy" || settings.redactIpAddresses !== false,
      includeLoopback: policy.name !== "legacy" };
    const candidates = resolve(collectParsed(source, detectionOptions, parsed));
    if (policy.mode === "pseudonymization") {
      pseudonyms.reserve(source);
      parsed.units.concat(parsed.pairs).forEach(function (unit) { pseudonyms.reserve(unit.value); });
      candidates.forEach(function (candidate) {
        if (!candidate.detector.allowKeep) return;
        candidate.replacement = pseudonyms.marker(candidate.detector.category,
          candidate.value === undefined ? source.slice(candidate.start, candidate.end) : candidate.value);
      });
    }
    const findings = findingMetadata(candidates, starts, policy);
    return { findings: findings, format: parsed.format, parseStatus: parsed.status, inputLines: starts.length };
  }

  function makeReport(length, analysis, policy, findings) {
    const counts = {};
    CONTROLS.forEach(function (control) { counts[control] = { detected: 0, redacted: 0, kept: 0 }; });
    let redacted = 0;
    findings.forEach(function (finding) {
      const count = counts[finding.control];
      count.detected += 1;
      if (finding.action === "REDACT") { count.redacted += 1; redacted += 1; }
      else count.kept += 1;
    });
    CONTROLS.forEach(function (control) { Object.freeze(counts[control]); });
    return Object.freeze({ engineVersion: 8, profile: policy.name, mode: policy.mode, policy: policy,
      format: analysis.format, parseStatus: analysis.parseStatus,
      inputLength: length, inputLines: analysis.inputLines, totalFindings: findings.length,
      redacted: redacted, kept: findings.length - redacted,
      categoryCounts: Object.freeze(counts), findings: findings,
      networkEgress: "none", persistentStorage: "none" });
  }

  function applyOverrides(findings, overrides) {
    if (overrides === undefined) return findings;
    if (!plainObject(overrides)) fail("INVALID_OVERRIDES");
    const keys = Object.keys(overrides);
    if (keys.length > LIMITS.maxCandidates) fail("OVERRIDE_LIMIT");
    const ids = new Set(findings.map(function (finding) { return finding.id; }));
    keys.forEach(function (id) {
      if (!ids.has(id)) fail("UNKNOWN_FINDING");
      if (overrides[id] !== "KEEP" && overrides[id] !== "REDACT") fail("INVALID_ACTION");
    });
    return Object.freeze(findings.map(function (finding) {
      if (!Object.prototype.hasOwnProperty.call(overrides, finding.id)) return finding;
      const action = overrides[finding.id];
      if (action === "KEEP" && !finding.allowKeep) fail("KEEP_FORBIDDEN");
      return Object.freeze(Object.assign({}, finding, { action: action, policyReason: "human-override" }));
    }));
  }

  function createPseudonyms() {
    const maps = new Map();
    const occupied = new Set();
    const names = { EMAIL: "EMAIL", USERNAME: "USERNAME", PATH_OR_USERNAME: "PATH", IP_ADDRESS: "IP",
      IPV6_ADDRESS: "IPV6", MAC_ADDRESS: "MAC" };
    return {
      reserve: function (source) {
        for (const match of source.matchAll(new RegExp(MARKER.source, "g"))) {
          if (!occupied.has(match[0]) && occupied.size >= LIMITS.maxCandidates) fail("SESSION_LIMIT");
          occupied.add(match[0]);
        }
      },
      marker: function (category, value) {
        if (!maps.has(category)) maps.set(category, { values: new Map(), next: 1 });
        const map = maps.get(category);
        if (map.values.has(value)) return map.values.get(value);
        if (occupied.size >= LIMITS.maxCandidates) fail("SESSION_LIMIT");
        let marker;
        do { marker = "[" + names[category] + "_" + map.next++ + "]"; } while (occupied.has(marker));
        occupied.add(marker);
        map.values.set(value, marker);
        return marker;
      },
      clear: function () { maps.clear(); occupied.clear(); }
    };
  }

  function buildReview(input, options, pseudonyms, release, limits) {
    let source = checkInput(input, limits);
    const policy = inspectPolicy(options);
    const analysis = prepareReview(source, options || {}, policy, pseudonyms, limits);
    const findings = analysis.findings;
    const report = makeReport(source.length, analysis, policy, findings);
    let active = true;
    return Object.freeze({ findings: findings, report: report, policy: policy,
      apply: function (overrides) {
        if (!active) fail("REVIEW_CLEARED");
        const decided = applyOverrides(findings, overrides);
        return { sanitized: applyFindings(source, decided), findings: decided,
          report: makeReport(source.length, analysis, policy, decided) };
      },
      clear: function () { source = ""; active = false; if (release) release(); }
    });
  }

  function sessionLimits(config) {
    if (config === undefined) return LIMITS;
    if (!plainObject(config) || Object.keys(config).some(function (key) { return key !== "limits"; }) ||
      (config.limits !== undefined && config.limits !== "standard" && config.limits !== "large")) fail("INVALID_SESSION_OPTIONS");
    return config.limits === "large" ? LARGE_LIMITS : LIMITS;
  }

  function createSession(config) {
    const limits = sessionLimits(config);
    const pseudonyms = createPseudonyms();
    const reviews = new Set();
    return Object.freeze({
      limits: limits,
      createReview: function (input, options) {
        const review = buildReview(input, options, pseudonyms, function () { reviews.delete(review); }, limits);
        reviews.add(review);
        return review;
      },
      clear: function () {
        reviews.forEach(function (review) { review.clear(); });
        pseudonyms.clear();
      }
    });
  }

  function createReview(input, options) {
    const pseudonyms = createPseudonyms();
    return buildReview(input, options, pseudonyms, function () { pseudonyms.clear(); }, LIMITS);
  }

  function analyze(input, options) {
    const review = createReview(input, options);
    const analysis = { findings: review.findings, report: review.report };
    review.clear();
    return analysis;
  }

  function sanitize(input, options) {
    const source = checkInput(input);
    const review = createReview(source, options);
    const applied = review.apply();
    const matches = applied.findings.filter(function (finding) { return finding.action === "REDACT"; }).map(function (finding) {
      return { category: finding.category, text: source.slice(finding.start, finding.end), index: finding.start };
    });
    review.clear();
    return { original: source, sanitized: applied.sanitized, matches: matches,
      categories: Array.from(new Set(matches.map(function (match) { return match.category; }))).sort(),
      redactionCount: matches.length };
  }

  return {
    sanitize: sanitize,
    analyze: analyze,
    createReview: createReview,
    createSession: createSession,
    inspectDetectors: function () { return DETECTORS; },
    inspectPolicy: inspectPolicy,
    inspectPolicies: function () { return Object.freeze(PROFILE_NAMES.map(function (profile) { return inspectPolicy({ profile: profile }); })); },
    getCapabilities: function () { return Object.freeze(Object.assign({}, LIMITS,
      { formats: FORMATS, modes: MODES, profiles: PROFILE_NAMES, controls: CONTROLS, actions: Object.freeze(["REDACT", "KEEP"]),
        lockedCategories: LOCKED, maxOverrides: LIMITS.maxCandidates, largeLimits: LARGE_LIMITS })); },
    isValidIpv4: isValidIpv4,
    isLoopbackIpv4: isLoopbackIpv4,
    REDACTION_LABELS: REDACTION_LABELS
  };
});
