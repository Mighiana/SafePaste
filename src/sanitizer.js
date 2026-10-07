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
    PATH_OR_USERNAME: "[REDACTED_USERNAME]"
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
        pattern: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
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
        pattern: /((?:["']?)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{12,})(\2)/gi
      },
      {
        category: "SECRET",
        label: REDACTION_LABELS.SECRET,
        pattern: /((?:["']?)\bsecret\b(?:["']?)\s*[:=]\s*)(["']?)([^"'\s,;}{]{3,})(\2)/gi
      },
      {
        category: "PASSWORD",
        label: REDACTION_LABELS.PASSWORD,
        pattern: /((?:["']?)\b(?:password|passwd)\b(?:["']?)\s*[:=]\s*)(["']?)([^"'\s,;}{]{3,})(\2)/gi
      },
      {
        category: "EMAIL",
        label: REDACTION_LABELS.EMAIL,
        pattern: /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b/gi
      },
      {
        category: "USERNAME",
        label: REDACTION_LABELS.USERNAME,
        pattern: /((?:["']?)\b(?:username|user[_-]?name|user)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9][A-Za-z0-9._-]{2,63})(\2)(?=$|[\s,;}\]])/gi
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
        validator: isRedactableIpv4
      });
    }

    return rules;
  }

  const LIMITS = Object.freeze({ maxInputLength: 2097152, maxCandidates: 100000,
    maxJsonDepth: 64, maxFields: 50000 });
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
    ["IP_ADDRESS", "network", "review", "IPv4 address", "Validated IPv4 syntax; contextual policy required", 20]
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

  function fail(code) {
    const error = new Error("SafePaste: " + code);
    error.code = code;
    throw error;
  }

  function checkInput(input) {
    const source = String(input || "");
    if (source.length > LIMITS.maxInputLength) fail("INPUT_LIMIT");
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

  function parseJson(source) {
    let index = 0;
    const units = [];
    function whitespace() { while (/[\x20\t\r\n]/.test(source[index] || "X")) index += 1; }
    function add(unit, key, isKey) {
      if (units.length >= LIMITS.maxFields) fail("FIELD_LIMIT");
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
        if (depth >= LIMITS.maxJsonDepth) fail("DEPTH_LIMIT");
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

  function parseFields(source, format) {
    const units = [];
    const assignments = /(?:^|[\s,;])(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]{0,63})[ \t]*=[ \t]*/g;
    const headers = /(?:^|[\r\n])([A-Za-z][A-Za-z0-9_-]{0,63})[ \t]*:[ \t]*/g;
    function add(unit, key) {
      if (units.length >= LIMITS.maxFields) fail("FIELD_LIMIT");
      unit.key = key; units.push(unit);
    }
    function scan(pattern, header) {
      let match;
      while ((match = pattern.exec(source)) !== null) {
        const start = pattern.lastIndex;
        let unit;
        if (!header && (source[start] === '"' || source[start] === "'")) {
          try { unit = readQuoted(source, start, false); }
          catch (error) { if (error.code !== "FIELD_SYNTAX") throw error; continue; }
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
    let coveredEnd = -1;
    return units.filter(function (unit) {
      if (unit.start < coveredEnd) return false;
      coveredEnd = unit.end;
      return true;
    });
  }

  function parseInput(source, requested) {
    if (["auto", "text", "json", "env", "headers", "logfmt"].indexOf(requested) === -1) fail("UNKNOWN_FORMAT");
    let format = requested;
    if (format === "auto") {
      const trimmed = source.trimStart();
      if (/^[{[\"]/.test(trimmed)) format = "json";
      else {
        const lines = source.split(/\r\n|[\r\n]/).filter(function (line) { return line.trim() && !/^\s*#/.test(line); });
        if (lines.length && lines.every(function (line) { return /^(?:export[ \t]+)?[A-Za-z_][\w.-]{0,63}[ \t]*=[ \t]*(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'#]*)(?:[ \t]+#[^\r\n]*)?[ \t]*$/.test(line); })) format = "env";
        else if (lines.length && lines.every(function (line) { return /^[A-Za-z][\w-]{0,63}[ \t]*:/.test(line); })) format = "headers";
        else if (/(?:^|\s)[A-Za-z_][\w.-]{0,63}[ \t]*=/.test(source)) format = "logfmt";
        else format = "text";
      }
    }
    if (format === "json") {
      try { return { format: format, status: "parsed", units: parseJson(source) }; }
      catch (error) {
        if (error.code !== "JSON_SYNTAX") throw error;
        return { format: "text", status: "malformed-json-fallback", units: parseFields(source, "text") };
      }
    }
    return { format: format, status: format === "text" ? "text" : "parsed",
      units: requested === "text" ? [] : parseFields(source, format) };
  }

  function explicitCategory(key) {
    if (!key) return null;
    if (/^(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)$/i.test(key)) return "API_KEY";
    if (/^(?:password|passwd)$/i.test(key)) return "PASSWORD";
    if (/^secret$/i.test(key)) return "SECRET";
    if (/^(?:username|user[_-]?name|user)$/i.test(key)) return "USERNAME";
    if (/^authorization$/i.test(key)) return "AUTHORIZATION_HEADER";
    return null;
  }

  function diagnosticKey(key) {
    return /^(?:version|release|app[_-]?version|software[_-]?version|request[_-]?id|trace[_-]?id|build[_-]?id)$/i.test(key || "");
  }

  function collectParsed(source, options, parsed) {
    const units = parsed.units;
    function overlapsUnit(candidate) {
      let low = 0; let high = units.length;
      while (low < high) {
        const middle = Math.floor((low + high) / 2);
        if (units[middle].end <= candidate.start) low = middle + 1;
        else high = middle;
      }
      return low < units.length && units[low].start <= candidate.start && units[low].end >= candidate.end;
    }
    const candidates = parsed.format === "json" ? [] : collect(source, options).filter(function (candidate) { return !overlapsUnit(candidate); });
    units.forEach(function (unit) {
      function add(start, end, detector) {
        if (candidates.length >= LIMITS.maxCandidates) fail("FINDING_LIMIT");
        candidates.push({ start: unit.starts ? unit.starts[start] : unit.start + start,
          end: unit.ends ? unit.ends[end - 1] : unit.start + end, detector: detector,
          replacement: parsed.format === "json" && !unit.quoted ? JSON.stringify(detector.replacement) : detector.replacement });
      }
      const category = explicitCategory(unit.key);
      const minimum = category === "API_KEY" ? 12 : category === "AUTHORIZATION_HEADER" ? 8 : 3;
      const validIdentity = category !== "USERNAME" || /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(unit.value);
      if (category && validIdentity && unit.value.length >= minimum && !(parsed.format === "json" && unit.value === "null" && !unit.quoted)) {
        add(0, unit.value.length, BY_CATEGORY[category]);
      }
      collect(unit.value, options).forEach(function (candidate) {
        if (candidate.detector.category === "IP_ADDRESS" && diagnosticKey(unit.key)) return;
        add(candidate.start, candidate.end, candidate.detector);
      });
    });
    return candidates;
  }

  function collect(source, options) {
    const candidates = [];
    buildRules(options).forEach(function (rule) {
      let match;
      while ((match = rule.pattern.exec(source)) !== null) {
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
        candidates.push({ start: start, end: start + value.length, detector: BY_CATEGORY[rule.category] });
      }
    });
    return candidates;
  }

  function resolve(candidates) {
    candidates.sort(function (a, b) {
      return a.start - b.start || b.detector.priority - a.detector.priority || b.end - a.end;
    });
    const resolved = [];
    candidates.forEach(function (candidate) {
      const previous = resolved[resolved.length - 1];
      if (previous && candidate.start < previous.end) {
        previous.end = Math.max(previous.end, candidate.end);
        if (candidate.detector.priority > previous.detector.priority) {
          previous.detector = candidate.detector;
          previous.replacement = candidate.replacement;
        }
      } else {
        resolved.push({ start: candidate.start, end: candidate.end, detector: candidate.detector,
          replacement: candidate.replacement });
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

  function findingMetadata(candidates, starts) {
    return Object.freeze(candidates.map(function (candidate, index) {
      const detector = candidate.detector;
      return Object.freeze({ id: "finding-" + (index + 1), ruleId: detector.id,
        category: detector.category, control: detector.control, severity: detector.severity,
        reason: detector.reason, description: detector.description,
        certainty: detector.certainty, replacementPolicy: detector.replacementPolicy,
        start: candidate.start, end: candidate.end,
        position: position(starts, candidate.start), endPosition: position(starts, candidate.end),
        replacement: candidate.replacement || detector.replacement, action: "REDACT", allowKeep: detector.allowKeep });
    }));
  }

  function applyFindings(source, findings) {
    const pieces = [];
    let cursor = 0;
    findings.forEach(function (finding) {
      pieces.push(source.slice(cursor, finding.start), finding.replacement);
      cursor = finding.end;
    });
    pieces.push(source.slice(cursor));
    return pieces.join("");
  }

  function createReview(input, options) {
    let source = checkInput(input);
    const starts = lineStarts(source);
    const settings = options || {};
    const parsed = parseInput(source, settings.format || "auto");
    const findings = findingMetadata(resolve(collectParsed(source, settings, parsed)), starts);
    const report = Object.freeze({ engineVersion: 3, profile: "legacy", format: parsed.format, parseStatus: parsed.status,
      inputLength: source.length, inputLines: starts.length, totalFindings: findings.length,
      redacted: findings.length, kept: 0, findings: findings });
    let active = true;
    return Object.freeze({ findings: findings, report: report,
      apply: function () {
        if (!active) fail("REVIEW_CLEARED");
        return { sanitized: applyFindings(source, findings), findings: findings, report: report };
      },
      clear: function () { source = ""; active = false; }
    });
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
    const matches = applied.findings.map(function (finding) {
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
    inspectDetectors: function () { return DETECTORS; },
    getCapabilities: function () { return LIMITS; },
    isValidIpv4: isValidIpv4,
    isLoopbackIpv4: isLoopbackIpv4,
    REDACTION_LABELS: REDACTION_LABELS
  };
});
