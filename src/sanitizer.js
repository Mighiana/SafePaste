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
        pattern: /\b(Authorization\s*:\s*)(?:(?:Bearer|Basic|Token)\s+)?[A-Za-z0-9._~+/=-]{8,}/gi,
        replacement: function (match, prefix) {
          return prefix + REDACTION_LABELS.AUTHORIZATION_HEADER;
        }
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
        pattern: /((?:["']?)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{12,})(\2)/gi,
        replacement: function (match, prefix, quoteStart, secret, quoteEnd) {
          return prefix + quoteStart + REDACTION_LABELS.API_KEY + quoteEnd;
        }
      },
      {
        category: "SECRET",
        label: REDACTION_LABELS.SECRET,
        pattern: /((?:["']?)\bsecret\b(?:["']?)\s*[:=]\s*)(["']?)([^"'\s,;}{]{3,})(\2)/gi,
        replacement: function (match, prefix, quoteStart, secret, quoteEnd) {
          return prefix + quoteStart + REDACTION_LABELS.SECRET + quoteEnd;
        }
      },
      {
        category: "PASSWORD",
        label: REDACTION_LABELS.PASSWORD,
        pattern: /((?:["']?)\b(?:password|passwd)\b(?:["']?)\s*[:=]\s*)(["']?)([^"'\s,;}{]{3,})(\2)/gi,
        replacement: function (match, prefix, quoteStart, secret, quoteEnd) {
          return prefix + quoteStart + REDACTION_LABELS.PASSWORD + quoteEnd;
        }
      },
      {
        category: "EMAIL",
        label: REDACTION_LABELS.EMAIL,
        pattern: /\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63}\b/gi
      },
      {
        category: "USERNAME",
        label: REDACTION_LABELS.USERNAME,
        pattern: /((?:["']?)\b(?:username|user[_-]?name|user)\b(?:["']?)\s*[:=]\s*)(["']?)([A-Za-z0-9][A-Za-z0-9._-]{2,63})(\2)(?=$|[\s,;}\]])/gi,
        candidate: function (args) {
          return args[3];
        },
        indexOffset: function (args) {
          return args[1].length + args[2].length;
        },
        replacement: function (match, prefix, quoteStart, username, quoteEnd) {
          return prefix + quoteStart + REDACTION_LABELS.USERNAME + quoteEnd;
        }
      },
      {
        category: "PATH_OR_USERNAME",
        label: REDACTION_LABELS.PATH_OR_USERNAME,
        pattern: /(^|[^A-Za-z0-9/\\._-])((?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)([A-Za-z0-9._-]+)([^\s"'<>]*))/g,
        candidate: function (args) {
          return args[2];
        },
        indexOffset: function (args) {
          return args[1].length;
        },
        replacement: function (match, prefix, pathValue) {
          if (pathValue.indexOf("\\") !== -1) {
            return prefix + pathValue.replace(/^([A-Za-z]:\\Users\\)[A-Za-z0-9._-]+/, "$1" + REDACTION_LABELS.USERNAME);
          }
          return prefix + pathValue.replace(/^((?:\/home\/|\/Users\/))[A-Za-z0-9._-]+/, "$1" + REDACTION_LABELS.USERNAME);
        }
      }
    ];

    if (redactIpAddresses) {
      rules.push({
        category: "IP_ADDRESS",
        label: REDACTION_LABELS.IP_ADDRESS,
        pattern: /(^|[^A-Za-z0-9_.-])((?:\d{1,3}\.){3}\d{1,3})(?=$|[^A-Za-z0-9_.-]|\.(?=$|[\s"')\]}]))/g,
        candidate: function (args) {
          return args[2];
        },
        indexOffset: function (args) {
          return args[1].length;
        },
        validator: isRedactableIpv4,
        replacement: function (match, prefix) {
          return prefix + REDACTION_LABELS.IP_ADDRESS;
        }
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
        if (candidate.detector.priority > previous.detector.priority) previous.detector = candidate.detector;
      } else {
        resolved.push({ start: candidate.start, end: candidate.end, detector: candidate.detector });
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
        replacement: detector.replacement, action: "REDACT", allowKeep: detector.allowKeep });
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
    const findings = findingMetadata(resolve(collect(source, options || {})), starts);
    const report = Object.freeze({ engineVersion: 2, profile: "legacy", format: "text",
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
