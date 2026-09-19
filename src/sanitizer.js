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
    const beforeCandidate = source.slice(0, candidateIndex);
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
        pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
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

  function sanitize(input, options) {
    const source = String(input || "");
    const matches = [];
    let sanitized = source;

    buildRules(options || {}).forEach(function (rule) {
      sanitized = sanitized.replace(rule.pattern, function () {
        const args = Array.prototype.slice.call(arguments);
        const match = args[0];
        const offset = args[args.length - 2];
        const fullText = args[args.length - 1];
        const candidate = rule.candidate ? rule.candidate(args) : match;
        const indexOffset = rule.indexOffset ? rule.indexOffset(args) : 0;
        const candidateIndex = offset + indexOffset;

        if (rule.validator && !rule.validator(candidate, {
          source: fullText,
          index: candidateIndex,
          match: match
        })) {
          return match;
        }

        matches.push({
          category: rule.category,
          text: candidate,
          index: candidateIndex
        });

        if (rule.replacement) {
          return rule.replacement.apply(null, args);
        }

        return rule.label;
      });
    });

    const categories = Array.from(new Set(matches.map(function (match) {
      return match.category;
    }))).sort();

    return {
      original: source,
      sanitized: sanitized,
      matches: matches,
      categories: categories,
      redactionCount: matches.length
    };
  }

  return {
    sanitize: sanitize,
    isValidIpv4: isValidIpv4,
    isLoopbackIpv4: isLoopbackIpv4,
    REDACTION_LABELS: REDACTION_LABELS
  };
});
