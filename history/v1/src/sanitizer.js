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
    PASSWORD: "[REDACTED_PASSWORD]",
    EMAIL: "[REDACTED_EMAIL]",
    IP_ADDRESS: "[REDACTED_IP_ADDRESS]",
    PATH_OR_USERNAME: "[REDACTED_PATH]"
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

  function buildRules(options) {
    const redactIpAddresses = options.redactIpAddresses !== false;

    const rules = [
      {
        category: "AUTHORIZATION_HEADER",
        label: REDACTION_LABELS.AUTHORIZATION_HEADER,
        pattern: /\b(Authorization\s*:\s*)(?:Bearer\s+)?[A-Za-z0-9._~+/=-]{12,}/gi,
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
        pattern: /(\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|client[_-]?secret)\b\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{12,})(\2)/gi,
        replacement: function (match, prefix, quoteStart, secret, quoteEnd) {
          return prefix + quoteStart + REDACTION_LABELS.API_KEY + quoteEnd;
        }
      },
      {
        category: "PASSWORD",
        label: REDACTION_LABELS.PASSWORD,
        pattern: /(\b(?:password|passwd|pwd)\b\s*[:=]\s*)(["']?)([^"'\s,;}{]{3,})(\2)/gi,
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
        category: "PATH_OR_USERNAME",
        label: REDACTION_LABELS.PATH_OR_USERNAME,
        pattern: /\b(?:[A-Za-z]:\\Users\\|\/home\/|\/Users\/)([A-Za-z0-9._-]+)([^\s"'<>]*)/g,
        replacement: function () {
          const match = arguments[0];
          if (match.indexOf("\\") !== -1) {
            return match.replace(/^(?:[A-Za-z]:\\Users\\)[A-Za-z0-9._-]+/, "C:\\Users\\[REDACTED_USER]");
          }
          return match.replace(/^((?:\/home\/|\/Users\/))[A-Za-z0-9._-]+/, "$1[REDACTED_USER]");
        }
      }
    ];

    if (redactIpAddresses) {
      rules.push({
        category: "IP_ADDRESS",
        label: REDACTION_LABELS.IP_ADDRESS,
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        validator: isValidIpv4
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

        if (rule.validator && !rule.validator(match)) {
          return match;
        }

        matches.push({
          category: rule.category,
          text: match,
          index: offset
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
    REDACTION_LABELS: REDACTION_LABELS
  };
});
