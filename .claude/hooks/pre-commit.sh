#!/usr/bin/env sh
set -eu

# SafePaste pre-commit secret scan.
# This is a lightweight guard for obvious accidental credentials in production
# and harness files. It is not a comprehensive secret detection system and
# should be paired with review/tests.

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
PROJECT_DIR="$ROOT_DIR/SafePaste"

if [ ! -d "$PROJECT_DIR" ]; then
  exit 0
fi

if ! command -v git >/dev/null 2>&1; then
  echo "SafePaste pre-commit hook: git is required for staged secret scanning."
  exit 1
fi

PATTERN='(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|password[[:space:]]*[:=][[:space:]]*["'\'']?[^"'\'']{8,}|api[_-]?key[[:space:]]*[:=][[:space:]]*["'\'']?[A-Za-z0-9_./+=-]{16,})'
FOUND=0

set +e
git diff --cached --name-only --diff-filter=ACMR | while IFS= read -r file; do
  case "$file" in
    SafePaste/tests/*|SafePaste/evals/*|SafePaste/history/*|SafePaste/docs/*|SafePaste/RED_TEAM.md)
      continue
      ;;
    SafePaste/*)
      ;;
    *)
      continue
      ;;
  esac

  case "$file" in
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip)
      continue
      ;;
  esac

  if git grep --cached -I -n -E -e "$PATTERN" -- "$file"; then
    echo "SafePaste pre-commit hook: possible secret in $file"
    exit 9
  fi
done
SCAN_STATUS=$?
set -e

if [ "$SCAN_STATUS" -eq 9 ]; then
  FOUND=1
elif [ "$SCAN_STATUS" -ne 0 ]; then
  echo "SafePaste pre-commit hook: scan failed."
  exit "$SCAN_STATUS"
fi

if [ "$FOUND" -ne 0 ]; then
  echo "Commit blocked. Review the flagged values before committing."
  exit 1
fi

exit 0
