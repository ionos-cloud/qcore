#!/bin/sh
# Extract the CHANGELOG.md section for a given version and print it to stdout.
#
# Usage: extract-changelog.sh <version> [changelog-path]
#
# Matches a heading like "## [1.2.3] - 2024-01-01" or "## 1.2.3" and prints
# everything up to (but not including) the next "## " heading, with the heading
# line itself and surrounding blank lines trimmed. Exits non-zero if the
# version has no section, so callers can fall back to auto-generated notes.
set -eu

version="${1:?usage: extract-changelog.sh <version> [changelog-path]}"
changelog="${2:-CHANGELOG.md}"

awk -v ver="$version" '
    # Start of the section for the requested version.
    !in_section && /^## / {
        line = $0
        # Strip the "## " prefix and any surrounding [ ] around the version.
        sub(/^## +/, "", line)
        gsub(/[][]/, "", line)
        # Take the first whitespace-separated token as the version.
        n = split(line, parts, /[ \t]+/)
        if (parts[1] == ver) { in_section = 1; next }
    }
    # A new "## " heading ends the section.
    in_section && /^## / { exit }
    in_section { print }
' "$changelog" |
    # Trim leading and trailing blank lines.
    sed -e '/./,$!d' | tac | sed -e '/./,$!d' | tac
