#!/bin/sh
# release-notes.sh vX.Y.Z [CHANGELOG.md]: print the version's CHANGELOG
# section as the release notes (spec §4.8 RL-14).
#
# Prints the body of the `## [X.Y.Z] - YYYY-MM-DD` heading (Keep a
# Changelog): every line from the one after the heading to the one before the
# next `## ` heading, or to the end of the file. The release job writes it to
# a file and passes it to `goreleaser release --release-notes` (§4.10).
#
# Exit 1 when the file has no section for the version, the heading's date is
# not YYYY-MM-DD, the section is empty, or the version is not X.Y.Z[-pre]:
# `[Unreleased]` is never a release, so a tag cut before the changelog commit
# fails here and publishes nothing. Exit 2 on a usage error.
set -eu
usage() {
  echo "usage: sh scripts/release-notes.sh vX.Y.Z [CHANGELOG.md]" >&2
  exit 2
}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
case "$1" in
  v*) ;;
  *) usage ;;
esac
ver=${1#v}
file=${2:-CHANGELOG.md}
if ! printf '%s\n' "$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
  echo "error: $ver is not a release version (X.Y.Z); [Unreleased] is never a release" >&2
  exit 1
fi
if [ ! -f "$file" ] || [ ! -r "$file" ]; then
  echo "error: $file is not a readable file" >&2
  exit 1
fi
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
rc=0
# Exit 3: the heading's date is malformed; exit 4: no heading. index() is a
# literal match, so the version's dots match only dots.
awk -v h="## [$ver]" '
  found && /^## / { exit }
  found { print; next }
  index($0, h) == 1 {
    rest = substr($0, length(h) + 1)
    if (rest !~ /^ - [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) { bad = 1; exit }
    found = 1
    next
  }
  END {
    if (bad) exit 3
    if (!found) exit 4
  }
' "$file" > "$tmp" || rc=$?
case "$rc" in
  0) ;;
  3)
    echo "error: $file's heading for $ver is not '## [$ver] - YYYY-MM-DD'" >&2
    exit 1
    ;;
  4)
    echo "error: $file has no section for $ver" >&2
    exit 1
    ;;
  *)
    echo "error: awk failed reading $file (exit $rc)" >&2
    exit 1
    ;;
esac
if ! grep -q '[^[:space:]]' "$tmp"; then
  echo "error: $file's section for $ver is empty" >&2
  exit 1
fi
cat "$tmp"
