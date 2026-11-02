#!/bin/sh
# check-go-toolchain.sh [--exact] [path/to/go.mod]: fail unless the Go
# toolchain in use meets go.mod's toolchain line (spec §4.2 RL-4).
#
# Reads the go.mod given by path (default ./go.mod); runs `go env GOVERSION`
# where it is invoked, so the toolchain judged is the one a build started
# from that directory would use. Without --exact the line is a floor (CI: a
# newer patch passes); with --exact the toolchain must equal it (the release).
#
# Why: assay v0.12.0 was built with go1.26.9 because setup-go's go-version
# "1.26" took whatever patch the runner cache held, and go1.26.9 carries
# GO-2026-6809 (crypto/x509, fixed in go1.26.10). go.mod's toolchain line is
# raised when a stdlib advisory names a fix; this checks the toolchain a
# build actually used against it, so a runner that pins GOTOOLCHAIN=local to
# an older Go fails here instead of shipping.
set -eu
exact=
if [ "${1:-}" = --exact ]; then
  exact=1
  shift
fi
case "${1:-}" in
  -*) echo "usage: sh scripts/check-go-toolchain.sh [--exact] [path/to/go.mod]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: sh scripts/check-go-toolchain.sh [--exact] [path/to/go.mod]" >&2
  exit 2
fi
mod=${1:-go.mod}
if [ ! -f "$mod" ] || [ ! -r "$mod" ]; then
  echo "error: $mod is not a readable file" >&2
  exit 1
fi
want=$(sed -n 's/^toolchain go\([^[:space:]]*\).*/\1/p' "$mod" | head -n 1)
if [ -z "$want" ]; then
  echo "error: $mod names no toolchain line to hold the build to" >&2
  exit 1
fi
gov=$(go env GOVERSION) || {
  echo "error: go env GOVERSION failed" >&2
  exit 1
}
# GOVERSION can carry a GOEXPERIMENT suffix ("go1.26.10 X:boringcrypto").
have=$(printf '%s\n' "$gov" | sed 's/^go//; s/[ -].*//')
if [ -z "$have" ]; then
  echo "error: go env GOVERSION gave no version ($gov)" >&2
  exit 1
fi
if [ -n "$exact" ]; then
  if [ "$have" != "$want" ]; then
    echo "error: Go $have is not go$want (--exact)" >&2
    exit 1
  fi
  echo "Go $have is go$want ($mod)"
  exit 0
fi
sort -V </dev/null >/dev/null 2>&1 || {
  echo "error: sort -V is not available" >&2
  exit 1
}
lowest=$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -n 1)
if [ "$lowest" != "$want" ]; then
  echo "error: Go $have is older than go$want, the toolchain $mod requires" >&2
  exit 1
fi
echo "Go $have meets go$want ($mod)"
