#!/bin/sh
# Scans one built release binary for known Go vulnerabilities before anything
# is published (spec §4.2). GoReleaser runs it as each build's post hook
# (.goreleaser.yaml), so it reads the exact binary that goes into the archive
# and the packages -- stripped, cross-compiled, built by the toolchain the
# release used -- and a finding fails the hook, which fails the release.
#
# assay's QA 2026-10-30: a release shipped with GO-2026-6809 reachable. A
# source scan on a developer's machine judges that machine's toolchain, not
# the release's; this judges the deliverable.
#
# An advisory with no fixed version blocks the release until the toolchain
# (go.mod's toolchain line) or the dependency moves, or until a reviewed
# exception is written here, in this file, with its reason.
#
# govulncheck is pinned, and exits nonzero on any finding it can place. The
# same version runs CI's source scan (.github/workflows/ci.yml).
#
#   sh scripts/release-vulncheck.sh dist/muster_linux_amd64_v1/muster
set -eu
[ "$#" -eq 1 ] || { echo "usage: sh scripts/release-vulncheck.sh <binary>" >&2; exit 2; }
GOVULNCHECK_VERSION=v1.9.0
echo "govulncheck $GOVULNCHECK_VERSION: $1"
go run "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}" -mode=binary "$1"
