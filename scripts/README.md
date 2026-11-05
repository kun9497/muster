# scripts

The release pipeline's shell scripts, each named in the stage-4 spec §4
(`docs/superpowers/specs/2026-11-02-stage4-public-release-design.md`).
`check-go-toolchain.sh [--exact] [path/to/go.mod]` holds a build to `go.mod`'s
`toolchain` line: CI runs it as a floor and the release runs it with `--exact`
(§4.2 RL-4). `release-vulncheck.sh <binary>` scans each built binary with
govulncheck pinned by version, as GoReleaser's post-build hook (§4.2);
`reproduce.sh --ref <git ref> --version <string> [--arch amd64|arm64]
<artefact>` rebuilds the ref in a temporary worktree under the toolchain its
`go.mod` names and compares the binary's sha256 with the one inside a release
`.tar.gz`, `.deb` or `.rpm`, or a bare binary (§4.3; `--print-date --ref <ref>`
prints the `-X main.date` value it would use);
`release-notes.sh vX.Y.Z` extracts a version's `CHANGELOG.md` section as the
release notes (§4.8 RL-14). All are POSIX `sh`, shellcheck-clean, and checked
by `make shellcheck` and CI's shellcheck step, as are the scripts under
`ci/release/`: the Debian package's `postrm` (§4.6 RL-13), the install
contract `contract.sh` and `expected-exit.sh` the CI matrix runs inside each
image (§4.7), and `ops-alert.sh`, which opens, updates or closes the pinned
issue the release workflow's `alert` job keeps (§4.10). `sort -V`, which the
toolchain check relies on, is a GNU and busybox extension.
