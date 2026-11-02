# scripts

The release pipeline's shell scripts, each named in the stage-4 spec §4
(`docs/superpowers/specs/2026-11-02-stage4-public-release-design.md`).
`check-go-toolchain.sh [--exact] [path/to/go.mod]` holds a build to `go.mod`'s
`toolchain` line: CI runs it as a floor and the release runs it with `--exact`
(§4.2 RL-4). `release-vulncheck.sh` scans each built binary with govulncheck
pinned by version (§4.2); `reproduce.sh <tag> [<archive>]` rebuilds a tag in a
temporary worktree and compares the bytes with the published archive (§4.3);
`release-notes.sh vX.Y.Z` extracts a version's `CHANGELOG.md` section as the
release notes (§4.8 RL-14). All are POSIX `sh`, shellcheck-clean, and checked
by `make shellcheck` and CI's shellcheck step.
