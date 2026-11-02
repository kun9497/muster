# Stage 4 — Public release

Korean pair: `2026-11-02-stage4-public-release-design.ko.md`. Main design: `2026-09-02-muster-design.md` (§5.9 the
snapshot lifecycle, §7 exit codes, §8 `:428` release integrity, §9 output, §10.2 the stage-4 paragraph, §10.3 the
deferred list, D13, D16, D28). Rulings of this design are the RL list (single letters collide with earlier stages).
The brainstorm that produced it is summarised in §1.1; the choices the brainstorm left to the author are marked
"author's call" where they appear, and collected in §10.

**Date** 2026-11-02 · **Status** approved by the user on 2026-11-02; 4A executed (its rulings RA-1..RA-44 are in the plan's Execution notes and folded here where they correct a sentence).

## 1. Scope and intent

Stage 4 turns muster from a repository one builds into a release one installs. The person it serves is a Linux
operator on a company security team. They open the GitHub Releases page, download the package for their
distribution, verify it, install it, run `sudo muster collect` once and `muster check` once, and a month later
want to know what changed on that server since. Nothing in this stage is for anyone else: no central tool consumes
the output, and no outside contributor is being recruited yet.

Stage 4 is three slices, one plan each, in this order:

- **4A — the release pipeline and the packages** (§4): a tag push builds, scans, signs, attests and publishes
  Linux binaries, `.deb` and `.rpm` packages, checksums and SBOMs; the packages install the binary and the
  documents and start nothing; `snapshot ls|rm|prune` close the lifecycle D13 promised.
- **4B — `snapshot diff`** (§5): the two newest snapshots of the host, or two named files, evaluated by the
  installed control set; verdicts that changed, fact changes on request.
- **4C — operator documents and release gates** (§6): the README pair rewritten for the operator (verification
  before installation), the threat model's supply-chain section, a document drift check between the English and
  Korean pairs, a reproducibility check, and `RELEASING.md`.

The first public release is `v0.1.0`; the binary stays at `0.x` until the operator feedback the release is cut to
collect has been read (RL-1). The control set keeps its own version (`controls/VERSION`, D16).

### 1.1 What the brainstorm settled

These are the user's decisions, in their words where they gave them:

- The operator downloads from GitHub Releases and installs a package, "like assay" — but the design's own
  release-integrity list (§8 `:428`) is the requirement, and assay's pipeline is the starting point where it
  meets it (§4.1).
- `.deb` and `.rpm` are in the first release, beside the tar.gz.
- Signing is keyless (Sigstore / OIDC), not with a project key as assay does.
- After `apt install`, "only the binary is installed and nothing runs automatically".
- A month later the operator wants "what changed compared with the last result": verdicts that changed by
  default, fact changes as an option; the previous snapshot is picked automatically, and a file can be named.
- Results stay on the server; there is no central tool. SARIF is deferred (§9).
- `--controls-dir` is deferred on the author's recommendation (§9).
- The release is for operators to download and use; contributor-facing items (DCO, a PR template, the Lynis
  differential) are deferred.
- The first version is `v0.x`.

## 2. Goals, non-goals, anti-goals

**Goals.** An operator can (1) verify a downloaded file against the repository and the tag before running it as
root, with two independent methods and commands copied from the README; (2) install it as a package on Ubuntu
22.04/24.04, Debian 12 and the RHEL 9 family, or from a tar.gz anywhere else, with nothing started and nothing
changed on the host; (3) rebuild the binary from the tag and get the same bytes; (4) see which verdicts changed
between two snapshots of the same host with the facts behind each change; (5) list and prune the snapshots muster
keeps; (6) read the operator documents — the README and `RELEASING.md` pairs — in English or Korean and get the same
facts (RL-38: `THREAT_MODEL.md`, `SECURITY.md`, `ATTRIBUTION.md` and `CHANGELOG.md` stay English-only, as
CONTRIBUTING says today; `README.ko.md` carries a Korean summary of what the verification proves and does not).

**Non-goals.** No installer script, no `curl | sh`, no auto-update, no update check, no telemetry. No macOS or
Windows build (a check-only build for them stays in §10.3 of the main design). No upload of results anywhere. No
change to any verdict, fact, exit code or output of `collect`, `check` or `fix`: a 4A/4B/4C change that moves an
example report is a defect (the examples gate holds).

**Anti-goals** — the release is a failure even if every job is green when:

1. **Installing or running it changes the server.** A package script that enables a unit, creates a user, writes a
   configuration file or starts a process; a subcommand that changes a setting. muster's first promise (§8) is that
   `collect` writes one file and nothing else is written; the package keeps the same promise.
2. **A downloaded file cannot be verified**, or the README's verification commands fail on a published release.
3. **The same source gives different bytes.** If `scripts/reproduce.sh --ref v0.1.0 --version 0.1.0 <archive>` does not reproduce the published
   binary, "reproducible build" is a false claim and is removed from the README until it is true.
4. **`snapshot diff` reports a muster upgrade as a server change.** The operator must never be sent to fix a host
   because the rules moved (§5.4).
5. **A published snapshot or report carries a secret.** The redaction policy (§5.6 of the main design) and the
   anonymiser (3D-3) are re-proven on the release artefacts before the tag (§6.5).
6. **The English and Korean documents say different things.** The drift check (§6.3) is a release gate.

## 3. Constraints

- Everything in CLAUDE.md's "Rules that are contracts": exit codes, determinism, JSON on stdout and nothing else,
  strict YAML, no KISA or CIS text, fixtures from public images. English canonical with the `.ko.md` pair in the
  same commit; the main design pair stays line-aligned.
- `internal/report`, `internal/check` and the new `internal/diff` are pure (no `os`, `os/exec`, `net`, `syscall`,
  `time`); a test enforces it as for `internal/profile` and `internal/anonymize`.
- Standard library plus the two existing modules (`yaml.v3`, `x/sys`) in the binary (D28). Release tooling
  (GoReleaser, cosign, syft, govulncheck, nfpm through GoReleaser) runs in CI only and is pinned by version and,
  for GitHub Actions, by commit SHA.
- Never a dotted RFC1918 or public IPv4 literal, or a hostname ending `.corp/.internal/.intra/.lan/.local/.priv`, in
  a committed file (gitleaks scans the PR range).
- No history rewrite; a tag is never moved (RL-6).
- The lab host is read-only for this stage; package installation is proven in CI containers and on the runner VM,
  never on the lab.

## 4. 4A — the release pipeline and the packages

### 4.1 What comes from assay and what does not

assay's `release.yml` and `.goreleaser.yaml` (read on 2026-11-02 at assay 030da65) are the starting point. Taken
as they are: the `v*` tag trigger; GoReleaser v2 pinned by commit; `CGO_ENABLED=0`, `-trimpath`, `-s -w` and the
three `-X main.version/commit/date` variables (muster's Makefile already sets the same three); no `go mod tidy` at
release time (the release builds the `go.sum` CI tested); a toolchain check that refuses a build below the Go
version `go.mod` names (assay's v0.12.0 shipped with GO-2026-6809 because `go-version: "1.26"` took the runner's
older patch); a `govulncheck -mode=binary` post-build hook on every binary, pinned, that stops the release before
anything is published; a `checksums.txt`; `actions/attest-build-provenance` over the published files; a job that
opens or closes one pinned issue when the release job fails or recovers.

Changed: signing is keyless (§4.5), where assay signs with a project key off the transparency log because the same
key signs its database artefact; the targets are `linux/amd64` and `linux/arm64` only (RL-2: `collect` is Linux-only
and the check-only builds for other systems are deferred); the README install one-liner, `install.sh`, `install.ps1`
and the step that commits a README pin to `main` are not taken — the main design forbids `curl | sh`, and a release
job never pushes to `main` (RL-3).

Added, because assay has neither: SBOMs (§4.4), the `.deb` and `.rpm` packages (§4.6), a reproducibility check
(§4.3), release notes from `CHANGELOG.md` (§4.8), and the lifecycle commands (§4.9).

### 4.2 The build

- **RL-4 — one toolchain, named in `go.mod`.** `go.mod` keeps `go 1.25` as the language version and gains a `toolchain goX.Y.Z` line naming the newest patch of a supported Go line (go1.26.10 at 4A; RA-17 — 1.25 receives no more fixes, so "raise it on an advisory" needs a line that still moves; the version CI pins today
  is 1.25.5; the plan raises it to the latest 1.25 patch at the time). `release.yml` and `ci.yml` set up Go with
  `go-version-file: go.mod` and run `scripts/check-go-toolchain.sh`: in CI the line is a floor (a newer patch passes);
  in the release job it must be equal (`--exact`), because a different patch gives different bytes and §4.3 would fail.
  Raising the line is a normal commit; a stdlib advisory with a fix raises it before the next tag.
- **RL-5 — the build is reproducible by construction.** GoReleaser's build sets `mod_timestamp:
  '{{ .CommitTimestamp }}'`, `-X main.date={{ .CommitDate }}` (the commit's date, not the build's — `muster version`
  therefore prints when the source was committed, and the Makefile's `DATE` moves to `TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ` — the one spelling equal to `{{ .CommitDate }}`; `%cI` prints the committer's offset and plain `format:` renders it with a false `Z` (RA-1) — so
  `make build` agrees), `-X main.version={{ .Version }}` (the tag without `v`) and `-X main.commit={{ .FullCommit }}`
  (the Makefile's short hash becomes the full one; `muster version` prints both forms as before). `-buildvcs=false`
  is set so the binary carries no VCS stamp beyond those variables. Archives and packages set
  `SOURCE_DATE_EPOCH` from the commit timestamp.
- Builds: `id: muster`, `main: ./cmd/muster`, `goos: [linux]`, `goarch: [amd64, arm64]`. The post hook runs
  `scripts/release-vulncheck.sh "{{ .Path }}"` (govulncheck pinned by version; an advisory the toolchain cannot fix
  yet blocks the release until the maintainer raises the toolchain or records a reviewed exception in the script —
  never by unpinning).
- `ci.yml` gains `govulncheck ./...` in source mode on every PR (the same pinned version). Source mode on a PR and
  binary mode on the release are the two layers; neither replaces the other.

### 4.3 Reproducibility

`scripts/reproduce.sh --ref <tag> --version <X.Y.Z> [--arch amd64|arm64] <artefact>` (RA-22, RA-25: the artefact is a tar.gz, a `.deb`, an `.rpm` or a bare binary; `--version` is the verbatim release string) checks out the ref in a temporary detached worktree, selects the toolchain `go.mod` names through `GOTOOLCHAIN`, verifies it equals
the `go.mod` line, builds with the exact flags of §4.2 for the host's architecture (or `GOARCH` given), and prints
the binary's sha256 beside the one inside the downloaded archive or package, exiting 0 only when they match. The
same script runs in CI's `release-dry-run` job (§4.7) against GoReleaser's own snapshot build, so a change that
breaks reproducibility fails the PR, not the tag. The README's "Reproduce the build" section is this script's
usage and nothing more (RL-7: the claim in the README is exactly what the script proves).

### 4.4 Artefacts of a release

For tag `vX.Y.Z` the GitHub Release carries, and nothing else:

| File | Content |
|---|---|
| `muster_X.Y.Z_linux_<arch>.tar.gz` | `muster`, `LICENSE`, `NOTICE`, `ATTRIBUTION.md`, `README.md`, `README.ko.md`, `THREAT_MODEL.md`, `SECURITY.md`, `CHANGELOG.md`, `examples/systemd/` (§4.6) |
| `muster_X.Y.Z-1_<amd64|arm64>.deb`, `muster-X.Y.Z-1.<x86_64|aarch64>.rpm` (nfpm's conventional names, RA-19) | §4.6 |
| `muster_X.Y.Z_checksums.txt` | sha256 of every file above |
| `muster_X.Y.Z_checksums.txt.sigstore.json` | the keyless signature bundle over the checksums file (§4.5) |
| `muster_X.Y.Z_linux_<arch>.tar.gz.spdx.json`, one per `.deb`/`.rpm` | SBOM, SPDX JSON, by syft pinned (RL-8) |
| release notes | the `CHANGELOG.md` section of this version (§4.8) |

Build provenance (`actions/attest-build-provenance`) is attached to every archive and package and lives in the
repository's attestation store, not as a release file. `NOTICE` and `ATTRIBUTION.md` travel in every archive and
package because the ComplianceAsCode-derived CIS index is BSD-3-Clause and the CIS disclaimer must reach the user
(CB-13).

### 4.5 Signing and attestation

- **RL-9 — keyless, Sigstore bundle.** `cosign sign-blob --new-bundle-format --bundle <checksums>.sigstore.json <checksums>` (RA-18: on the cosign v2.4 line `--bundle` alone writes cosign's legacy JSON; the flag writes the Sigstore bundle that cosign v3, `gh` and sigstore-go read) under the
  job's OIDC token (`id-token: write`), cosign pinned to the v2.4 line as assay pins it. The signing identity is the
  workflow at the tag: `https://github.com/kun9497/muster/.github/workflows/release.yml@refs/tags/vX.Y.Z`, issuer
  `https://token.actions.githubusercontent.com`. The entry is in the public transparency log; the repository is
  public, so the log says nothing the Releases page does not.
- **RL-10 — the attestation is SLSA Build L2, said as such.** `gh attestation verify <file> -R kun9497/muster`
  proves GitHub-hosted Actions built the file from this repository at this tag. The README says L2 and says what
  it does not prove: that the source at the tag is safe, or that the reviewer read it.
- Either method alone is sufficient and the README says so; both are given because one needs `gh` and the other
  `cosign`, and an air-gapped host may have neither — for that host the README gives the sha256 route and names
  it the weakest (it proves only that the download matches the checksums file, whose own trust is the signature).

### 4.6 The packages

- **RL-11 — the package installs the binary and the documents, and starts nothing.** nfpm through GoReleaser,
  package `muster`, `.deb` for amd64/arm64 and `.rpm` for x86_64/aarch64, licence Apache-2.0, no dependencies
  (static binary), `Section: admin` / `Group: Applications/System`. Contents: `/usr/bin/muster` (0755);
  `/usr/share/doc/muster/` with the documents of §4.4; `/usr/share/doc/muster/examples/systemd/muster-collect.service`
  and `muster-collect.timer` (RL-12); the licence at the distribution's conventional place
  (`/usr/share/doc/muster/copyright` on Debian). Nothing under `/etc`, `/var`, `/usr/lib/systemd`.
- **RL-12 — example units live in the documentation directory, not on the unit search path.** The user's words were
  "only the binary, nothing runs"; a unit file under `/usr/lib/systemd/system/` is inert on the RHEL family and on
  Debian without a maintainer script, but a future preset or packaging change could enable it, and a file under
  `examples/` cannot be enabled by accident. The README shows the two commands that install and enable them
  (`install -m 0644 … /etc/systemd/system/`, `systemctl enable --now muster-collect.timer`). The service runs
  `/usr/bin/muster collect` weekly with `--out` defaulted; the author's call is weekly (`OnCalendar=weekly`,
  `Persistent=true`), because a month is the horizon the operator named and a week gives four points inside it.
  The unit runs `collect` without `--deep`, the same command the README's first run gives, so the weekly snapshots
  compare whole (§5.4); an operator who wants the walk edits the unit and then every snapshot is deep.
- **RL-13 — maintainer scripts.** No `preinst`, `postinst` or `prerm`. `postrm` on Debian (RA-27, RA-40): on `purge` only — a symlinked `/var/lib/muster` loses the link; a `/var/lib/muster` that is a mount point (device differs from `/var/lib`'s; a bind mount of the same filesystem is not detected) is left to the operator with a note on stderr; otherwise `rm -rf --one-file-system` removes it — and the purge never fails on this script. Otherwise, remove
  `/var/lib/muster` (snapshots, the lock, `latest`) and nothing else; on `remove` leave it. rpm has no purge: `%postun`
  does nothing, erase leaves `/var/lib/muster`, and the README says how to remove it by hand. A package script never
  calls `systemctl`, never creates a user or a directory (`collect` creates `/var/lib/muster` itself, 0700, D13).
  Upgrade is install over install: no script, snapshots stay, and the new `controls_version` shows in the next
  check and diff.
- Package metadata: `Maintainer`/`Packager` is the commit identity `.mailmap` and `NOTICE` use,
  `seonggyun.seo <40746364+kun9497@users.noreply.github.com>` (RL-39; the user's choice of the recommended form),
  `Homepage` the repository, `Description`/`Summary` the README's two opening sentences (RA-41). The `.deb` carries `Priority: optional`; the
  `.rpm` `Release: 1`. The install contract (§4.7) asserts these fields.

### 4.7 CI proves the package on every PR

A new `release-dry-run` job in `ci.yml`: `goreleaser release --snapshot --clean --skip=publish,sign` builds every
artefact of §4.4 (the attestation and signing steps need the tag and are skipped), then:

- `scripts/reproduce.sh` against the amd64 snapshot binary (§4.3);
- `scripts/release-vulncheck.sh` ran as the post hook (the dry run fails on a finding, as the release would);
- an **install contract** matrix over `ubuntu:22.04`, `ubuntu:24.04`, `debian:12` (`.deb`), `rockylinux/rockylinux:9`,
  `almalinux:9` (`.rpm`): install the package, assert the installed file list equals §4.6 exactly (`dpkg -L` /
  `rpm -ql` against the committed lists `ci/release/contract-files.deb.txt` and `.rpm.txt` — two, because dpkg and rpm print different rows: dpkg no `/.`, rpm no directories at all (RA-34); compared by string equality since the EL images lack `diff`), assert no unit was enabled
  (`systemctl list-unit-files 'muster*'` empty or the container has no systemd), assert no muster process ran and
  `/var/lib/muster` does not exist, run `muster version` and compare its five lines (line 1 is `muster <version>` verbatim; the package's own `Version` field is nfpm's `X.Y.Z-1` form, `~` for a `-` in a snapshot version) and the metadata fields (`Maintainer`/`Packager`, `Homepage`/`URL`, section/group, priority/release, RA-23),
  run `muster check --facts <example snapshot>` and compare its exit code with the example's, upgrade over itself,
  remove and assert a seeded `/var/lib/muster` survives, purge (Debian) and assert it is gone;
- the tar.gz: extract, same `muster version` and `check` assertions;
- **the README's install blocks run** (RL-28): the fenced blocks of the README's Install section are executable
  templates — `vX.Y.Z`, the architecture and the signing identity are the only placeholders — and the dry run
  executes them against the snapshot build with the placeholders substituted: the sha256 route and the package
  installs on every PR; the `gh attestation verify` and `cosign verify-blob` commands on `push` to `main` only,
  where the job has an OIDC token and attests and signs the snapshot build under `ci.yml`'s identity (a fork's
  pull request has no token). A README command that cannot run is a red PR, not a red release.

The job runs on `pull_request` and `push` to `main` and is a required check. It is the only place the release
pipeline is exercised before a tag, so the plan writes it in the same task as `.goreleaser.yaml`.

### 4.8 Release notes, changelog, versions

- **RL-14 — release notes are the `CHANGELOG.md` section.** `scripts/release-notes.sh vX.Y.Z` extracts the
  `## [X.Y.Z] - YYYY-MM-DD` section (Keep a Changelog) to a file GoReleaser publishes as the notes
  (`release.header`/`--release-notes`); GoReleaser's own commit-derived changelog is disabled. The job fails when the
  section is missing or still reads `[Unreleased]`, so cutting a release starts with the changelog commit. The
  `Controls` paragraph D16 requires stays where it is. The `[0.1.0]` section is a fresh, operator-facing page —
  what the release does, how to verify and install it, its limits, then the `Controls` paragraph — and the
  accumulated stage history that is `[Unreleased]` today moves whole under a `## History before 0.1.0` heading
  that stays in the file (RL-29); later sections are written per release as Keep a Changelog has them.
- Releases are ordinary GitHub releases, marked Latest; `0.x` in the version is the only pre-release signal
  (RL-30: a pre-release flag would leave the Releases page without a Latest and make every install command name a
  tag by hand).
- `muster version` prints `muster X.Y.Z`, `commit <full sha>`, `built <commit date>`, and gains two lines:
  `controls <controls/VERSION>` and `schema <facts schema_version>` (RL-15: the operator reading a diff needs to
  name all three to a reviewer; `version` is the only command that reads no input, so it is where they belong).
  The e2e test pins the five lines.
- SECURITY.md's "Supported versions" already reads "until 1.0, only the latest tagged release receives fixes" and
  stays. The README's status block names the latest release instead of the latest merged stage once `v0.1.0` exists
  (§6.1).

### 4.9 Snapshot lifecycle: `snapshot ls|rm|prune` (D13)

- `muster snapshot ls [--dir <d>] [--format table|json]` lists the snapshots in the directory (default
  `/var/lib/muster/snapshots`): file name, `collected_at`, host name, `muster_version`, `controls_version`, size,
  and which one `latest` points at; sorted by `collected_at` descending, the name's own UTC timestamp breaking ties.
  Only regular files whose name matches the writer's pattern (`<hostname>-<UTC timestamp>-<short digest>.json`) are
  listed; anything else in the directory is counted in the header line (RA-9) and never opened. **RL-16 — three
  classes of row.** A file that decodes as a snapshot is `ok`; one whose `schema_version` is newer than the binary
  is `newer` (its header fields `collected_at` and the versions are read by a lenient header-only decode, so the
  operator sees which binary wrote it); one that decodes as neither is `unreadable` and is ordered by its name's
  UTC timestamp. Both marks are listed, never skipped: the operator must see what is taking space. "The newest
  snapshot" — for RL-17 below and for `diff`'s selection (RL-19) — means the newest `ok` row; a `newer` or
  `unreadable` row newer than it is named in a warning on stderr by `prune` and by `rm`'s re-point, not by `ls`
  (RA-4): `<name> (<class>) is newer than the newest readable snapshot <newest>` (RA-37).
- `muster snapshot rm <name|path>…` removes the named files: any regular file inside the directory by its name
  (pattern-matching or not, `ok`, `newer` or `unreadable` — `rm` is the explicit path for what `prune` will not
  touch), or a file anywhere by its full path (`rm` never guesses a directory). `rm latest` is refused ("latest is a
  link; name the snapshot it points at"). Removing the file `latest` points at re-points `latest` to the newest `ok`
  snapshot remaining or removes the link when none remains. `--dry-run` prints what would go.
- `muster snapshot prune [--keep N] [--keep-days D] [--dir <d>] [--dry-run]` removes every `ok` snapshot that is
  both outside the newest `N` and older than `D` days when both are given, outside `N` or older than `D` when one is;
  neither given is a usage error (exit 2). `newer` and `unreadable` rows are never removed by `prune` and never count
  toward `N` (an older binary must not delete what a newer one wrote; junk is removed by `rm`, by name). **RL-17 —
  prune never removes the newest `ok` snapshot**, whatever the bounds (the diff of §5 needs it and an operator who
  typed `--keep-days 0` meant "old ones"). When `latest` pointed at a removed file, `prune` re-points it as `rm`
  does. The clock is one reading per command, as `--max-age` reads it.
- **RL-18 — the trust rule for a directory muster deletes in.** The same rule the collector's writer applies to the
  directory it writes in (`trustedDir`: the directory itself, `lstat`-ed, is not a symlink and not other-writable),
  plus ownership by the caller and not group-writable; the components above it are not walked, so writer and
  remover agree and a host that can `collect` into a directory can prune it. The lock is `collect`'s helper over the
  same path (the shared lock file on the default directory, the directory's own flock elsewhere — one extra open by
  path, accepted in the Task 4 ruling). For listing and removal the directory is opened once with
  `O_NOFOLLOW|O_DIRECTORY`, and every listing and removal goes through that fd (`unlinkat`), never by a path that
  could be re-pointed between listing and removal; a symlink inside the directory is never followed and never
  removed by `prune` (it is listed by `ls` under the header's count). A full path given to `rm` outside the directory
  applies the same rule to its parent. The three commands run as whoever owns the directory — root, in the default
  layout — and refuse a directory they do not own (exit 2) rather than acting under `sudo` on another user's files.
  `collect` is unchanged.
- The main design's §8 sentence "the snapshot is the only file `collect` ever writes" gains `snapshot rm` and
  `prune` as the only subcommands that remove a file, and only in that directory; THREAT_MODEL says the same.
- `ls`/`rm`/`prune` live in `cmd/muster/snapshot.go` beside `info`/`extract`/`anonymize`; the pure listing and
  selection logic (what prune would remove, given names and times) is a package without `os`
  (`internal/snapshots`), tested with fixtures; the file operations are a thin Linux-tagged layer with a temp-dir
  test as root in CI and a non-root refusal test. Exit codes: 0, 2 on any refusal or I/O error; nothing on stdout but
  the listing or the dry-run plan.

### 4.10 The release job and the alert

Every workflow's actions — `release.yml` and the existing `ci.yml`, `examples.yml`, `fuzz.yml` — are pinned by
commit SHA in one commit of 4A, and `.github/dependabot.yml` (ecosystem `github-actions`, monthly) proposes the
moves, as pull requests the maintainer merges like any other (RL-31: a SHA pin without an updater rots).

`release.yml`: `on: push: tags: ["v*"]`; permissions `contents: write`, `id-token: write`, `attestations: write`;
steps: checkout (full depth for GoReleaser), setup-go from `go.mod`, `check-go-toolchain.sh --exact`, cosign
installer pinned, syft installer pinned, `release-notes.sh`, GoReleaser (`release --clean --release-notes
<file>`), `attest-build-provenance` over `dist/*.tar.gz dist/*.deb dist/*.rpm`. Then the `alert` job as assay's
(one pinned issue, closed on the next success). A tag not on `main`'s history fails the first step (RL-6: tags are
cut from `main` and never moved; the script checks `git merge-base --is-ancestor`).

## 5. 4B — `snapshot diff`

### 5.1 The command

`muster snapshot diff [<old> [<new>]] [--dir <d>] [--facts] [--any-host] [--format table|json] [--profile <p>]
[--tuning <t>] [--waivers <w>] [--fail-on <status>]`

- **Selection (RL-19).** No argument: the two newest `ok` snapshots of `--dir` by the rule of §4.9's `ls` (the
  newest is `new`, the next is `old`; a `newer` or `unreadable` row newer than either is named in a stderr warning
  and skipped); fewer than two is a refusal naming the directory. One argument: that file is `old`, the
  newest in the directory is `new` — unless the one argument is itself the newest, which is a refusal ("name the
  other snapshot"). Two arguments: `old`, `new`, in that order; when `new.collected_at` is earlier than
  `old.collected_at` the command warns once on stderr and compares as named (the operator may be asking "what did
  we lose"). `-` is accepted for one of the two (stdin), not both. Files are opened through `openFacts` with the
  trust checks of `check`.
- **Same host (RL-20).** The two snapshots must carry the same `run.host.machine_id_hash`; otherwise exit 2
  ("snapshots are from different hosts; `--any-host` compares them anyway"). Two snapshots anonymised under one
  key pass this test (the hash is mapped the same way); one anonymised and one not do not, and `--any-host` is the
  deliberate way through. A snapshot without a machine id (an unreadable `/etc/machine-id`, or a container) is
  compared by host name, and the header says which identity was used.
- **One evaluation, both sides.** Both snapshots are evaluated by this binary's control set under the same
  `resolveSelection` result (profile and tuning), the same waivers, one clock reading. A rule therefore never
  differs between the sides (§5.4).

### 5.2 Changed verdicts (the default)

A row per control whose status differs between the sides: id, severity in force, `old → new` status, and the
facts behind it: every leaf the control's clauses read (the facts-used machinery of stage 2M) whose value or
status differs between the snapshots, as `key: old → new` with values escaped the way the `check` table escapes
them, lists summarised (`+3 −1 elements`, the first few names), at most eight leaves per row (`… and N more`,
`--format json` carries them all). Rows are ordered worsened first, then improved, then the rest; inside a group
by severity then id (RL-21). "Worsened" is a move up the ladder `PASS = NOT_APPLICABLE < MANUAL < WARN < FAIL <
ERROR`; `WAIVED` sits with its underlying status for the ladder and is shown as `WAIVED(FAIL)`.

A control whose status is equal on both sides but whose reason code differs (a different `FAIL`) is a row in a
second group, "same verdict, different reason", unless `--quiet`.

### 5.3 Fact changes (`--facts`)

With `--facts`, after the verdict rows: every fact leaf whose status or value differs, grouped by collector
(the key's first component), `key: old → new`, same escaping and list summary, capped at 200 rows in the table
(`… and N more; --format json carries all`) and uncapped in JSON. Keys under `run.` are never compared (volatile
by design, §9 of the main design); `collected_at`, the two versions and the host block appear once in the header.

### 5.4 Rule changes — the anti-goal 4 mechanism

Because both sides are evaluated by the same control set, a changed rule can never appear as a changed verdict.
What can appear is a difference in what was *collected*: a leaf the older snapshot does not carry because its
collector did not exist in the binary that wrote it (the control reads `ERROR(missing_fact)` on that side), a
collector that ran on one side and was denied, skipped or timed out on the other (a non-root run; a container), or
`--deep` on one side only (the walk and verify controls read `MANUAL` behind the deep gate on the shallow side).
**RL-22 — a control whose inputs were not collected alike on both sides is "not comparable", not a change.** The
signal is the snapshots themselves, not the registry's `since` (every key is `since: 1` and §5.7 of the main
design says an addition never bumps the schema, so `since` cannot decide it): a control is not comparable when any
leaf its clauses read is `missing` (not carried) on exactly one side, when the `run.collectors` status of a
collector it reads differs between the sides, or when it is behind the deep gate (`deepFamilies`) and `run.deep`
differs. Such a row goes to a third group, "not comparable", each with its cause (`older snapshot lacks <key>`,
`<collector> denied on the old side`, `--deep on the new side only`), with no arrow and no exit-code effect. The
header prints both `muster_version` and `controls_version` pairs and, when they differ, one line: "the control set
changed between these snapshots: see CHANGELOG.md's Controls entries from <old> to <new>"; when `run.deep` or a
collector status differs it prints one line saying so. Those lines are the whole of the rule-change report: the
brainstorm's sketch of re-evaluating the old snapshot under the old rules is not possible (the old rules exist only
in the old binary) and not needed (same rules on both sides), and the author withdrew it in favour of RL-22.

### 5.5 Output and exit code

- Table: a header (two file names, two `collected_at`, the identity used, both version pairs, the profile line as
  `check` prints it), then the groups of §5.2 and, with `--facts`, §5.3; empty groups are omitted; "no verdict
  changed" is one line. JSON: `{schema_version, run: {…as check…, old: {path, collected_at, host, muster_version,
  controls_version, schema_version}, new: {…}, identity: machine_id|hostname|any}, changed: [{id, severity,
  severity_source, old: {status, reason_code}, new: {…}, facts: [{key, old: {status, value}, new: {…}}]}],
  same_verdict_different_reason: […], not_comparable: […], facts?: […]}`; arrays sorted as the table orders them;
  no map reaches the renderer. Byte-identical for identical inputs.
- **RL-23 — exit code.** 2 on a refusal (selection, trust, different hosts, unreadable input, schema newer than
  the binary); otherwise `check`'s threshold applied to the *new* status of the worsened rows: without a flag, or
  with `--fail-on fail`, exit 1 when a row worsened to `FAIL` or `ERROR`; `--fail-on warn` adds `WARN`, `--fail-on
  manual` adds `MANUAL`, `--fail-on none` is always 0 unless 2 — the same words and the same default as `check`, so
  a CI that reads `check` reads `diff` the same way. A row worsened to `WARN` is listed and exits 0 by default.
  `ERROR` on the new side of a comparable row is a worsening (exit 1), not exit 2: diff refuses only what stops
  the comparison.
- `--max-age` is not offered on `diff` (the age of the older side is the point) — stated in the usage.

### 5.6 Where it lives and how it is tested

`internal/diff` (pure: takes two `[]check.Result`, two fact maps, the registry and the selection; returns the
groups) with a determinism test, a ladder test and a `since` test; `cmd/muster/snapshot.go` adds the subcommand on
`runCheck`'s helpers (`openFacts` → `resolveSelection` → `loadWaivers` → evaluate twice → `diff.Build` →
render). Fixtures: pairs under `cmd/muster/testdata/diff/` built from the control fixtures (a `pass-*`/`fail-*`
pair of one control is a worsening; the `_hosts` snapshots against an edited copy give fact changes), the two
example snapshots (different hosts → the refusal and `--any-host`), for RL-22 a fixture with a collector's keys
removed (the "older binary" case), one with a collector marked `denied` in `run.collectors`, and a deep/shallow
pair, and anonymised pairs from the 3D-3 fixtures. Goldens for table and JSON with `-update`. The e2e test covers the
three selection forms over a temp directory and the exit codes. The examples gate is untouched (diff adds no
example file; RL-24: the examples workflow collects once per image, so there is no second snapshot to publish).

## 6. 4C — operator documents and release gates

### 6.1 The README pair

Rewritten for the operator, in this order: what muster is (the present first two paragraphs, kept); **Install** —
"Verify first" (the two commands of §4.5, then the sha256 route, with what each proves), then the package commands
per distribution and the tar.gz, then "Reproduce the build" (§4.3); **First run** — `sudo muster collect`,
`muster check`, a month later `muster snapshot diff`, with one short output excerpt each; **Keep it running** —
the example units and `snapshot prune`; **Positioning** — a short table against Lynis, OpenSCAP/`oscap` and
CIS-CAT on the axes offline-from-a-snapshot, changes-nothing, KISA items, CIS/STIG/NIST references, remediation
as a review script (facts only, no benchmark text, no claim about the others' quality); then the present sections
(what it does, principles, what it does not do, targets, standards, roadmap, documents, relationship to assay,
licence). The status block names the latest release and links the Releases page. The roadmap sentence
`coverage -check` verifies stays verbatim. `README.ko.md` is the same document in Korean, held by §6.3.

- **RL-32 — excerpts are pinned to committed files.** The `collect` and `check` excerpts are contiguous lines of
  `examples/ubuntu-24.04-vm-report.txt` and the `diff` excerpt is a table golden of `internal/diff` (a fixture
  pair; RL-24 stands — the examples workflow collects once); a test in `cmd/muster` holds each README fenced
  excerpt equal to its source, so an examples refresh or a renderer change updates the README in the same commit
  or fails CI. The identical bytes sit in `README.ko.md` (§6.3).
- **RL-33 — the Install section is written for `v0.1.0` before the tag exists**, with the literal file names and
  signing identity, and its blocks are what `release-dry-run` executes (RL-28). The commands that need a published
  release are run in the operator rehearsal (§6.5); if one fails there, `v0.1.1` carries the corrected README and
  the `v0.1.0` release notes are edited to point at it (RL-6: the tag stays).
- Each positioning cell is sourced: a footnote per comparand naming the version and the public document read, and
  a cell the author cannot source is `—`, not a claim (RL-34). Footnote markers are identifiers §6.3 holds on both
  sides.
- Targets: the README says what is true — the packages install and are tested on Debian 12, where the collector
  runs as CI's non-blocking canary; Ubuntu 22.04/24.04 and the RHEL 9 family stay the supported targets (RL-35).
  SECURITY.md's scope says the same.

### 6.2 THREAT_MODEL and SECURITY

THREAT_MODEL gains "Supply chain": what the attestation and the signature prove (built by GitHub Actions from
this repository at this tag; the checksums file is the one the job produced) and do not (that the source is
benign; that a maintainer's account was not misused — a reviewer reads the tag's diff), the toolchain and
dependency pins, govulncheck's two layers and the fail-closed rule, and the statement that no release artefact
contains a key. The "Reads" and "Writes" paragraphs name `snapshot rm`/`prune` as the removal path (§4.9).
SECURITY.md adds how to report a compromised release (the same path) and that a yanked release is marked on the
Releases page and in CHANGELOG, never deleted (RL-25: deleting hides the evidence a verifier needs). Both stay
English-only (RL-38); the README pair's Install section says in both languages what the two verifications prove
and do not, so the Korean operator does not need THREAT_MODEL for that.

### 6.3 Document drift check

`tools/docdrift` (`make docdrift`; CI runs `go run ./tools/docdrift -check`) reads a committed table,
`tools/docdrift/pairs.txt`: one line per pair, `<path> <rule set>`, and refuses an `X.ko.md` anywhere under the
repository root or `docs/` that is not in the table (so a new pair must choose its rule set) and a table entry
whose English side is missing. Two rule sets (RL-36):

- **`operator`** — the documents the operator reads: `README`, `CONTRIBUTING`, `RELEASING` and every future pair
  unless listed otherwise (the English-only documents of RL-38 are not pairs and are not listed). Both files exist; the heading outline matches (the same count of headings per level, in
  the same order of levels); the fenced code blocks are byte-identical in sequence (commands and output are not
  translated — a comment inside a command block is English on both sides); the set of backtick-quoted identifiers
  outside code blocks is equal after two normalisations, a `<…>` placeholder run becomes `<>` (a placeholder is
  the one translatable thing inside an identifier: `` `--walk-budget <기간>` ``) and a link target's `.ko.md`
  becomes `.md`.
- **`design`** — the main design pair: both files exist, the heading outline matches, and the line counts are
  equal (the pair is edited line for line); code blocks and identifiers are not compared, because a Korean reader
  is served by Korean comments in a YAML example.

The fifteen merged stage specs are listed with the rule set `history` — existence and heading outline only: they
are the record of decisions as made, and reconciling their identifier sets would rewrite ~8,000 lines of Korean for
no reader. Measured today, every pair fails the `operator` rules somewhere (the README's one code block has a
translated comment; CONTRIBUTING's Korean side names commands the English side does not); 4C reconciles the
`operator` pairs and the main design pair before the job turns required. The check is a required CI job and runs in
`release-dry-run` as well, so a tag cannot be cut over a drifted pair (RL-26). It checks shape, not meaning: the
reviewer still reads both.

### 6.4 `RELEASING.md`

English and Korean. The sequence: the CHANGELOG commit (section, date, the Controls paragraph if a verdict
moved); `make docdrift coverage-check release-dry-run` locally if a C toolchain is present, else trust CI on the
commit; wait for CI on `main`; `git tag vX.Y.Z && git push origin vX.Y.Z` (from a clean checkout of `main`, by a
maintainer, by hand — RL-27: no agent session pushes a tag; CLAUDE.md's push rule extends to tags); watch the
release job; then the **operator rehearsal** (§6.5). A failed release: fix on `main`, cut the next patch tag; the
failed tag stays (RL-6) with a CHANGELOG note.

### 6.5 The operator rehearsal — the gate before announcing

After the job publishes, from a machine that is not the build runner (the lab host is excluded; a fresh
container or VM): follow the README's Install section word for word — verify with both commands, install the
package, run `collect`, `check`, `anonymize`, `diff`; run `go run ./tools/anonverify <original> --key <key>
<anonymised> <check json> <check table> <fix script>` (RL-37: a maintainer tool beside `tools/coverage` — it
re-runs the anonymiser as a library on the original under the same key, takes every clear value the ledger mapped
as the oracle — host labels, account and group names, addresses, fingerprints, the machine id, path components —
and searches the produced files for them as whole tokens; the binary and the pure `internal/anonymize` are
untouched, and the tool has a test over the example snapshots), and confirm the report and the fix script carry
nothing the redaction policy forbids; run `reproduce.sh`; `remove` and `purge`. The
checklist is in RELEASING.md with a line to fill per step; the release is announced (the README status block
updated on `main`) only when every line is filled. The first rehearsal is `v0.1.0`'s and its filled checklist is
committed under `docs/releases/v0.1.0.md`.

## 7. Tests and CI (summary)

| Gate | Where | Holds |
|---|---|---|
| `release-dry-run` | ci.yml, PR + main | §4.7: the whole pipeline without publishing; reproduce; install contract matrix; vulncheck |
| `govulncheck` source | ci.yml `test` job | §4.2 |
| `check-go-toolchain.sh` | ci.yml floor, release.yml exact | RL-4 |
| `docdrift -check` | ci.yml + release-dry-run | §6.3 |
| examples gate | existing | no byte of `check`/`fix` output moves |
| `internal/snapshots`, `internal/diff` purity and determinism tests | go test | §4.9, §5.6 |
| e2e: `version` five lines, `ls/rm/prune`, `diff` selection and exit codes | cmd/muster | §4.8, §4.9, §5.5 |
| goldens: diff table/JSON | internal/diff | §5.5 |
| root tests: `prune` in a temp dir, `rm` through a directory fd; non-root refusal | CI sudo step | RL-18 |
| shellcheck | existing target | the new `scripts/*.sh` and `ci/release/*.sh` join the list |

## 8. Documents

Main design: §5.9 (the three commands arrive), §7 (diff's exit code), §9 (`version`'s five lines replace "build
date … and guide edition" — the guide edition rides inside the `controls` value), §8 `:428` (replace the
list with what is built: keyless, SBOM, packages, no install script, reproduce script), §9 (SARIF moves to
"deferred"), §10.2 (stage 4 paragraph restated as 4A/4B/4C with "merged" marks as they land), §10.3 (SARIF,
`--controls-dir`, contributor items, Lynis added), D13 closed, new **D37 — Release integrity and the install
contract** (keyless signing, L2 attestation stated as such, reproducible build by exact toolchain and commit date,
packages that start nothing, purge semantics), **D38 — `snapshot diff` compares under one control set** (RL-20,
RL-22, RL-23). The pair stays line-aligned. CLAUDE.md gains a "Release (stage 4)" section (the pipeline, the
contract list, the reproduce rule, the drift check, "never push a tag from an agent session"). CHANGELOG under
Unreleased per slice. README pair per §6.1, THREAT_MODEL and SECURITY per §6.2, RELEASING.md per §6.4,
CONTRIBUTING.md one paragraph on `docdrift`.

## 9. Deferred (not in stage 4)

- **SARIF** — no consumer in the operator's picture; back when one exists (the renderer and schema validation
  stay designed in §9 of the main design).
- **`--controls-dir`** — the author's recommendation, accepted: the operator consumes controls, profiles and tuning
  already cover selection and values, and a site control needs facts only a collector can add. The collision and
  digest rules of §4 stay for when it comes.
- **Contributor items** — DCO sign-off, the PR template, the Lynis differential and per-image baselines.
- **Other platforms** — a check-only build for macOS and Windows (§10.3 of the main design).
- **An installer script or one-liner** — never (main design §8).
- **Central upload or an agent** — out of scope (§10.3).

## 10. Author's calls

Choices the brainstorm left open and this document settles; the user can overturn any of them before the plan:

1. Weekly `OnCalendar` for the example timer (§4.6, RL-12).
2. Example units under `/usr/share/doc/muster/examples/systemd/`, not on the unit path (RL-12).
3. rpm erase keeps `/var/lib/muster`; only Debian's purge removes it (RL-13).
4. `muster version` gains `controls` and `schema` lines (RL-15).
5. `prune` keeps the newest snapshot whatever the bounds (RL-17).
6. The rule-change report is one header line pointing at CHANGELOG plus the "not comparable" group; the
   brainstorm's re-evaluate-under-old-rules idea is withdrawn (RL-22, §5.4).
7. Diff's exit code: 1 on any worsening including a new `ERROR` on a comparable row (RL-23).
8. One argument to `diff` means "this old one against the newest" (RL-19).
9. The reproducibility claim is exactly what `scripts/reproduce.sh` proves, and the commit date replaces the
   build date in `muster version` (RL-5, RL-7).
10. The positioning table's three comparands and five axes (§6.1).
11. The drift check compares outline, code blocks, identifier sets and listed line counts, not prose (§6.3).
12. A yanked release is marked, never deleted (RL-25); a tag is never moved (RL-6).

Settled after the builder check (the reviewers' questions, answered by the author):

13. "Not comparable" is decided by the snapshots — a leaf `missing` on one side, a collector status that differs,
    `--deep` on one side — not by the registry's `since` (RL-22, §5.4); the example timer runs without `--deep`
    so weekly snapshots compare whole (§4.6).
14. `ls` has three row classes (`ok`, `newer`, `unreadable`); `prune` touches only `ok` rows and keeps the newest;
    `rm` removes anything by name (RL-16, RL-17, §4.9).
15. The directory trust rule is the collector writer's rule plus ownership, through one directory fd, no component
    walk; `collect` is unchanged (RL-18).
16. Diff's exit threshold is `check`'s: `FAIL`/`ERROR` by default, `--fail-on` with the same words (RL-23).
17. The README's install blocks are executable templates run by `release-dry-run`; the Install section is written
    for `v0.1.0` before the tag (RL-28, RL-33); excerpts are pinned to committed files (RL-32).
18. Ordinary releases marked Latest, no pre-release flag (RL-30); `[0.1.0]` is a fresh operator page and the stage
    history moves under its own heading (RL-29).
19. Every workflow's actions pinned by SHA in 4A with a `dependabot.yml` for actions (RL-31).
20. The drift check has three rule sets — `operator`, `design`, `history` — in a committed pairs table; the merged
    stage specs are `history` (RL-36).
21. The rehearsal's canary check is `tools/anonverify`, a maintainer tool over the ledger's clear values (RL-37).
22. Positioning cells are sourced or `—` (RL-34); Debian 12 is "installs and is tested; collector as canary"
    (RL-35).

Decided by the user after the builder check: the Korean pairs are README and RELEASING only, with a Korean
supply-chain summary in `README.ko.md` (RL-38); the package maintainer string is the commit identity (RL-39).

## 11. Left to the builder

The GoReleaser and nfpm field names and the exact pinned versions; the layout of `scripts/` and `ci/release/`; the
table widths and wording of `diff`'s groups within §5's rules; the fixture pairs' choice of controls; the
`docdrift` identifier tokeniser's edge cases (a backtick inside a code span, a heading inside a code block); the
order of the three plans' tasks; which `releases/` and `ci/` paths join the shellcheck target.

## 12. Rulings

- **RL-1** `v0.1.0` first; `0.x` until operator feedback is read.
- **RL-2** Targets `linux/amd64`, `linux/arm64` only.
- **RL-3** No install script; the release job never pushes to `main`.
- **RL-4** One toolchain named in `go.mod` (the newest patch of a supported line; `go 1.25` stays); CI floor, release exact.
- **RL-5** Reproducible by construction: commit timestamp and date (`format-local:` under `TZ=UTC`), `-trimpath`, `-buildvcs=false`, exact toolchain.
- **RL-6** Tags are cut from `main` and never moved or deleted; a failed tag stays and is noted.
- **RL-7** The README claims only what `reproduce.sh` proves.
- **RL-8** SBOMs in SPDX JSON by pinned syft, one per archive and package; an archive's SBOM lists the binary's modules, a package's SBOM describes the package itself (syft reads a `.deb`/`.rpm` header, not the payload).
- **RL-9** Keyless signature over the checksums file, Sigstore bundle (`--new-bundle-format`), identity = the release workflow at the tag.
- **RL-10** Attestation stated as SLSA Build L2, with what it does not prove.
- **RL-11** Packages install the binary and documents and start nothing; nothing under `/etc`, `/var`, `/usr/lib/systemd`.
- **RL-12** Example units in the documentation directory; weekly.
- **RL-13** No pre/post-install scripts; Debian purge removes `/var/lib/muster` unless it is a mount point (left with a note) or a symlink (the link goes), and never fails; rpm erase keeps it.
- **RL-14** Release notes are the CHANGELOG section; a missing section fails the release.
- **RL-15** `muster version` prints five lines (version, commit, built, controls, schema).
- **RL-16** `ls` rows are `ok`, `newer` or `unreadable`, never skipped; non-snapshot names are counted, never opened.
- **RL-17** `prune` removes only `ok` rows and never the newest `ok` snapshot; `newer`/`unreadable` go only by `rm`.
- **RL-18** Delete only in a directory the caller owns under the writer's `trustedDir` rule, through one directory fd, never following a symlink; `collect` unchanged.
- **RL-19** Selection over `ok` rows: none → two newest; one → it against the newest; two → as given, warn if reversed.
- **RL-20** Same `machine_id_hash` or `--any-host`; host name when no id, said in the header.
- **RL-21** Row order: worsened, improved, rest; severity then id within.
- **RL-22** A control whose inputs were not collected alike (a leaf `missing` on one side, a collector status that differs, `--deep` on one side) is "not comparable".
- **RL-23** Exit 2 only on a refusal; else `check`'s threshold over the new status of worsened rows (`FAIL`/`ERROR` by default, `--fail-on` with `check`'s words).
- **RL-24** No example diff file; the examples workflow has one snapshot per image.
- **RL-25** A yanked release is marked, never deleted.
- **RL-26** `docdrift -check` is a required CI job and runs in `release-dry-run`.
- **RL-27** No agent session pushes a tag.
- **RL-28** The README's install blocks are executable templates that `release-dry-run` runs (verification on `main` pushes).
- **RL-29** `[0.1.0]` is a fresh operator-facing section; the stage history moves under `## History before 0.1.0`.
- **RL-30** Ordinary releases marked Latest; no pre-release flag.
- **RL-31** Every workflow's actions pinned by commit SHA; `dependabot.yml` for actions proposes the moves.
- **RL-32** README excerpts are held equal to committed files (an example report, a diff golden) by a test.
- **RL-33** The Install section is written for `v0.1.0` before the tag; a failure in the rehearsal is fixed by `v0.1.1`.
- **RL-34** A positioning cell is sourced (version and document in a footnote) or `—`.
- **RL-35** Debian 12: packages install and are tested; the collector is CI's canary; not a supported target.
- **RL-36** `docdrift` reads a pairs table with rule sets `operator`, `design`, `history`; an unlisted `.ko.md` is refused.
- **RL-37** `tools/anonverify` is the rehearsal's canary check, with the ledger's clear values as the oracle.
- **RL-38** Korean pairs: README and RELEASING; THREAT_MODEL, SECURITY, ATTRIBUTION, CHANGELOG English-only; `README.ko.md` summarises the verification.
- **RL-39** Package `Maintainer`/`Packager` is the commit identity `seonggyun.seo <40746364+kun9497@users.noreply.github.com>`.
