# Contributing to muster

muster checks a Linux host against the KISA 2026 Unix server guide. A
contribution is usually one of three things: a control, a collector fact, or
a fix in the evaluator or the renderers. This page says how each one lands.
The design and its decision log live in
`docs/superpowers/specs/2026-09-02-muster-design.md`; read the section you
are changing before you change it. Korean: `CONTRIBUTING.ko.md`.

## Before anything else

- Go 1.25. `go build ./...`, `make test` (or `go test ./...` on a host without a
  C toolchain), `make lint`, `make lint-controls`, `make coverage`.
- `collect` is Linux-only and lives behind build tags. On another platform,
  cross-compile it (`GOOS=linux GOARCH=amd64 go vet ./... && GOOS=linux
  GOARCH=amd64 go test -c ./internal/collect/collectors/ -o /dev/null`) and let
  CI run it.
- Never copy text from the KISA guide or a CIS Benchmark into any file.
  `docs/reference/kisa/` holds item codes, names, categories, importance and
  page numbers only; control descriptions are written in muster's own words.
  See `ATTRIBUTION.md`.
- Never commit anything that names an organisation, a host, an address, an
  alias or a credential. Fixtures use `example.org`/`example.net` names and
  RFC 5737 addresses. A snapshot captured from a private host is never
  committed, in whole or in part.

## Adding a control

1. **Scaffold it.**
   `go run ./cmd/muster controls new muster.<area>.<name> --kisa-id U-NN`
   writes `controls/<area>/<name>.yaml` with the item's importance and its
   KISA references (2026, and the 2021 number from the mapping) filled in,
   and the fixture stubs its automation can reach under
   `controls/testdata/<id>/` (a `pass-`/`fail-` pair for `auto` and
   `partial`, one `manual-` stub for `manual`). Areas are
   `account`, `file`, `service`, `patch`, `log` and `beyond`. The command
   refuses an item another control already claims and an item listed in
   `docs/reference/kisa/kisa_deferred.json`: to enrol a deferred item,
   remove its deferral first. Against the shipped inventory every item is
   one or the other, so the scaffold is for the next edition's items or for
   a deferral whose stage has come.
2. **Name the facts.** Every clause reads a registered key
   (`internal/facts/registry.yaml`). If the fact does not exist yet, add it
   to the collector that owns it (below) first. A clause never reads a raw
   JSON path.
3. **Write the judgment.** `checks` for one judgment, `mechanisms` when the
   host can be judged by more than one route, `custom` only when the grammar
   of spec §6.3 cannot express it. Set `absent_means` for what an absent fact
   means (`pass`, `fail`, `not_applicable`, `manual`) and `applies_when` for
   the gate. A `manual` control carries `manual_reason` and an `evidence:`
   list of the facts a reviewer needs in front of them.
4. **Fixtures.** A control with a judgment (`checks` or `mechanisms`) needs
   `controls/testdata/<id>/pass-*.json` and `fail-*.json`; a `manual`
   control needs `manual-*.json` carrying every `evidence:` leaf, plus
   `na-*.json` when it has an `applies_when` gate (`error-*` as the control
   needs; the file-name prefix is the expected status). Each is a
   partial snapshot holding only the keys the control reads, marked
   `"synthetic": true`. `go run ./cmd/muster snapshot extract --facts
   <snapshot> --control <id> --out <file>` cuts exactly those keys out of a
   real snapshot — review the values, remove anything that identifies the
   host, then mark it synthetic. `_expect` may pin `reason_code` and
   `exit_code`; those two keys are the only ones the fixture test reads —
   the expected status is the file-name prefix, not an `_expect` field. A
   YAML description is a plain scalar: it cannot contain the sequence `: `
   unquoted, so quote a description that needs it.
5. **Lint, test, regenerate.** `make lint-controls` (the KISA cross-check,
   the STIG/NIST index, the fixture pair, the grammar), `go test ./...`,
   then `make coverage` and commit the regenerated
   `docs/reference/coverage.md`. If the enrolled count changed, update the
   roadmap sentence in both READMEs — `-check` fails until the numbers match.
6. **References.** `references.stig` entries are `{benchmark, version, id}`
   and must exist in `docs/reference/stig/*.json`; `references.nist_800_53`
   ids must appear in some indexed rule. `make refindex` regenerates the
   index from the pinned DISA files (network); CI only reads the committed
   index. The walk's reference lists have the same shape of life:
   `make suidindex` regenerates them from pinned public images (docker and
   network), `make suidindex-check` verifies them, CI reads the committed
   files.

### Controls beyond the guide

A control that is not a KISA item has `category: beyond`, an id
`muster.beyond.<name>`, no `references.kisa` (the lint rule `beyond_scope`
keeps the two in step), and a CIS recommendation number only through the
index (see "Mapping a control to CIS"; the mapping is independently derived): it
is written from a primary source — kernel documentation, a man page, the distribution's own
documentation — in muster's own words, and its description says in one
sentence why it has the importance it has. Every such control gates on
`env.container eq none`: inside a container these facts describe the host.
`go run ./cmd/muster controls new muster.beyond.<name> --importance 중`
scaffolds one (no `--kisa-id`). A fixture that reads a `setting` key carries
the key present with its `effective` side `absent` when it means to be absent.

### Remediation bodies

`fix --dry-run` renders a control's `script`, `validate` and `rollback` into a
review script, so they are code. A `script` needs `idempotent: true`, a
`validate` and a way back, of six kinds: a `rollback`, a non-empty `backup`, a
record of the state the body changes — `modes` (the owner, group and mode of
paths and of `/*` or `/*/*` expansions), `sysctl` (kernel keys' runtime values)
or `modules` (whether each module is loaded) — any of these together, or — for
a service control — `units` alone (`units` excludes all five others). The
template records each declared kind under the block's own directory
(`$MUSTER_BACKUP/blocks/<fn>/`) before the body runs and, when the body or the
validate fails, runs the declared `rollback`, then restores units, modes,
files, sysctl values and modules, in that order. A path a daemon or the system
writes to while the block runs (a live log) is a `modes` entry, never a
`backup`, which would copy its contents back; a path a body only re-modes may
use either. Bodies run under `set -e` in
a subshell: a command that may legitimately fail says so with `|| true` on its
own line, never a trailing `; true`, and no `2>/dev/null` hides an error the
operator should see. A body acting on a file checks it exists first — a
directory the host may lack under `if [ -d <dir> ] && [ ! -L <dir> ]; then …;
fi`, one path under `if [ -f <p> ] && [ ! -L <p> ]` — and one calling an
optional tool guards it with `command -v`. A service control declares its
units in `units` — the logical service's `provesInstall` units in `services.go`,
each `<name>.socket` before its `<name>.service` (a Linux test pins the set, and
the validate names the same units) — and its script never names a unit: the
template sets `UNITS`, records each unit's state before the body and puts it
back on failure, so there is no hand-written rollback. The record puts back
enablement and masking, but it never stops a unit: a body that enables (the
one today is `auditd_active`) unmasks, enables and starts only an inactive
unit, and its text says a failed block leaves the started unit running. A
body that disables loops over `$UNITS` in two passes, even for one unit:

```sh
todo=
for u in $UNITS; do
  systemctl cat "$u" >/dev/null 2>&1 || continue
  [ "$(systemctl show -p Id --value "$u" 2>/dev/null)" = "$u" ] || continue
  todo="$todo $u"
done
for u in $todo; do
  systemctl --quiet disable --now "$u"
  systemctl --quiet mask "$u" || true
done
```

The first pass resolves every name before anything is masked and skips an
alias of a listed unit (Debian's `nfs-kernel-server.service` is an alias of
`nfs-server.service`; disabling it after the mask fails). An alias of a unit
you did not list is skipped too, so declare the real unit. A module body opens
with `mods='<the modules>'` and loops `for m in $mods`, for the same reason
(shellcheck flags a literal one-word list). A file body clears
the forbidden bits symbolically (`chmod u-xs,g-rwxs,o-rwxt`, never an absolute
mode, so a stricter file stays as it is); a body that removes an ACL (the two
that do: `passwd_permissions`, `shadow_permissions`) runs `setfacl -b` before
`chmod`. A `find` that changes a mode or an owner carries `! -type l` or the
type the control judges (`-type f`), so `chmod` never follows a symlink. A body
that changes files under a directory someone other than root may own (a
daemon's log directory, `at`'s spool) acts only where the template's
`modes_trusted "$d/." 0` holds — every ancestor root-owned and not
other-writable; a root-owned group-writable one, as Ubuntu's `/var/log`, is
accepted — and logs and leaves any other directory to the operator; its
validate checks the same set, so the block ends `done` and the next `check`
still names the path. A body that writes a file muster owns (a
`99-muster-*.conf` drop-in) and finds a symlink there — an operator's mask —
logs it, leaves it, and fails the block before writing anything; a rollback that
removes that file skips a symlink.

A body writes a value only when the current one is outside the set the
control's clause accepts, read the way the collector reads it (the first
`login.defs` line, the last `faillock.conf` line, the merged `pwquality`
chain, keys in any case), so it never loosens a stricter host and never
rewrites a value that already passes; the value it writes is the guide's, or
the first element of the list in force. A write's side effect on another
judged key is the writer's to put back: writing `net.ipv4.ip_forward` makes the
kernel reset `net.ipv4.conf.all.accept_redirects`, so `ip_forwarding_disabled`
reads that key first, restores it afterwards, and lists it in `sysctl`. A
rollback of a control whose daemon re-reads the file it wrote puts that file
back (or removes it) itself, then tests and reloads the daemon: the template's
`restore` runs after the rollback, too late for the reload.

A control whose script needs a parameter's value in force declares it in
`script_params`; the block then opens with `P_<name>='<value>'` (a list joined
by one space; take the first element with `first=${P_<name>%% *}`). The value
must pass its type's charset (`int` an optionally signed integer, `^-?[0-9]+$`;
`bool`; or a `string`/list element
in `[A-Za-z0-9._/@:+,=-]`), or the item is text-only (`params_unsafe`). Use it
only as data: after `=` (`n=$P_max`), as an option's operand
(`chage -M "$P_max_days"`) or after `--`, as a later operand, or as an awk
`-v`/`VAR=` assignment. It never stands first on a line and never inside a
`sed` expression: copy it to a plain variable and use `|` as the delimiter
(`sed -i "s|^deny .*|deny = $n|"`). `TestShippedBodiesPlaceParametersSafely`
holds every shipped body to that. A control whose fix writes the very line an
`absent_means: fail` finding names declares `script_on_absent: true`; any other
absent finding stays text-only.

`validate` is one line and checks only what the script set, proving set
membership, not equality with the value written. Three shapes: conditions
joined with `&&`; a single `case` whose last arm is `*) false` (a `case` that
matches nothing exits 0); or one `for` over a literal list whose conditions
end the loop with `exit 1`. A body that cannot apply on a host guards its
validate the same way (`if command -v sshd …; then …; fi`). A file validate
lists the control's default allowed modes, and a `find` in a validate tests the
complement of the allowed bits — 07777 minus the largest allowed mode
(`-perm /7137` for 0640, `/7177` for 0600, `/7337` for 0440) — and `! -user
root` where the owner is judged. `backup` paths and `modes` entries are
absolute and clean, in `[A-Za-z0-9._@:+/-]` (an entry may end in `/*` or
`/*/*`); `sysctl` keys match `^[a-z0-9_]+(\.[a-z0-9_-]+)+$` and are never
sorted (the order is the write and restore order); `modules` names match
`^[a-z0-9][a-z0-9_-]*$`. No here-document. The script runs
under `umask 077`, so a body that creates a file others read sets its mode.
`make shellcheck` and `go test ./internal/remedy -run TestScriptGolden -update`
(the `all-scripted.sh` golden renders every shipped body) check your change.
A new scripted control also enters `controls/testdata/_roundtrip.yaml` in the
same commit: the `fix-roundtrip` rows (`images`) whose seed script in
`ci/roundtrip/<key>.sh` loosens it and whose `seeded` list names it, or
`unproven:` with the reason no row can (no systemd unit, no package in the
image's enabled repositories, the unit cannot run in a container, or the
kernel does not ship the module). A `beyond` control gates containers out, so
it names only the `runner` row (the GitHub runner VM, seeded by
`ci/roundtrip/runner.sh`); `TestEveryScriptedControlIsInTheRoundtripTable`
holds the table, the shipped set and the CI matrix equal.

The bodies that edit what a file says (stage 3D-2d) add these rules:

- **No one-way runtime change.** A body never makes a change only a reboot
  undoes — no `-e 2`, no `--loginuid-immutable` — and it never loads audit
  rules into, or starts auditd over, such a setting pending in any rules file,
  whatever the kernel's lock state. Every other runtime effect is either
  recorded under `$MB` and put back by the rollback, or named in the control's
  text as staying after a failed block.
- **A daemon is touched only on what this run recorded.** Before any edit the
  body writes `$MB/<daemon>.was-running` when the daemon runs, and touches
  `$MB/<daemon>.edited` just before its first write. Its reload or restart, and
  the rollback's, need both markers; the rollback may call the prologue's
  `restore <path>` first. Records that describe one run (these markers, a list
  of the keys written, a list of the accounts changed) are removed as the
  body's first action and written fresh; only file backups and the lists a
  rollback replays keep their first copy.
- **The value written** is the first member of the list in force that the
  target accepts and that keeps the host up (`audit_disk_actions` never writes
  `email`, `exec`, `single` or `halt`); a clause that only forbids content may
  be met with a fixed neutral string (`FTP server ready.`), never a legal
  notice.
- **Comment out, never delete.** A line the body disqualifies is prefixed
  `# muster: `, and the file is in `backup`. A tool that writes its own file is
  used where it reads the file the way the collector does (`postconf -e`); one
  that rewrites more than the one key (`useradd -D`) is not.
- **Append safely.** Before appending to a file that may lack a final newline:
  `if [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ]; then echo >> "$f"; fi`.
- **Read the collector's way, and prove it.** A body's reader is a one-line
  `rd_<what>() { LC_ALL=C …; }` function; when the validate re-proves its
  verdict it repeats the same program, and
  `internal/collect/collectors/remediation_parity_test.go` (Linux) runs each
  reader over the parser's fixtures and compares with the Go parser. Every
  command whose text output a body, validate or rollback parses runs under
  `LC_ALL=C` (output that does not depend on the locale — `date +%s`, numeric
  `stat -c` fields, the `tail -c1` test — needs none).
- **A guarded validate.** Beside the three shapes, a validate may accept a
  leave the body logs, as `[ guard ] || …` or a `{ …; } || { …; }` grouping on
  one line; the block ends `done` and the next `check` names what was left.
- **SELinux.** `restorecon` runs only on a file a tool replaced or created
  (`postconf -e`, a newly created file), never after `sed -i` or `restore`,
  spelled `if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled &&
  command -v restorecon >/dev/null 2>&1; then restorecon -- "$f"; fi`.
- **Upgrades.** A vendor configuration file a body edits in place is reported
  at the next upgrade — dpkg (or ucf) asks about an edited conffile, rpm keeps
  the edit and writes `.rpmnew` — and the text says so for the files the
  package marks as configuration.
- **Proof a row cannot give.** A daemon whose restart path no round-trip row
  can run is named unproven in the plan and in the stage's design, with a
  stub test, not in `_roundtrip.yaml` (whose `unproven_units` names only
  declared units).

### Mapping a control to CIS

A control's `references.cis` is never written by hand from a Benchmark: it is the
rendering of the committed index in `docs/reference/cis/`, and
`TestEveryCISReferenceIsTheIndex` prints the block to paste. To map a control,
add or edit its row in `docs/reference/cis/map.yaml`:

- `rules:` the ComplianceAsCode rule ids that check what the control's clauses
  judge, reviewed against the clauses; a seed from a join is a starting point,
  never committed unreviewed.
- `recs:` (per benchmark) only for an entry that lists no rule id, with a reason
  that describes the control, never a title or the recommendation.
- `vars:` per spec CB-8: every variable selected on a reached Level 1 – Server
  entry is named, with `as: int`, a `{selected: value}` table whose keys spell
  their own value, or `param: none` and a reason.
- `docs/reference/cis/review.yaml` takes a candidate out of a profile, one reason
  each, where its judgment cannot honestly stand for the recommendation —
  including where a host meeting the recommendation would fail the control at
  muster's default.

Then run `make cisindex` (`go run ./tools/cisindex`; maintainer-run, it reads the
pinned files from `.cache/cisindex/` or the network) and paste the blocks
`TestEveryCISReferenceIsTheIndex` prints, then commit the regenerated index,
`internal/profile/builtin/cis-*.yaml` and the pasted references with the map
change in one commit.

## Adding a fact

- Register the key first: `{key, type, description, since, sensitivity,
  collector}` (+ `default_on` for settings, `subject_kind` for lists). Adding
  a key or a record field keeps `schema_version`; changing a key's type or
  meaning bumps it. The facts schema golden
  (`go test ./internal/facts -run TestFactsSchemaGolden -update`) records the
  change — review the diff.
- Every leaf is an envelope with a status: `ok`, `absent`, `denied`,
  `unsupported`, `timeout`, `error`. A status other than `ok` never produces
  PASS. A registered key the snapshot lacks reads `missing` and is
  `ERROR(missing_fact)`, never excused by `absent_means`.
- Collectors declare every path and command they touch (`Declare.Reads`,
  `Declare.Commands`); a read outside the declaration is a violation. A path
  discovered from a configuration file is read only when the declaration
  covers it; otherwise it is recorded and never opened.
- The conventions in `CLAUDE.md` bind every collector:
  - **C1** — `files.*` owns permission facts of a fixed path list; a path
    discovered from a daemon's configuration belongs to that daemon's
    collector.
  - **C2** — every leaf a clause judges is its own dotted key; a `record`
    fact is evidence for `present`/`absent` only.
  - **C3** — a configuration file that exists but cannot be read is the
    answer for every value it could set (the read's status, path-prefixed),
    never the module's default.
  - **C4** — a path the model declined to read is `absent` with the path in
    the reason; a declared file that exists and cannot be read is the read's
    status; a symlink an administrator placed at a declared main
    configuration file is `error` by design (muster reads without following
    symlinks; where a distribution ships a symlink, the collector models it).
- Honest degradation: an environment that has no such mechanism is
  `unsupported`; a root-only read as non-root is `denied`; a collector that
  needs no privilege never emits `error`. Never `time.Now` in a collector —
  ages are computed from `collected_at`.
- Same input, same bytes: sort every list, never let map order reach a
  value or a reason.
- The walk (`collect --deep`) is the one collector licensed to read outside
  a fixed declaration: `Declaration.Walk: true` allows `ReadDir` on any
  path, but every file it opens by name (`/proc/self/mountinfo`, the id
  files, the container-runtime configuration files, dpkg's database) is
  still declared, and it never follows a symlink. Its finding lists are
  capped, never stop the walk, and say so with `truncated: true`; a root it
  did not enter is a `walk.skipped` row with a reason from a closed
  vocabulary. The dpkg join decides a setuid bit against
  `docs/reference/suid/<id>-<version_id>.json`, a reference list of every
  file and mode of the covered packages of a public image; regenerate it
  with `go run ./tools/suidindex` (docker and network; `-check` compares)
  and never seed its package list from a guide's or benchmark's list of
  binaries — packages come from what the image ships, each with a reason in
  `sources.json`.

### Commands whose exit code is data

A collector never reads a command's exit code as success or failure alone. `rpm
-Va` exits 1 to say "something differs" and `dnf check-update` exits 100 to say
"updates are pending"; `needs-restarting -r` exits 1 for "reboot required";
`dpkg --verify` with no arguments exits 0 whatever it printed; `auditctl` exits
4 when the caller lacks CAP_AUDIT_CONTROL and 255 when the kernel refuses the
request. Classify in this order — timed out, could not start, then the codes and
messages the tool documents, then anything else as `error` naming the command
and the code — and write the verdict from the output, never from the code
alone. Record the timeout on the `Command` and the exit code in the envelope's
source (`Output.Source`).

## Tests

- Write the test that drives the caller before the test of the helper. After
  adding a call site, delete the call and confirm the suite goes red; if it
  stays green, the implementation is tested, not the feature.
- Assert something that differs when the feature is gone. Prefer structural
  assertions to substrings.
- Goldens: `go test ./internal/report -run TestJSON -update`,
  `-run TestTableGolden -update`, the facts golden above, and
  `go test ./internal/remedy -run 'TestScriptGolden|TestTableGolden|TestJSONGolden' -update`. Review every
  regenerated golden before committing it.
- A fixture must earn its place. `go test ./internal/controls -run
  TestEveryMutantIsKilled` mutates every control (operators flipped, expected
  values shifted, clauses and mechanisms removed, `absent_means` changed) and
  requires a fixture that answers differently for each mutant. A survivor is
  a missing fixture — add one, named for what it shows. Only a mutant no
  fixture can tell apart, because a collector invariant or a closed value
  vocabulary makes it equivalent, goes into `controls/testdata/_mutants.yaml`:
  one row, and a reason that names that invariant. The test fails on a row
  whose mutant is killed or is no longer generated.
- Every parser entry point in `internal/collect/collectors` and
  `internal/pkgfiles` has a `Fuzz<Name>` target seeded from the parser's own
  testdata, and `TestEveryParserHasAFuzzTarget` fails when a new function or
  method that takes `[]byte` has none (a helper reached only through a parent
  is declared in `coveredThrough`; bytes that are not host input, in
  `notParsers` with a reason). The profile and tuning parsers in
  `internal/profile` and `internal/tuning` have one each (`FuzzParseProfile`,
  `FuzzParseTuning`). Pull requests run the seeds only; the nightly `fuzz.yml`
  runs every target for a minute over four shards.
  `make fuzz TARGET=<name> TIME=<duration>` runs one locally, and
  `FUZZPKG=./internal/profile/` (or another package) picks a target outside
  the collectors. A crash lands as the corpus file Go
  writes under `testdata/fuzz/`, with the fix in its own commit.
- `MUSTER_ORACLE=1 go test ./internal/collect/collectors -run Oracle` (Linux,
  as root) compares the sshd, passwd/group, mountinfo and services parsers
  with `sshd -T`, `getent`, `findmnt` and `systemctl` on the host it runs on;
  CI runs it in the root job and inside the init containers. A mismatch is a
  parser defect or a daemon behaviour to record in the test, never a rule to
  loosen.
- `examples/` holds two snapshots the `examples.yml` workflow collects — an
  `ubuntu:24.04` container and the runner VM — rewritten so they carry no
  host identity, and `cmd/muster`'s example test checks them end to end.
  `make examples-fetch RUN=<id>` refreshes them from a workflow run; never
  replace them with a snapshot from a private host.
- CI runs the race build, the lint, the coverage check, a root collect on the
  runner VM, a non-root collect, the container matrix (Ubuntu 22.04/24.04,
  Rocky 9, AlmaLinux 9, Debian 12 as a canary), the read-only contract run,
  the daemon oracles, `sh -n` and shellcheck over the review scripts and
  `ci/roundtrip/*.sh`, the
  `fix-roundtrip` job (seeded failures repaired by the generated script in
  throwaway containers on Rocky 9, AlmaLinux 9, a Debian 12 init image built in
  the job and Ubuntu 22.04, and on the runner VM itself, which also proves the
  `beyond` controls a container cannot judge; on each init row a second container
  proves the guard run — a script planned in the first container is refused —
  and the failure run — every block's validate forced false must roll units,
  files, modes, sysctl values and modules back to what was recorded; the runner
  row has no guard run and re-seeds the same VM for its failure run), and the
  capability matrix
  (`docs/reference/capability-matrix.json`): facts that must be `denied`
  without root and `unsupported` without systemd.

## Documentation

English is canonical. The user-facing documents — the README, this page,
the design spec and every control's titles and descriptions — have a
`X.ko.md` (or `_ko`) pair updated in the same commit; `CHANGELOG.md`,
`CLAUDE.md`, the plans and the security/attribution notes are English-only.
Identifiers, flags and paths stay English on both sides. A change that
alters a verdict on an existing snapshot goes under **Controls** in the
changelog and bumps `controls/VERSION`.

## Commits and reviews

Commit under your own name and e-mail; the project keeps no organisation
identity. Keep a commit to one change with a subject that says what it does.
A pull request runs the whole CI matrix; a secret scan (`gitleaks`) runs over
every commit in the range, so a private hostname shape or an RFC 1918
address in a test fixture fails it — use the public example ranges.
