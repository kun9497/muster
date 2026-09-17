# Stage 3F — test hardening: mutants, fuzzers, oracles, examples

*English · [한국어](2026-09-17-stage3f-hardening-design.ko.md)*

This document is the design for plan 3F of muster: the four test subsystems the main design
(`2026-09-02-muster-design.md`, §11 "Parser oracles (stage 2)", "Stage 3", D21) reserved and
stage 2 parked to "test hardening" — mutation testing of the control YAML, native fuzzing of
every parser, daemon oracles for the parsers, and example snapshots captured from public
images. It is the second stage-3 sub-project (3A the walk is merged; 3F was agreed to run
before 3B). Decisions are numbered F-1 … F-12 and bind the plan. None of them changes what a
collector reads or how a control judges: 3F adds evidence that the existing behaviour is the
behaviour tested, and the only code it may change is a parser a fuzzer breaks or a control a
mutant proves wrong — each as its own commit, named in the CHANGELOG.

## 1. Goal and scope

Three questions the suite cannot answer today: does every fixture actually judge the clause
it sits beside (a fixture that passes for the wrong reason is invisible); does any parser
panic, loop or grow without bound on input the fixtures never showed it; do the parsers
agree with the daemons whose files they read. And one thing the README cannot show: what a
real snapshot and report look like. 3F answers each with the cheapest mechanism that cannot
go stale: a mutation test that runs with `go test` (F-1…F-4), one fuzz target per parser entry point (at least 30 targets — the F-5 table is the floor, the
F-6 inventory rule the ceiling: 26 in the collectors, 4 in `pkgfiles`, plus one for every
parser the inventory finds under another name)
with a committed corpus run nightly (F-5…F-7), an oracle test that runs in the CI jobs that already
have the daemons (F-8…F-10), and two committed example snapshots with their reports
(F-11…F-12).

Out of scope: gremlins or any Go-level mutation (the design reserves it for custom functions,
and no control uses one); Lynis (stage 4); property tests of the evaluator beyond what the
mutants prove; changing caps, budgets, keys or verdicts.

## 2. Mutation testing of the control YAML (F-1 … F-4)

**F-1 — A test, not a tool; the kill oracle is the fixture set.** `internal/controls/
mutation_test.go` holds `TestEveryMutantIsKilled`. For every control of the embedded set it
evaluates the control's fixtures (`controls/testdata/<id>/*.json`, through the same loader
and `check.Evaluate` the fixture harness uses) and records, per fixture, the observed
`(status, reason_code)`. It then generates the control's mutants in a fixed order (F-2), and
for each mutant re-evaluates every fixture. A mutant is **killed** when at least one fixture's
`(status, reason_code)` differs from the original's; it **survives** when every fixture
answers exactly as before. The comparison is against the original's *observed* result, not
against the fixture's expected prefix, so a fixture that reaches its status for a reason
unrelated to the mutated clause cannot count as a kill. Mutants are built in memory on a deep
copy of the decoded control; nothing is written under `controls/`. Every mutant is re-linted (`controls.Lint` with the registry and the custom-function
set the fixture harness uses); a mutant lint rejects (a collection op on a non-list fact, a
`not_matches` on a `list<string>`, a param default of the wrong type) is counted **invalid** and
skipped: it is not a judgment change a fixture could see. A mutant whose only differing
fixtures moved to `ERROR(internal_error)` is invalid too, not killed — the evaluator recovers
every panic into that status, so such a "kill" would prove nothing. The test reports the totals — generated, invalid, killed,
surviving, excluded — in its log line.

**F-2 — The mutation operators.** Each mutant changes exactly one thing and carries a
**signature** that names it, stable across runs and readable by a person; the signature
grammar is `<path> <operator>` where `<path>` is a JSON-pointer-like locator into the control
(`checks[1]`, `checks[0].where`, `mechanisms[2].when[0]`, `mechanisms[1].checks[0].require`,
`applies_when[0]`, `params.allowed`, `absent_means`) and `<operator>` one of the rows below.

| Family (design §11) | Operator | Applies to |
|---|---|---|
| operator flip | `op eq->ne`, `op ne->eq`, `op in->not_in`, `op not_in->in`, `op lt->gte`, `op lte->gt`, `op gt->lte`, `op gte->lt`, `op matches->not_matches`, `op not_matches->matches`, `op contains->not_contains`, `op not_contains->contains`, `op present->absent`, `op absent->present` | every clause and every `where`/`require` sub-clause |
| operator flip | `op each->none` | an `each` clause that has a `where` (the `none` keeps that `where`; its `require` is dropped); `none->each` is never valid — an `each` needs `require`, which a `none` never has — and is not generated |
| expected substitution | `expected not` (bool), `expected +1`, `expected -1` (int), `expected "__mutant__"` (string), `expected drop[i]` (one element of a list), `expected []` (empty list) | a literal `expected`; a `${param}` reference is mutated through the parameter's `default` with the same rows, generated **once per parameter** (not per referencing clause), signature `params.<name>.default …` |
| clause removal | `remove` | each clause of `checks`, of a mechanism's `checks`, when that list has more than one clause |
| condition removal | `remove` | each `applies_when` clause; each mechanism `when` clause; a whole mechanism when the control has more than one |
| condition removal | `absent_means -><value>` | the three other values of `absent_means` |

`on`, `persona` and `subject` are not mutated (the persona set and the subject key are
structural, not judgments). Every operator is generated for every site it applies to; each
signature names one site and one change, so two mutants never coincide. Mutants are built on
a deep copy made by re-encoding the decoded control to YAML and decoding it again through the
strict loader, so a mutant is exactly what the loader would have accepted from a file.

*Cost and the `absent_means` rows.* Roughly 350 clauses, 300 expected values, the removals
and 64 judgment controls × 3 `absent_means` values give about 1,100 mutants; still seconds.
An `absent_means` mutant is killed only by a fixture in which every judged fact is absent, so
every judgment control gains one such fixture where the layout is reachable (its prefix follows
the control's `absent_means`: `manual-`, `na-` or `pass-`); for the five walk-based controls
the walk gate answers before `absent_means`, so the reachable shape is `walk.complete` ok
true with the judged list absent (the `manual-no-package-db` fixtures already have it), and a
control whose absent shape is unreachable by design lists its three `absent_means` mutants as
one exclusion class with that reason.

**F-3 — Exclusions.** A surviving mutant passes only if `controls/testdata/_mutants.yaml`
lists it: `- {control: muster.x.y, mutant: "checks[0].where expected +1", reason: …}`, strict
YAML. The reason must say why no fixture can tell the mutant apart (an *equivalent* mutant —
`lte 3` versus `lt 4` when every fixture value is an integer — or a distribution condition
whose two sides no fixture pair exercises *by design*). An exclusion whose mutant is in fact
killed, or names a mutant that is not generated, fails the test — exclusions cannot rot. The
target is a 100 % kill rate with an exclusion list a reviewer can read in one sitting; a
mutant that survives because a fixture is missing is fixed by adding the fixture, never by an
exclusion. Exclusions are per control and per signature, never wildcards.

**F-4 — Output and cost.** On failure the test prints one line per surviving mutant —
`muster.file.suid_sgid checks[0].require op eq->ne: 12 fixtures unchanged` — and, for
exclusions that no longer hold, `excluded mutant … is now killed by <fixture>`. The whole
test evaluates roughly 68 controls × 10–20 mutants × 6 fixtures; it runs in the ordinary
`go test ./internal/controls/` (seconds) and needs no flag. The first run of the test is part
of plan 3F: every surviving mutant is examined, fixtures are added where a clause was
unjudged, and the exclusion list that remains is reviewed row by row before the plan closes.

## 3. Native fuzzing of the parsers (F-5 … F-7)

**F-5 — One target per parser entry point.** `internal/collect/collectors/fuzz_test.go`
(Linux build tag, like the package) and `internal/pkgfiles/fuzz_test.go` (cross-platform)
carry `Fuzz<Name>` targets. The entry points are the `parse*` functions a collector calls
with host data; helpers that only their parent calls (`parseNftRule`, `parseIptablesRule`,
`parseAptInstLine`, `parseRsyslogAction`, `parseRsyslogActionCall`, `parseProcAddr`,
`parseKVInto`) are covered through the parent and named as such in the coverage table of
F-6. Targets and adapters:

| Target | Calls | Adapter |
|---|---|---|
| `FuzzParsePasswd`, `FuzzParseGroup`, `FuzzParseShadow` | the three account parsers | `[]byte` |
| `FuzzParseSubIDs` | `parseSubIDs(data, known)` | `known` answers true for `alice`, false otherwise |
| `FuzzParseMountinfo` | `parseMountinfo` | `[]byte` |
| `FuzzParseDpkgStatus`, `FuzzParseAptSimulation`, `FuzzParseDnfCheckUpdate`, `FuzzParseRpmQa` | the patch parsers | `[]byte` |
| `FuzzParseProcNet` | `parseProcNet(data, "tcp")` and `"tcp6"` | both protocols per input |
| `FuzzParseDaemonDump` | `parseDaemonDump` | `[]byte` |
| `FuzzParseSshdConfig` | `parseSshdConfig(a, "/etc/ssh/sshd_config", kw, 0)` once per keyword of `sshdOptions` | a small in-memory `Access` (`memAccess`, new in the test file: a `map[path][]byte` behind `ReadFile`/`Stat`/`Glob`, `NoWalkAccess` embedded) serving the input as the main file and as every `Include` match, so an `Include` loop is exercised |
| `FuzzParsePAMFile` | `parsePAMFile(data, "sshd", "/etc/pam.d/sshd")` | `[]byte` |
| `FuzzParseKV`, `FuzzParseDropin` | `parseKV`, `parseDropin(data, map)` | fresh map per call |
| `FuzzParseShellFile` | `parseShellFile(data, "/etc/profile")` | `[]byte` |
| `FuzzParseNftRuleset`, `FuzzParseIptablesSave` | the firewall parsers | `string(data)`; iptables for the families `v4` and `v6` |
| `FuzzParseVsftpdInto`, `FuzzParsePureFtpdInto`, `FuzzParsePostfixInto` | the `*Into` ftp and mail parsers | fresh map per call |
| `FuzzParsePamListfiles`, `FuzzParseSendmailPrivacy` | `parsePamListfiles(data)`, `parseSendmailPrivacy(data)` | `[]byte` |
| `FuzzParseRsyslogSelector` | `parseRsyslogSelector(string)` and the action parsers on the same input | one input, three calls |
| `FuzzParseExportsContent`, `FuzzParseChronySources` | nfs and timesync | `[]byte` |
| `FuzzParseRPMFileLine`, `FuzzParseTarTV`, `FuzzParseStatLine`, `FuzzCanonicalUsr` | the exported `internal/pkgfiles` parsers | `string(data)`; `CanonicalUsr` with a six-entry table the target builds (`/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/libx32` → `/usr/…`) |

Each target's body checks three properties and nothing about meaning: **no panic** (the
fuzzer's own rule — a recovered panic is a failure with the input); **determinism** — the
parser is called twice on the same input and the results are `reflect.DeepEqual` (a map
adapter compares the maps); **bounded output** — every field the parser fills through `sourceRaw` is
at most `rawCap` bytes long (fields that copy a token verbatim — an account name, a mount
point — are bounded by the input and not capped), and every list the parser returns has at
most as many elements as the input has bytes (a parser that fabricates rows is a bug; a
parser that splits a line into several statements or records stays under this bound). The
seed corpus is registered with `f.Add` from a per-target list of `testdata/` globs written in
the fuzz file — the plan fills each list from the files the parser's unit tests read — so
the seeds are the fixtures the tests know, and Go runs them as ordinary unit tests under
`go test` (that is the pull-request regression).

**F-6 — Corpus and completeness.** Inputs the fuzzer finds are written by Go under
`testdata/fuzz/Fuzz<Name>/` in its native format; a nightly failure uploads that directory as
an artifact and the maintainer commits the file, which turns the crash into a regression the
pull-request suite runs. `TestEveryParserHasAFuzzTarget` (same package) parses the package's own
sources with `go/ast` and lists every top-level function whose first parameter is `[]byte`, or
`string` named `content`, `line`, `sel` or `act` — the name prefix `parse` is not the rule,
because `nssSources`, `decodeACL`, `dnsTokenize`, `rsyslogLogicalLines`, `rpmFileTable` and a
dozen others parse host bytes under other names; each such function must be the callee of a
`Fuzz<Name>` target or a row of a `coveredThrough` table naming the parent that covers it; a
new parser without either fails the test.

**F-7 — Where it runs.** A new workflow `.github/workflows/fuzz.yml` — `schedule` once a day
and `workflow_dispatch` — on `ubuntu-24.04`, a four-shard matrix; each shard runs, for its
share of the target list, `go test -run '^$' -fuzz '^Fuzz<Name>$' -fuzztime 60s
./internal/collect/collectors/` (the `pkgfiles` targets take part in the same split), about
twelve minutes per shard with fifty targets; a failing target uploads `testdata/fuzz/` and fails
the job. The shard assignment is computed, not committed: each shard runs `go test -list '^Fuzz' ./...` and takes the
targets whose index modulo four is its own, so a new target joins the rotation by existing.
`make fuzz TARGET=<name> TIME=<duration>` runs one target locally with the same flags. The
pull-request workflow gains nothing: the seed corpus already runs inside `go test ./...`. This
amends the main design's §11 sentence "thirty seconds per parser on pull requests": the
pull-request budget is the seed corpus, the nightly run is the fuzzing (recorded in §6).

## 4. Parser oracles (F-8 … F-10)

**F-8 — Four pairs, compared on the machine that runs them.** `internal/collect/collectors/
oracle_test.go` (Linux) skips unless `MUSTER_ORACLE=1`. It reads the host through
`collect.Host()` under `collect.Guard` with the collector's own declaration, runs the oracle
command through `collect.RunCommand` (absolute path, no shell, a timeout and an output cap)
inside the test, and compares:

| Parser | Oracle | Rule |
|---|---|---|
| `parseSshdConfig` on `/etc/ssh/sshd_config`, once per keyword of `sshdOptions` (the parse path, called directly so `-G`/`-T` are not consulted) | `sshd -T` as root | for every keyword the parser resolved to a value, `-T` carries the same keyword with the same value after an alias map the test owns (`without-password` and `prohibit-password` fold to one token on both sides, because `sshd -T` prints `without-password` for either spelling; an unset `banner` → `none`; case folded); keywords the file did not set are not compared (defaults are the daemon's) |
| `parsePasswd`, `parseGroup` on `/etc/passwd`, `/etc/group` | `getent passwd`, `getent group` | every parser row `(name, uid, gid, home, shell)` / `(name, gid, members)` appears in `getent`'s output with the same values (members compared after the parser's trim and de-duplication); a `getent`-only row must carry an id in the systemd dynamic range 61184–65519 (Ubuntu 24.04 and EL9 ship `passwd: files systemd`) — anything else is a mismatch |
| `parseMountinfo` on `/proc/self/mountinfo` | `findmnt -A -J -o ID,FSTYPE,TARGET` (`-A` keeps every mountinfo row; without it findmnt de-duplicates) | the sets of `(id, fstype, target)` are equal after flattening `findmnt`'s nested `children` and the same octal unescaping |
| `services.<name>.enabled` and `.active` for every row of the services table (the collector's facts are per logical service, an OR over the row's units) | `systemctl show -p LoadState,ActiveState,UnitFileState,SubState <unit>` for each of the row's units | `enabled` equals the OR of `enabledFromUnitFile(state, active)` over the row's units (the collector's own function, reused); `active` is compared only for rows with no `ports` and no super-server names (for the others the collector also counts a reachable port or an inetd entry, which the oracle does not see) |

A mismatch fails naming the pair, the key and both values. A pair whose oracle binary is
absent (`sshd` in a container without openssh) skips with the binary's name; the test's
summary line says how many pairs ran.

**F-9 — Where it runs.** The root job on the runner VM runs
`sudo env PATH="$PATH" GOFLAGS="$GOFLAGS" MUSTER_ORACLE=1 go test ./internal/collect/collectors/ -run Oracle -count=1`
(the existing sudo-run step's shape) and asserts zero skips (the runner has `sshd`, `getent`,
`findmnt`, `systemctl`). The init containers (Rocky, Alma) have no Go toolchain, so the runner
builds the test binary once, statically (`CGO_ENABLED=0 go test -c ./internal/collect/collectors/
-o bin/collectors.test`), and the container step runs it from the `bin` mount the matrix already
has (`/m/collectors.test -test.run Oracle` with `MUSTER_ORACLE=1`; the test reads no `testdata`); there the sshd pair skips unless the image
ships `sshd`, and the log records which pairs ran. The non-init containers do not run it
(no systemd, no daemon to be an oracle).

**F-10 — Seed corpora from the images' real files.** A four-line shell step, not test code:
after the oracle step, the root job and each init container copy `/etc/ssh/sshd_config`
(plus `/etc/ssh/sshd_config.d/*`), `/etc/passwd`, `/etc/group` and `/proc/self/mountinfo` into
an artifact `seeds-<image>`; the maintainer converts them once into Go's corpus format under
`testdata/fuzz/Fuzz<Name>/` and commits (design §11: "seed corpora taken from the CI images'
real files"). The files carry no secret — account names of a public image, mount tables of a
runner — and the shadow file is never copied. The step is not gated and runs on the four
files only.

## 5. Example snapshots (F-11 … F-12)

**F-11 — Files.** `examples/` holds `ubuntu-24.04-container.json` (collected inside the
`ubuntu:24.04` container: overlay root, the walk lists `unsupported`),
`ubuntu-24.04-vm.json` (collected on the runner VM with `--deep` and the same exclusions the
root job uses, so the walk lists carry real rows), each one's `…-report.json` and
`…-report.txt` (`check --format json` / the table), and `examples/README.md` saying where
each came from, the exact commands, the run id, and that no file here comes from anyone's
host. The snapshot headers already carry the provenance (`muster_version`, `commit`,
`collected_at`, `host.os_release`). Before `check` runs, the workflow rewrites two things in
each snapshot with `jq` so no host-shaped literal is committed: `run.host.hostname` becomes
`github-runner` / `ubuntu-container`, and every non-loopback, non-wildcard `addr` in the
`sockets.*` records becomes `192.0.2.1` (an RFC 5737 address); `run.host.boot_id` (the raw boot UUID), `run.host.kernel`
and `run.host.uptime_s` are blanked (they identify the runner's kernel, not the image);
`machine_id_hash` is a hash and stays. The reports are generated from the rewritten files. An example
over 4 MiB is refused by the workflow (the VM's walk lists sit under their caps after the root
job's exclusions).

**F-12 — Generation and the test.** A new workflow `.github/workflows/examples.yml`
(`workflow_dispatch` only) builds the binary, collects both snapshots and both reports, and
uploads them as the artifact `examples-<run id>`; `make examples-fetch RUN=<id>` downloads
it with `gh run download` into `examples/`, and a person commits. `cmd/muster/examples_test.go`
loads each committed snapshot, runs `check` against the embedded set, asserts no result is
`ERROR(internal_error)`, and regenerates both reports in memory: the JSON report must equal
the committed one byte for byte after masking the `check` block's `muster_version`, `commit`,
`controls_version` and `controls_digest` (the in-process test fills `dev`/`none`), and the
table likewise after masking its first header line — the same-input-same-bytes contract on a
real snapshot. Staleness is not gated: an example collected with an older `controls_version`
still passes as long as it loads and evaluates. Both READMEs gain an "Example output"
paragraph pointing at the files.

## 6. What changes elsewhere

- `internal/controls/mutation_test.go`, `controls/testdata/_mutants.yaml`; new fixtures
  wherever a mutant survived for want of one.
- `internal/collect/collectors/fuzz_test.go` (with `memAccess`), `oracle_test.go`,
  `testdata/fuzz/**`; `internal/pkgfiles/fuzz_test.go`.
- `.github/workflows/fuzz.yml`, `examples.yml`; `ci.yml`: the oracle step in `collect-root`,
  the static test binary run in the init containers, the seed-file artifact steps.
- `Makefile`: `fuzz`, `examples-fetch`. `examples/` (five files).
- `CONTRIBUTING.md`/`.ko.md`: a fixture must kill the mutants of its clause, a surviving
  mutant is an exclusion with a reason; a new parser needs a fuzz target, seeds and a shard
  line; how examples are refreshed. `CLAUDE.md` Tests: two lines. `CHANGELOG.md` under
  Tooling. The main design's §11 "Stage 3" sentence marks the four as 3F and is amended: fuzzing runs
  nightly with the seed corpus as the pull-request regression (F-7), not thirty seconds per
  parser on every pull request. `controls/VERSION`
  is bumped only if a control changes (a fixture-only change keeps it).

## 7. Errors and degradation

- Nothing in 3F changes a collector's reads, a key, a cap or a verdict. A parser a fuzzer
  breaks is fixed in its own commit with the crashing input committed as a seed; a control a
  mutant proves wrong is fixed in its own commit with a CHANGELOG line and a VERSION bump.
- The mutation test never writes under `controls/`; a mutant that only turns fixtures into
  `ERROR(internal_error)` is invalid, never a kill (F-1).
- The oracle test is off by default (`MUSTER_ORACLE` unset → skip); it never runs on a
  developer's machine unasked and never on the lab host from a checkout.
- The examples workflow runs only on demand; the committed examples are refreshed by a person.

## 8. Testing and success criteria

- Mutants: 100 % killed, exclusions reviewed row by row in the plan's execution notes; the
  test runs in seconds in the ordinary suite.
- Fuzzing: every entry-point parser has a target and seeds (`TestEveryParserHasAFuzzTarget`
  green); the first nightly run is triggered by hand on the branch (`workflow_dispatch`) and
  its findings — crashes or none — are recorded; a crash is a fix commit plus a committed seed.
- Oracles: the runner job runs all four pairs with zero skips; the init containers run the
  three pairs that have a binary; mismatches found on the first run are recorded and either
  fixed as parser bugs (own commit) or shown to be normalisation gaps fixed in the test.
- Examples: two snapshots and their reports committed from a `workflow_dispatch` run;
  `TestExamplesLoadAndCheck` green; the README pair points at them.
- Every gate of CLAUDE.md stays green; no hostname, address, alias or organisation name in any
  file (the examples' hostname and socket addresses are rewritten, F-11); nothing captured
  from the lab host is committed.
