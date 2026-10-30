# Stage 3D-3 — `snapshot anonymize` and `--max-age` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `check`/`fix --max-age` refuse a stale snapshot before evaluation, and `muster snapshot anonymize` writes a
keyed-pseudonym copy of a snapshot whose verdicts under the built-in profiles equal the original's.

**Architecture:** `--max-age` is a duration parser, a strict `collected_at` reader and one clock reading in
`cmd/muster`, recorded as `max_age_s` in the check and fix blocks. Anonymisation is a pure package
`internal/anonymize` (key, pseudonym classes, address map, path map, a classification table over every document path,
placeholders, sort specs) driven by a `cmd/muster` command that decodes the whole document with `json.Number`,
transforms the tree and writes it in collect's encoding; `facts.Run` gains `anonymization`, which reports and plans
carry.

**Tech Stack:** Go standard library only (`crypto/hmac`, `crypto/sha256`, `crypto/rand`, `encoding/base32`,
`encoding/base64`, `net/netip`), `encoding/json` with `UseNumber`.

**Spec:** `docs/superpowers/specs/2026-10-30-stage3d3-anonymize-maxage-design.md` (AX-1..AX-14, §1.1, §2–§6). Read it
whole before any task; every task cites the AX it implements.

## Global Constraints

- No new dependency (D28); `go.mod` unchanged.
- `internal/anonymize` imports no `os`, `os/exec`, `net`, `syscall` and no `internal/collect` (test enforced);
  `internal/check`, `internal/remedy`, `internal/report` stay free of `time` (existing tests).
- Same input, same key, same bytes; no `map` iteration reaches output unsorted.
- Exit codes unchanged except the new refusals, all exit 2 with nothing on stdout.
- Without `--max-age`, `check`/`fix` output is byte-identical to today (goldens and examples unchanged).
- Every `[]byte`-taking function has a `Fuzz<Name>` target; `.github/workflows/fuzz.yml` gains each new package line.
- Test before call site, caller first; delete the call and see red (CLAUDE.md).
- Docs English canonical with `.ko.md` pairs in the same commit; the main design pair stays line-aligned (636 lines
  at base).
- Commits: personal identity; end messages with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`; never
  push, stash, amend, rebase or force.

## Review Focus

1. A snapshot whose `collected_at` has an offset or fractions (`2026-10-30T10:00:00+09:00`, `…00.5Z`): under
   `--max-age` it is refused as unusable, never parsed leniently — test in Task 1.
2. A user named like a path component (`log`, `tmp`, `var`) or like an enum value (`none`, `aide`): no mount target and
   no enum changes — tests in Tasks 4 and 8.
3. A snapshot from a newer muster with an extra record field: refused with the upgrade message, nothing written —
   test in Task 6.
4. A fixture (`synthetic: true`, `run: {}`): anonymised output keeps `synthetic`, `_expect`, `_provenance` and the empty
   `run` exactly — test in Task 6.
5. An account name that is also a host label (`runner` and host `github-runner`): each maps by its own class, no
   cross-rewrite — test in Task 4.

---

### Task 1: `--max-age` on `check` and `fix`

**Files:**
- Create: `cmd/muster/maxage.go`, `cmd/muster/maxage_test.go`
- Modify: `cmd/muster/check.go` (flags, usage, `runCheck` order, waiver `now`), `cmd/muster/fix.go` (flags,
  `fixValueFlags`, usage, `runFix`), `internal/report/report.go` (`CheckBlock.MaxAgeS int64 json:"max_age_s,omitempty"`
  as the last field), `internal/remedy/plan.go` (`FixBlock.MaxAgeS` last field), the check/fix block builders

**Interfaces:**
- Produces: `func parseMaxAge(s string) (int64, error)`; `func parseCollectedAt(s string) (time.Time, error)`; `var
  now = func() time.Time { return time.Now() }` in `cmd/muster`; `func checkAge(collectedAt string, maxAge int64, now
  time.Time) error` returning the exact messages of AX-13/AX-14.

- [ ] **Step 1: Write the failing tests** — `TestParseMaxAge` (table: `7d`=604800, `2w`, `1d12h`=129600, `90m`, `1s`;
  refused: ``, `0s`, `-1d`, `1.5d`, `500ms`, `12h1d` (order), `1d1d` (repeat), `101y`/`5300w` beyond 100 years, `d`);
  `TestParseCollectedAt` (accepts only `YYYY-MM-DDTHH:MM:SSZ` round-trip equal; refuses offset, fraction, empty, lower
  case `z`); `TestCheckAge` (inclusive bound; 5 min future → ok with age 0; 5 min 1 s future → refused; empty →
  "no usable collected_at; cannot judge --max-age"); CLI tests `TestCheckMaxAgeRefusesStale` and
  `TestFixMaxAgeRefusesStale` (pinned `now`; exit 2; stdout empty; stderr exact `muster: snapshot collected at <ts> is
  <age> old, older than --max-age <d>`; refusal before a broken `--profile` file; `--allow-error` and `--fail-on none`
  do not lift it); `TestMaxAgeRecordedInBlocks` (`check.max_age_s` and `fix.max_age_s` equal the parsed seconds; absent
  without the flag); `TestFixValueFlagsMatchParser` (every value flag the parser takes is in `fixValueFlags`); the
  existing goldens unchanged.
- [ ] **Step 2: Run** `go test ./cmd/muster/ -run 'MaxAge|CollectedAt|CheckAge|FixValueFlags'` — FAIL.
- [ ] **Step 3: Implement**; `<age>` renders as the largest units, `w` down to `s`, in the grammar's own spelling;
  waiver expiry uses the same `now()` reading (one call per command).
- [ ] **Step 4: Run** `go test ./... && go vet ./...` — PASS; goldens and examples unchanged.
- [ ] **Step 5: Commit** `check, fix: --max-age refuses a stale snapshot before evaluation (AX-13, AX-14)`.

**Pre-flight additions (binding):** the `--max-age` messages, all exact: stale `muster: snapshot collected at <ts> is
<age> old, older than --max-age <d>`; future `muster: snapshot collected at <ts> is in the future (more than 5m ahead
of this clock); cannot judge --max-age`; unusable `muster: no usable collected_at; cannot judge --max-age`. `<age>` is
the full decomposition with zero terms omitted (8d2h → `1w1d2h`; 0 s → `0s`); `<d>` echoes the flag value as given. The
bound is at most 100×365 days = 3,153,600,000 s inclusive (test `5214w` accepted, `5215w` refused; `101y` is an
unknown-unit case; overflowing digits refused). `now()` is read once per command, truncated to the second and
converted to UTC, and that one value goes to `waiver.Apply` and `checkAge`. `remedy.Build` copies `max_age_s` from
its input into `FixBlock.MaxAgeS` (a test in `internal/remedy` pins it).

### Task 2: `internal/anonymize` — key, classes, keep set, injectivity

**Files:**
- Create: `internal/anonymize/key.go`, `classes.go`, `keep.go`, `*_test.go`, `imports_test.go`, `fuzz_test.go`
- Modify: `.github/workflows/fuzz.yml` (the `anonymize=` line)

**Interfaces:**
- Produces: `type Key struct{...}`; `func NewKey(raw []byte) (*Key, error)` (exactly 32 bytes); `func (k *Key)
  ID() string` (16 hex of `HMAC(k, "muster/anon/v1/key-id")`); `func (k *Key) Account(name string) string`, `Host(name
  string) string`, `Fingerprint(fp string) string`, `MachineIDHash(h string) string`; `func Kept(name string) bool`
  (the closed list, `KeepSetVersion = "v1"`); `type Ledger struct{...}` recording every (class, input → output) with
  `func (l *Ledger) Note(class, in, out string) error` refusing a collision (AX-9); `""` maps to `""` everywhere.

- [ ] **Step 1: Write the failing tests** — deterministic per key and differing across keys; account `u`+12 lower base32;
  sigils kept (`%admins` → `%u…`, `+@ng` …, `#1001` kept, `#x` mapped); host case-folded label-wise, last label kept,
  single label mapped whole, trailing dot kept; fingerprint `SHA256:`+43 base64; machine-id 64 lower hex; `Kept` for
  `root`, `ftp`, `lp`, `uucp`, `nuucp`, `adm`, `syslog`, `utmp`, `wheel`, `sudo`, `admin`, `ALL`, `*`, not for `toor`;
  `Ledger` refuses two inputs to one output and a mapped value equal to a kept one; `TestAnonymizeImportsNoHostPackages`;
  `FuzzHost`, `FuzzAccount` seeds.
- [ ] **Step 2: Run** `go test ./internal/anonymize/` — FAIL.
- [ ] **Step 3: Implement** (sub-key per class `HMAC(key, "muster/anon/v1/<class>")`).
- [ ] **Step 4: Run** — PASS; add the fuzz.yml line.
- [ ] **Step 5: Commit** `anonymize: keyed pseudonyms per class, the closed keep set and the collision ledger (AX-2..AX-5, AX-9)`.

**Pre-flight additions (binding):** the class constants are `ClassAccount = "account"`, `ClassHost = "host"`,
`ClassAddress = "address"`, `ClassURL = "url"`, `ClassFingerprint = "fingerprint"`, `ClassMachineID =
"machine_id_hash"`, `ClassPath = "path"` (the AX-10 tokens), plus `ClassHostOrAddr`, `ClassPlaceholder`, `ClassBlank`
(a string becomes `""`, a number `0`, presence kept; its paths enter `replaced`), `ClassKept`, `ClassGrammar`; `func
Kept(name string) bool` keeps its name. `Ledger.Note(field, class, in, out string)` takes the field path so a collision
with another class's output in the same field is caught. Tests add: sigils `-name` and `@ng`; keeping wins across
classes (user `admin` and group `admin` both kept); `Ledger` refuses another class's equal output in one field.
`fuzz.yml`: add `anonymize=$(go test -list '^Fuzz' ./internal/anonymize/ | grep '^Fuzz')` and append `echo
"$anonymize" | sed 's#^#./internal/anonymize/ #'` to the `targets=` group. Canary and test addresses in RFC 1918 or
public space are built in Go from octets at test time, never written as dotted literals in a committed file
(`.gitleaks.toml` would flag them); host canaries use non-matching suffixes, URL users `@example.org`.

### Task 3: Addresses (§1.1)

**Files:** Create `internal/anonymize/addr.go`, `addr_test.go`; extend `fuzz_test.go`.

**Interfaces:**
- Produces: `func (k *Key) Addr(a netip.Addr) netip.Addr`; `func (k *Key) Prefix(p netip.Prefix) netip.Prefix`; `func
  (k *Key) AddrToken(s string) (string, bool)` parsing every §1.1 form (address, CIDR, dotted netmask, `addr:port`,
  `[v6]:port`, transport prefix, zone, range, nft set) and reporting whether it matched.

- [ ] **Step 1: Write the failing tests** — every kept range returns itself; every in-range address stays in its range
  and the map is injective over a sampled /16 and over all of `10.0.0.0/24`; public addresses stay public (none land in
  any listed range) over a 2^20 sample; prefix preservation (two addresses sharing an n-bit prefix map to outputs
  sharing it) for public and in-range; CIDR containment (mapped network contains every mapped host) for public and
  in-range; `::ffff:a.b.c.d` and `64:ff9b::a.b.c.d` map their IPv4 part; zone kept; netmask form; range ends mapped;
  nft set elements; a CIDR with host bits set keeps its length; a non-address token returns false. `FuzzAddrToken`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** Crypto-PAn with the class sub-key as PRF (bit i flipped by the low bit of
  `HMAC(sub, prefix_i)`); in-range: keep the range prefix bits, map the rest; public: the fixed-bit tree — keep bit i
  when the current prefix is a proper ancestor of any kept or in-range block (a precomputed boundary set per family),
  else flip by the PRF.
- [ ] **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `anonymize: class-keeping, prefix-preserving address map (§1.1)`.

**Pre-flight additions (binding):** tests add `addr:port`, `[v6]:port` and each transport prefix; addresses built from
octets in Go (no dotted literals of RFC 1918 or public space in committed files).

### Task 4: Paths, read-text grammars, placeholders, the walker

**Files:** Create `internal/anonymize/path.go`, `text.go`, `walk.go`, `table.go` (the schema of the table, not its
contents), tests.

**Interfaces:**
- Consumes: Tasks 2–3.
- Produces: `type Class string` with constants `Account, Host, HostOrAddr, Addr, URL, Fingerprint, MachineID, Path,
  Placeholder, Kept, Grammar` and the sort-spec type; `type FieldRule struct{ Class Class; Grammar string; Sort
  *SortSpec; Order string }`; `type Table map[string]FieldRule` keyed by document path (`run.host.hostname`,
  `facts.<key>.value`, `facts.<key>.value[].<field>`, envelope fields `facts.<key>.reason` …); `func Transform(doc
  map[string]any, t Table, k *Key, mode string) (map[string]any, Report, error)` (pure): first pass collects account
  names; second rewrites; returns `Report{Classes, Replaced []string}` for `run.anonymization`; `func (k *Key)
  MapPath(p string, homes Homes) string` (AX-6, one function); grammars `"whitespace"` (hosts.equiv, securetty lines).

- [ ] **Step 1: Write the failing tests** on a hand-built table and document: AX-6 every position and every exception
  (`/tmp` home, mount target, `/home/lost+found` mapped, nested and shared homes, sudoers.d/cron.d base names, never by
  component equality elsewhere — a user `log` leaves `/var/log` alone); a user `none` leaves an enum `none` alone;
  account `runner` and host `github-runner` map independently; placeholder keeps absent/`""`/present; read-text
  `hosts.equiv` line `+ alice` → `+ u…` with `^\+` intact; host-or-address ordered dispatch (address form, host form,
  else placeholder); url class; sorted list re-sorted by its spec, ordered list kept; unknown path → error naming it;
  `Report` lists sorted `classes` and `replaced` paths in the AX-10 spelling.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `anonymize: path positions, read-text grammars, placeholders and the document walker (AX-6..AX-8)`.

**Pre-flight additions (binding):**
- Table spelling: one rule per (registry key, value-relative field path), written `<key>` for a scalar value,
  `<key>[]` for a list element, `<key>[].<field>` (nested: `<key>[].<field>[].<sub>`) for records; plus one generic
  envelope rule set and one generic `Source` rule set. Transform applies a key's value rule to `value` on every side
  of a setting (`runtime`, `persisted`, `effective`) and on every `personas.<p>` entry (persona names kept — the closed
  set from sshd's `personaOrder`), and applies the `Source` rules (`path` → path, `raw`/`cmd` → placeholder, `line`,
  `exit_code`, `kind` → kept) to `source`, `winner` and every `inputs[]` at any depth. `replaced` spells positions as
  document paths: `facts.<key>.runtime.reason`, `facts.<key>.personas.<p>.source.raw`,
  `facts.<key>.source.inputs[].inputs[].raw`, `facts.<key>.value[].<field>`.
- A read-text grammar is positional: `Grammar{Split: "whitespace", Tokens: []Class{…}, Rest: Class}`; a bare `+` or
  `-` is kept, `+name`/`-name` keep the sigil and map the name, `@ng` maps by the account rule. `hosts.equiv` lines:
  `Tokens: [HostOrNetgroup, Account]`, `Rest: Kept`; securetty: `Tokens: [Kept]`. Tests: `alice-host bob`, `+@ng -bob`,
  a bare `+`.
- AX-6's control-named mount targets are a closed list in `internal/anonymize` (`/tmp`, `/var`, `/var/tmp`, `/var/log`,
  `/var/log/audit`, `/home`, `/dev/shm`, `/boot` …), pinned by Task 7's test against the control set;
  `internal/anonymize` never imports `internal/controls`. `FieldRule` gains `Home bool`, marking the fields `Homes` is
  built from (`accounts.users[].home` …).
- Test for `firewall.raw_dumps[].content`, `run.host.boot_id` and `run.host.uptime_s` → `ClassBlank`.

### Task 5: The classification table

This is the data task: every document path classified. Use the strongest model.

**Files:** Create `internal/anonymize/table_data.go` (or an embedded `table.yaml` decoded strictly, the
implementer's choice, stated in the commit), `internal/anonymize/table_test.go`; create
`internal/collect/collectors/anonymize_table_test.go` (Linux tag).

**Interfaces:** Produces `var Default Table` and `const TableVersion`.

- [ ] **Step 1: Write the failing tests** — `TestEveryRegistryKeyIsClassified` (`facts.LoadRegistry()` keys ⊆ table);
  `TestEveryCorpusFieldIsClassified` (walk every corpus snapshot of spec §4; every path seen ⊆ table);
  `TestHeaderAndEnvelopeReflection` (`facts.Run`, `facts.Envelope`, `facts.Setting` json fields ⊆ table);
  `TestReadByValueIsNeverPlaceholder` (every (key, field) a clause, `applies_when` or mechanism `when` reads with a
  value op — parse controls with `controls.LoadDefault()` — is not `Placeholder`); in the collectors package (Linux):
  `TestEmittedRecordsAreClassified` (run the collectors' existing unit-test record builders through the table) and
  `TestSortSpecsMatchCollectors` (each sorted list's collector output is already sorted under its spec).
- [ ] **Step 2: Run** — FAIL listing unclassified paths.
- [ ] **Step 3: Fill the table** from the scope report `scope-identifiers.md` (in the cycle workspace) and the
  collectors' code, every list's order and sort spec from the collector's `sort` call.
- [ ] **Step 4: Run** `go test ./internal/anonymize/ ./internal/collect/...` (Linux tests on the lab) — PASS.
- [ ] **Step 5: Commit** `anonymize: classify every header, envelope, key and record path (AX-8)`.

**Pre-flight additions (binding):**
- `TestEmittedRecordsAreClassified` mechanism: a test-only recorder in the collectors package — the existing test
  helpers that build a collector's output (`build()`/`buildOn()` or the Builder they wrap) append each finished tree,
  marshalled to JSON, to a package-level slice; a `TestMain` in the Linux-tagged file runs `m.Run()`, then checks every
  recorded path against `anonymize.Default` and every sorted list against its spec, and fails listing the gaps. Name
  the helpers in the commit.
- `TestReadByValueIsNeverPlaceholder` and any test reading the control set live in an external test package
  (`package anonymize_test`) so `internal/anonymize` never imports `internal/controls`.
- `_notes` (fixture top level) → `ClassPlaceholder`, with a test.

### Task 6: `muster snapshot anonymize` and the header record

**Files:** Create `cmd/muster/anonymize.go`, `cmd/muster/anonymize_test.go`; modify `cmd/muster/snapshot.go`
(dispatch, usage), `internal/facts/snapshot.go` (`Run.Anonymization *Anonymization json:"anonymization,omitempty"`
with `Scheme, Mode, KeyID, KeepSet string; Classes, Replaced []string`), `internal/facts` schema golden (regenerated
for an additive run-header field; see the additions below).

**Interfaces:** Consumes `anonymize.Transform`, `anonymize.Default`, `trustedFile`, `openFacts` (as the schema gate).

- [ ] **Step 1: Write the failing tests** — keyed output deterministic (two runs byte-equal); `--ephemeral` differs and
  records `mode: ephemeral`, empty `key_id`; exactly one of `--key`/`--ephemeral`; key not 32 bytes refused; already
  anonymised refused; `include_secrets` refused; newer-version unknown field → upgrade message, same-version →
  bug message, nothing written; `--out` = input or key file refused even with `--force`; existing `--out` refused
  without `--force`; output 0600 (non-Windows); a fixture keeps `synthetic`, `_expect`, `_provenance` and an empty
  `run: {}`; the output passes `facts.Load`; top-level key order `schema_version, run, facts` then fixture keys, `run`
  in `facts.Run` field order, `MarshalIndent` two spaces as collect writes.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** (decode with `UseNumber`; encode ordered; write with
  `O_CREATE|O_EXCL`, remove partial on error). **Step 4: Run** — PASS.
- [ ] **Step 5: Commit** `snapshot: anonymize command and run.anonymization (AX-1, AX-3, AX-10, §2)`.

**Pre-flight additions (binding):**
- `facts.Run.Anonymization` is the **last** field of `facts.Run`. The schema golden is regenerated with `-update`: it
  gains a `run.anonymization` field row and an `Anonymization` struct entry — an additive run-header field, which keeps
  `schema_version` under spec §5.7 and AX-10 (the commit cites AX-10; it is not a description-only edit). The same
  commit adds the `run.anonymization.*` rows to the table (class kept) so the header reflection test stays green.
- Version ordering for the two refusal messages: a `muster_version` is comparable only when it parses as
  `vMAJOR.MINOR.PATCH` optionally followed by `-N-g<hash>` and/or `-dirty`; the snapshot is newer only when both parse
  and the snapshot's triple is greater (or equal with a larger `N`). Anything else — `dev`, a bare hash, empty — gives
  the bug message. The decision lives in `cmd/muster` (`func unclassifiedMessage(snapVersion, binVersion string, path
  string) string`); tests override the package `version` variable and cover dev vs tag, tag vs hash, hash vs tag, equal
  tags.
- Tests add: as root (`os.Geteuid()==0`, skipped otherwise) a warning on stderr and an untrusted key file refused;
  `--force` refuses a non-regular `--out` (a directory); `collected_at` byte-identical in the output.

### Task 7: Fix refuses a script from an anonymised snapshot; the keep-set pin

**Files:** Modify `cmd/muster/fix.go`; create `cmd/muster/fix_anonymized_test.go`, `internal/controls/keepset_test.go`.

- [ ] **Step 1: Write the failing tests** — `fix --dry-run --format script` on an anonymised snapshot: exit 2, stdout
  empty, stderr "plan the script from the original snapshot"; `table` and `json` succeed and carry
  `run.anonymization`; the keyed `machine_id_hash` makes an older guard refuse (the rendered script's hash ≠ the
  original's); `TestKeepSetCoversControlLiterals` (every literal and default compared against an account-class value in
  the control set and the built-in profiles is `anonymize.Kept`).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. Delete the refusal; see red; restore.
- [ ] **Step 5: Commit** `fix: refuse a script from an anonymised snapshot; pin the keep set to the controls (AX-5, AX-11)`.

**Pre-flight additions (binding):** the mount-target closed list of Task 4 is pinned here too:
`TestMountTargetsCoverControls` (every literal and default mount target a control compares is in the list), external
test package.

### Task 8: The invariant, the canaries, the delete-the-call checks

**Files:** Create `cmd/muster/anonymize_invariant_test.go`, synthetic fixtures under
`cmd/muster/testdata/anonymize/`.

- [ ] **Step 1: Write the tests** — the corpus of spec §4 under every built-in profile: equal `(id, status,
  reason_code)`, mechanism, observation-verdict multiset per row, exit code; the synthetic fixtures (keep-set clauses
  mapped and preserved, `log` home at `/tmp`, nested/shared homes, `journal_upload.url` `""` with an active unit, the
  `cron.files` presence pair); the canary sweep (every class, `source.raw` cut with `…`, header fields, a sudoers.d
  drop-in, an EL mail spool, every host-or-address form) over the anonymised snapshot and the check JSON, plan JSON and
  table made from it; properties (deterministic, injective, class kept, refuses its own output).
- [ ] **Step 2: Run** — PASS, then for each of the four delete-the-call cases of spec §4 make the change, see red,
  restore; record each in the commit message.
- [ ] **Step 3: Commit** `anonymize: the verdict invariant, the canary sweep and the delete-the-call checks (AX-12, §4)`.

**Pre-flight additions (binding):** delete-the-call case 4 ("mapping an address before `exposure` is derived") is a
synthetic test: take a fixture with a listener row whose `exposed`/`loopback` booleans are set, map its address leaf
first through a test-only hook that re-derives the booleans from the mapped address (a copy of the collector's
classification), and show the verdict changes for a cross-class map while Transform's post-derivation run keeps it.
Canary addresses built from octets in Go; run `gitleaks detect --no-git --source .` locally on the fixtures before the
commit.

### Task 9: Documents

Written by the controller (main documents). Per spec §5: main design pair (§5.6, §7.2, §7.5, §8 `:426`, §9, §10.2,
D36; line-aligned), THREAT_MODEL, SECURITY.md, README pair, CLAUDE.md (a 3D-3 note), CHANGELOG, usage texts already in
Tasks 1 and 6. Commit `docs: 3D-3 — snapshot anonymize, --max-age, D36 (English and Korean)`.

### Task 10: Branch gates

- [ ] `gofmt -l .`, `go vet ./...`, `go run honnef.co/go/tools/cmd/staticcheck@2025.1.1 ./...`, `go test ./...`,
  `make lint-controls`, `go run ./tools/coverage -check`,
  `go run ./tools/cisindex -check`; on the lab `go test -race ./...` and shellcheck through the docker image; the
  Linux-tagged table tests of Task 5 run there.
- [ ] Hand off: push, PR, examples run (no example should change), merge — each on the user's word.

## Execution notes

- Pre-flight (wf_83d98800-842, 157 agents): 25 confirmed, 26 refuted; folded as each task's "Pre-flight additions"
  block (a Blank class; positional read-text grammars; one table spelling for setting sides, personas and nested
  sources; the collectors recorder; the version-ordering rule; the schema-golden wording; the table rows for
  `run.anonymization` in the same commit; pinned max-age messages and bound; mount targets as a pinned closed list;
  canaries built in Go against gitleaks; staticcheck in the gates).
