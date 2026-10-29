# Stage 3D-1b — CIS Level 1 profiles over an index of recommendation numbers

Korean pair: `2026-10-20-stage3d1b-cis-profiles-design.ko.md`. Main design: `2026-09-02-muster-design.md` (§3
references, §6.2 schema, §6.8 lint, §10.2 roadmap, §12 boundary, D04, D33). The cycle it builds on:
`2026-10-07-stage3d1-profiles-design.md` (Y-1..Y-9; Y-1 named this stage). Rulings of this design are the CB list
(single letters all collide with earlier stages). The scope map it was written from is the cycle's ignored workspace
(`scope-{cac,muster,join,legal,critic}.md`); its findings are restated here where they bind. A first review round
(`design-review-r1.md`, 35 findings), a second (`design-review-r2.md`, 15 findings in seven fixes) and a third
(`design-review-r3.md`, 9 findings in five fixes) are folded in.

## 1. Scope and intent

`check --profile` selects which of muster's controls a run evaluates (3D-1). The roadmap names the next profiles:
"the `cis-<distro>-l1` profile over an index of CIS recommendation numbers, every selected control carrying a
`references.cis` entry". This cycle builds three of them — Ubuntu 22.04, Ubuntu 24.04 and the RHEL 9 family, Level 1 –
Server — from public sources only, and makes the CIS references muster already carries checkable against an index.

A CIS profile is a **selection of muster's own controls**, each judged by muster's own clauses. A PASS under it is
muster's verdict on muster's control, not a CIS assessment, and muster claims no level of compliance or consistency
with any CIS Benchmark. The value to an operator is a run that answers the questions CIS Level 1 asks that muster can
answer, with every result traceable to a recommendation number they can look up in the Benchmark they hold.

- **CB-1 — Three built-in profiles: `cis-ubuntu2204-l1`, `cis-ubuntu2404-l1`, `cis-rhel9-l1`.** Each selects the
  controls that carry a Level 1 – Server recommendation of that benchmark, minus a committed review list (CB-7). They
  are built-ins beside `default`; their names are identifiers, never a product name. The documents CB-13 names carry
  the disclaimer; the profile line, the unknown-profile message and `controls list` do not repeat it. `cis-rhel9-l1` is
  the RHEL 9 family's (CB-3).
- **CB-2 — The numbers come from ComplianceAsCode, pinned, and nothing else of the source is kept.** The source is
  ComplianceAsCode/content (BSD-3-Clause, CB-15; the project behind SCAP Security Guide and Ubuntu's USG) at release
  `v0.1.82` (commit `3da954fbccfb4ca611da86c9be9205d83c38bfc7`): `controls/cis_ubuntu2204.yml` (CIS Benchmark v2.0.0),
  `controls/cis_ubuntu2404.yml` (v1.0.0), `products/rhel9/controls/cis_rhel9.yml` (v2.0.0) and
  `controls/cis_almalinux9.yml` (v2.0.0). Those files carry CIS titles. A new generator, `tools/cisindex`, decodes
  from each file exactly the header's `version` and each entry's `id`, `levels` and `rules`; `title`, `notes`,
  `status`, `related_rules` and every other field never leave its decoder (that sentence is the one NOTICE
  repeats, CB-15). Two readings of the kept fields are fixed here, because the files are not what their field names
  suggest:
  - An entry whose `id` does not match the recommendation grammar `^[0-9]+(\.[0-9]+){1,4}$` is a helper, dropped before
    anything is counted (at the pin: `reload_dconf_db` and `enable_authselect`, in the two EL9 files only). The grammar
    is a loud failure only for a number written in `map.yaml` (§2).
  - A `rules:` entry that contains `=` is a **variable selection** (`var_password_pam_minlen=14`,
    `sshd_idle_timeout_value=5_minutes`), never a rule id: it is excluded from reachability, from coverage (CB-6) and
    from rule-id validation (CB-5), and it is the only place a profile value comes from (CB-8). An entry whose `rules:`
    holds no rule id — absent, empty, or selections only — is reachable through `recs:` alone, and only such an
    entry is (CB-5). Rule ids repeated inside one entry's `rules:` are read as a set.
  The benchmark key, the display name and `applies_to` are muster's own, in `sources.json` (CB-3), never read from the
  files (the files' `title` is not the display name). Downloads are cached under `.cache/cisindex/` (git-ignored). No
  CIS PDF is read, stored or needed.
- **CB-3 — Benchmarks and their keys, in the STIG index's shape.** Three benchmarks, keyed as the STIG index keys its
  products — `product: ubuntu2204` (CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0), `ubuntu2404` (CIS Ubuntu Linux 24.04
  LTS Benchmark v1.0.0), `rhel9` (CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0) with `applies_to: [alma9, rocky9]`
  (the aliases only, as STIG's). The RHEL 9 file is the one source of `rhel9`'s numbers, levels, rule ids and variable
  selections. The AlmaLinux OS 9 file is read for one proof only: the generator fails unless its recommendation ids and
  its literal level sets equal RHEL 9's (they do at the pin), and `alma9` is admitted on that proof. Its `rules:` and
  selections differ from RHEL 9's on 32 entries at the pin; that difference is logged by the generator, never fatal,
  and never read: a rule id found only in the AlmaLinux file is unknown to `map.yaml`, and `cis-rhel9-l1` on an
  AlmaLinux or Rocky host carries RHEL 9's coverage words and parameter values — the index file's `equal_to` note, the
  docs and coverage.md say so. `rocky9` is an inference, stated as such in ATTRIBUTION like the STIG references' (CIS
  publishes a Rocky 9 Benchmark that no public source indexes). The versions are the pinned files' own; cisecurity.org
  lists newer ones (22.04 v3.0.0, 24.04 v2.0.0), and the docs say which the index encodes.
- **CB-4 — The index holds only the recommendations muster maps, plus one count.** A Benchmark's complete numbering in
  order is its structure (main design §12 forbids copying "text and structure").
  `docs/reference/cis/<product>-<version>.json` carries the product key, display name and version, the source pin, the
  `equal_to` proof, `applies_to`, `counts.l1_server` — the number of recommendation entries whose literal `levels` list
  holds `l1_server`; the files declare `l2_server` as inheriting `l1_server`, and no inherited count is published — and
  one row per mapped recommendation: `{rec, levels, controls, rules}`. `levels` is the entry's literal list. No title,
  no status word, no unmapped number, no other level's count (a count a profile does not use is not published; a Level
  2 profile would add its own with the inheritance rule written down).
- **CB-5 — The map is muster's work; the join is only its seed.** `docs/reference/cis/map.yaml` names, per muster
  control, the ComplianceAsCode rule ids that check what the control judges (rule ids are shared across products, so
  one row serves all three benchmarks; each id matches `^[a-z0-9][a-z0-9_-]*$` — package, service and module ids carry
  hyphens, `kernel_module_usb-storage_disabled` — so a selection, which contains `=`, can never be written as one),
  and per benchmark any recommendation the rule ids cannot reach (`recs:` with a one-line reason). The scope map's
  automatic join (control → its STIG ids → the rules ComplianceAsCode's STIG files list → the CIS files' numbers)
  seeds it; it recovers about 45 of the 58 controls with STIG references and nothing for the 59 without, and about
  three in four of its pairs are right, so every row is reviewed against what the control's clauses judge before it is
  committed. The generator validates every rule id against the union of the three source files' rule ids (the
  AlmaLinux file excluded, CB-3), every `recs:` number against that benchmark's file, and refuses a `recs:` number whose
  entry carries any rule id (naming them): the override exists for entries that list no rule id, nothing else. An
  index row's `controls` is the union of the controls its rule ids reach and those whose `recs:` name it, sorted by id.
- **CB-6 — Coverage is computed, never asserted.** Each index row carries `rules: all | some | none`, defined against
  the pinned file alone: `all` when the union of the mapped controls' rule ids contains every rule id of the entry (its
  selections excluded), `some` when it contains at least one, `none` for an entry with no rule id. CB-5 makes the three
  words total: an entry with rule ids is reached by rule ids only, and `none` ⇔ reached by `recs:`. No `rules` word is
  written by hand, no `recs:` reason asserts that a control equals or covers a recommendation (that would be a statement
  about the Benchmark's text), and nothing in muster renders the word "full" or a percentage; coverage.md marks `some`
  and `none`.
- **CB-7 — Membership: an `l1_server` number on the profile's benchmark, minus a review list, kept in step by tests.**
  A control enters `cis-<product>-l1` when the index names it on a recommendation whose literal levels include
  `l1_server` (whatever its `rules` word). `docs/reference/cis/review.yaml` removes a control from a profile, one reason
  each, where its judgment cannot honestly stand for the recommendation (CB-8). The built-in profile files list exact
  control ids, and `TestCISProfilesMatchTheIndex` holds each list equal to candidates minus the review list. Because
  `map.yaml` and `review.yaml` are hand-edited and the generator needs the network, a second, offline test
  (`TestCISMapAndReviewMatchTheIndex`) holds the committed files together: every `map.yaml` id appears in some index
  row's `controls` and the reverse, every `recs:` number is an index row, every `review.yaml` `{profile, id}` names a
  candidate of that benchmark that the generated profile omits, and a `params` entry names a control the profile
  selects. Rule-id validity and the `rules` word need the pinned files and stay maintainer-run (`cisindex -check`): a
  change to `map.yaml` or `review.yaml` ships with the regenerated index and profiles in the same commit.
- **CB-8 — A profile sets a parameter only where a selection maps one to one; otherwise the control is reviewed.** One
  to one means the muster parameter feeds only clauses whose facts the reached entry's mapped rule ids check: a
  parameter that also drives another clause is `param: none` there, and the review-list rule below decides the control
  (`password_policy.min_len` sets both the login.defs and the pwquality length while 5.3.3.2.2's rule checks pwquality
  alone, so `password_policy` is reviewed out on every benchmark until muster splits the parameter, parked). A `vars:`
  row in `map.yaml` names a ComplianceAsCode variable, the muster parameter and the conversion. The value is read from
  the benchmark file's `l1_server` entries that the control's rule ids reach: equal selections on several such entries
  are one value; two different values on one benchmark fail the generator; a variable not selected on any such entry
  leaves that profile's parameter at muster's default. The conversions are an enumerated vocabulary, because the files
  select option words as often as numbers (`var_accounts_tmout=15_min`, `sshd_idle_timeout_value=5_minutes`,
  `var_accounts_user_umask=027`) and the number behind a word lives in ComplianceAsCode's `.var` files, which are never
  fetched. Two conversions exist: `as: int` (decimal digits only; `027` is refused) and `as: {selected: value}` — a
  table written in `map.yaml`, muster's own, from the pinned file's selected text to any YAML value, type-checked
  against the parameter's declared type (`controls.CheckParamValue`, supplied by the caller, §2). A table key is only a
  selection whose own spelling states its value — decimal digits, a umask `0?[0-7]{3}`, or `<n>_min`, `<n>_minutes`,
  `<n>_seconds` — and the generator refuses any other key: a word such as
  `var_password_hashing_algorithm=cis_ubuntu2204` or `var_pam_wheel_group_for_su=cis` means what a `.var` file or the
  Benchmark says, neither of which muster reads, so it is `param: none`, and when the control has a parameter for that
  quantity the control goes on the review list for that benchmark ("the selection's value is not in the decoded
  source"). `session_timeout` (`15_min`, `5_minutes`) and `umask_policy` are the first cases: the one octal-looking
  selection at the pin is a umask, `var_accounts_user_umask=027`, and its row is a list of the umasks muster counts as
  at least as strict (`"027": ["027", "077", "0027", "0077"]`), never the subsets of 027, which are the weaker values.
  No selection at the pin sets a file mode, so no CIS profile sets an `allowed_modes`. Every variable selected on an
  `l1_server` entry a control's rule ids reach is named by a `vars:` row of that control — with a conversion, or `param:
  none` and a reason that describes the control — so the generator produces the worklist and nothing is silently
  dropped. Conversion runs only over the controls that survive `review.yaml` for that benchmark: a selection with no
  table entry, or one no conversion parses, fails the generator unless the control is on the review list there, where
  the review row suppresses it and the index row is still written (CB-4's row carries no value). So the generator writes
  `params` only for controls that remain in the profile (a value on an excluded control would make `profile.Merge` warn
  on every run). The profile's `params`/`param_sources` report the value as `profile` (3D-1). Where muster's default is
  weaker than the selection and no parameter carries the value, the control goes on the review list: a profile that
  PASSes a weaker threshold than the recommendation names would mislead. At the pin the rule yields about fifteen
  `vars:` rows, roughly half of them `param: none`.
- **CB-9 — Controls carry `references.cis` as a rendering of the index.** The shape stays `{benchmark, version, rec}`;
  `benchmark` is the canonical product key only (`rhel9`, never `alma9`: lint refuses an alias, naming the key);
  entries are sorted by key, then by `rec` compared component-wise as integers (`5.1.7` before `5.1.20`). The YAML
  stays hand-edited (no tool rewrites a control file); `TestEveryCISReferenceIsTheIndex` holds every control's
  `references.cis` equal to the index rows that name it and, on a difference, prints the expected `cis:` block for
  that control. The hand-written entries of today (13 controls, all spelled `ubuntu-22.04`) are replaced by that
  rendering; review found some of them wrong — `session_timeout` lacks the TMOUT recommendation. Beyond controls may
  carry CIS references (CB-12).
- **CB-10 — Lint checks the references and the profiles.** `references_cis` gains: the rec grammar
  `^[0-9]+(\.[0-9]+){1,4}$`; with `--references`, the entry exists in the CIS index (the canonical key, the indexed
  version, the number); no duplicate entry. Y-1's rule — every control the profile selects carries a `references.cis`
  entry on the profile's benchmark whose indexed levels include `l1_server` — runs in `cmd/muster`, after
  `resolveSelection`, over `profile.CISBenchmark(name)` (the exported table of §4; `internal/controls` cannot import
  `internal/profile`). Without `--references` the rule checks only that an entry on the benchmark exists, and
  `shapeOnlyNote` says CIS levels were not checked; the `--references` help names `cis` beside `stig` and
  `nist_800_53`. `make lint-controls` and CI (`ci.yml`) run `--profile` with `--references` for `default` and the three
  CIS built-ins.
- **CB-11 — `check` and `fix --dry-run` warn on a host the profile's benchmark does not cover.** The chain root decides
  (`Resolved.Chain[0]` is `builtin:cis-…`), so a site file that `extends` a CIS built-in warns the same way. The match
  is a table in `internal/profile` beside the built-in→benchmark table, over `run.host.os_release`: `ubuntu2204` ⇔ `id`
  `ubuntu` and `version_id` `22.04`; `ubuntu2404` ⇔ `ubuntu` and `24.04`; `rhel9` ⇔ `id` in `rhel`, `rocky`,
  `almalinux` and the first dotted component of `version_id` `9` (CentOS Stream is not named and warns). When the
  snapshot does not match, or its `id` or `version_id` is empty (the collector writes empty strings for an unreadable
  os-release), the command writes one line through `warnTo`: `muster: warning: profile cis-rhel9-l1 is built for rhel9,
  alma9, rocky9; the snapshot is ubuntu 24.04` or `…; the snapshot's os release is unknown`. The result bytes and the
  exit code do not change; a profile still evaluates where it was asked to.
- **CB-12 — A beyond control may carry a CIS reference (D35).** Most of what CIS Level 1 asks that muster can judge —
  mount options, kernel parameters, module blacklists, auditd, AIDE, the bootloader — lives in the 49 `beyond`
  controls. The main design §12 already admits a CIS number "unless the mapping is independently derived"; the mapping
  here is muster's own (CB-5: BSD-licensed rule ids judged against muster's clauses), so CONTRIBUTING's "a beyond
  control carries no CIS recommendation number" is reworded to that rule. `category: beyond` still means "no KISA
  item"; it says nothing about CIS.
- **CB-13 — No compliance claim, anywhere, and one disclaimer in one wording.** No output, document or test says "CIS
  compliant", "CIS score", a percentage or "passes CIS Level 1". The profile line stays `profile cis-ubuntu2204-l1 (<n>
  of <total>, …)`. The disclaimer is one sentence, written here so the documents copy it: *The `cis-<distro>-l1`
  profiles select muster's own controls that carry a CIS Benchmark recommendation number at Level 1 – Server; their
  results are muster's verdicts on muster's controls, not a CIS assessment, and muster is an independent publication
  not authorized, sponsored or otherwise approved by the Center for Internet Security.* It stands, in those words, in
  README.md, NOTICE and ATTRIBUTION.md (the main design §12 asks the three to state the boundary in the same words),
  with its Korean rendering in README.ko.md, and in the `check` usage text that names the built-ins; `tools/coverage
  -check`, which already holds README fragments, holds the three English copies. "Center for Internet Security®" and
  "CIS Benchmarks®" are credited in their exact form at the first prominent appearance.
- **CB-14 — No verdict changes.** No `checks`, facts or parameter defaults change; `default` selects what it selected.
  `controls/VERSION` moves (the reference edits change the set's digest). `guide_edition` stays `kisa-unix-2026`
  whatever profile is in force (it names the guide the control set is built on, not the selection).
- **CB-15 — ComplianceAsCode is redistributed under its licence, conservatively.** The index, `map.yaml`'s rule ids
  and the generated profiles are treated as a modified redistribution of the pinned files' data (the reading the repo
  already takes for KISA, ATTRIBUTION), and the profiles are embedded in the binary. NOTICE gains a ComplianceAsCode
  section carrying the BSD-3-Clause copyright line (`Copyright (c) 2012-2017, Red Hat, Inc.`), the three conditions and
  the warranty disclaimer verbatim, the repository, tag and commit, and the CB-2 sentence on what was decoded and what
  was not; ATTRIBUTION's CIS section points to it. Nothing presents muster as endorsed by, or built on, SCAP Security
  Guide: "via ComplianceAsCode <tag>" is attribution, not a claim.
- **CB-16 — The CIS index loads beside the STIG index, in its own namespace.** `controls.LoadReferenceIndex` globs
  `cis/*.json` into its own product, alias and version maps (M-4's uniqueness per family: `ubuntu2204` is a STIG product
  and a CIS product, `rhel9`'s CIS aliases are its own), decoded with `DisallowUnknownFields` over `internal/cisindex`'s
  index type (a `title` fails the load), and gains `HasCIS` beside `HasSTIG` plus the two accessors Y-1, the alias
  refusal and the tests use: `CISLevels(product, version, rec) ([]string, bool)` and `CISRows(product)` (the rows with
  their `controls`). A reference directory with no `cis/*.json` is not an error (`HasCIS` false; every `cis` entry is
  then unindexed under `--references`), so the existing index fixtures keep working and
  `internal/controls/testdata/refs/` gains a `cis/mini-1.0.0.json` for the lint tests.

## 2. The index

**Generator** `tools/cisindex` (`go run ./tools/cisindex [-check]`; `make cisindex`, `make cisindex-check`). It is
maintainer-run, like `tools/refindex`: it fetches over the network, the cache is git-ignored, and CI never runs it
(CB-7's offline test is CI's gate). `tools/cisindex` is a thin `main`; the source decoder, the `map.yaml` and
`review.yaml` decoders, the index JSON type, the candidate computation and the `vars:` conversion live in
`internal/cisindex`, which the generator, the two `cmd/muster` tests and `internal/controls` import, so no test
duplicates a struct. `internal/cisindex` imports nothing from muster and no `os`, `os/exec`, `net` or `syscall`
(`TestCISIndexImportsNoHostPackages`); `internal/controls` imports only its index type. What needs the control set is
passed in: the conversion takes `ParamType func(control, param string) (string, bool)` and `Check func(typ string, v
any) error`, which `tools/cisindex` fills from the loaded set and `controls.CheckParamValue`, and the candidate and
review checks take the set's ids. Fetching, the SHA-256 pin check, the cache and every write stay in the `main`.

- `tools/cisindex/sources.json`: per benchmark `{product, benchmark, version, applies_to, repo, tag, commit, path,
  sha256}`, plus the AlmaLinux file as an `equal_to: rhel9` entry. A download whose SHA-256 differs from the pin is
  refused; the cache is `.cache/cisindex/<sha256>` (git-ignored).
- The decoder (`internal/cisindex`) is a typed struct with exactly the kept fields (CB-2); YAML decoding drops the rest.
  It takes `[]byte`, so it carries `FuzzDecodeControls` with seeds; a test feeds it synthetic YAML only (the real files
  carry titles and never enter the tree), including the two-helper case and a selection inside `rules:`.
- Inputs besides the pinned files: `docs/reference/cis/map.yaml` and `docs/reference/cis/review.yaml` (§3).
- Output: one `docs/reference/cis/<product>-<version>.json` per benchmark, sorted, deterministic
  (`json.MarshalIndent` + newline), and the three built-in profile files (`internal/profile/builtin/cis-*.yaml`),
  generated from the index, the review list and the `vars:` rows, so the drift tests (CB-7) check generated artifacts.
- `-check` re-renders from the cache (or the network) and byte-compares every output; exit 1 on a difference.
- Failure is loud: a `map.yaml` rule id not in the union of the three files, or outside the CB-5 grammar; a `recs:`
  number the pinned file does not carry, or outside the grammar, or whose entry carries a rule id; a `review.yaml` id
  that is not a candidate; the AlmaLinux file's ids or literal level sets differing from RHEL 9's; a variable selected
  on a reached `l1_server` entry that no `vars:` row of the control names; a table value its parameter's type refuses;
  and, for a control not reviewed out on that benchmark, a selection no conversion parses, one with no table entry, or
  two values for one variable.

**Index file** (`docs/reference/cis/ubuntu2204-2.0.0.json`, shape):

```json
{
  "product": "ubuntu2204",
  "benchmark": "CIS Ubuntu Linux 22.04 LTS Benchmark",
  "version": "2.0.0",
  "applies_to": [],
  "source": {"repo": "ComplianceAsCode/content", "tag": "v0.1.82", "commit": "3da954f…", "path": "controls/cis_ubuntu2204.yml", "sha256": "…"},
  "counts": {"l1_server": 0},
  "recs": [{"rec": "5.3.3.1.1", "levels": ["l1_server", "l1_workstation"], "controls": ["muster.account.lockout_threshold"], "rules": "all"}]
}
```

The `rhel9` file adds `"applies_to": ["alma9", "rocky9"]` and `"equal_to": {"path": "controls/cis_almalinux9.yml",
"sha256": "…", "compared": "ids and levels"}`.

**Loader.** CB-16.

## 3. The map and the review list

`docs/reference/cis/map.yaml` (strict YAML; sorted by control id):

```yaml
- id: muster.account.lockout_threshold
  rules: [accounts_passwords_pam_faillock_enabled, accounts_passwords_pam_faillock_deny]
  vars:
    - { var: var_accounts_passwords_pam_faillock_deny, param: max_attempts, as: int }
- id: muster.log.time_sync
  rules: [service_chronyd_enabled]
  vars:
    - { var: var_timesync_service, param: none, reason: "the control judges that a time-sync service is enabled, not which one" }
  recs:
    ubuntu2204: [{ rec: "2.3.2.2", reason: "the control judges that a time-sync service is enabled" }]
```

At the pin, Ubuntu 22.04's 5.3.3.1.1 lists `var_accounts_passwords_pam_faillock_deny=4` and
`accounts_passwords_pam_faillock_deny`, and 5.3.2.2 lists `accounts_passwords_pam_faillock_enabled`: both rows render
`rules: all`, and `cis-ubuntu2204-l1` sets `lockout_threshold.max_attempts` to 4 (the EL9 files select 5). Ubuntu
22.04's 2.3.2.2 carries no rule id (fifteen of its `l1_server` entries do not), so it is reached by `recs:` and renders
`rules: none`. `service_chronyd_enabled` also reaches 2.3.1.1 on both Ubuntu files, which renders `rules: some` and
selects `var_timesync_service`, hence the `param: none` row; it reaches nothing on `rhel9`, whose 2.3.2 lists
`chronyd_specify_remote_server`.

- `rules:` are ComplianceAsCode rule ids the control's clauses check. They are reviewed per control against the
  control's facts and clauses; the join's seed rows are a starting point, never committed unreviewed.
- `vars:` is CB-8's row: `{var, param, as}`, with `as` either `int` or a `{selected: value}` table, or `{var, param:
  none, reason}` for a selected variable no parameter of the control carries one to one (CB-8).
- `recs:` (per benchmark) adds a number whose entry lists no rule id, with a reason. A reason describes the control,
  never the recommendation (CONTRIBUTING says so).

`docs/reference/cis/review.yaml`: `{profile, id, reason}` rows that take a candidate out of a profile (CB-7, CB-8).

## 4. The profiles

- Built-ins move from Go literals to embedded strict YAML (`internal/profile/builtin/*.yaml` with `//go:embed`;
  `internal/profile` still imports no `os`, `os/exec`, `net` or `syscall`): `default.yaml` (`include: [muster.*]`, as
  today, with the `kisa-unix-2026` alias) and the three generated `cis-*.yaml`, each an exact-id `include` list and its
  `params`. A Go table maps each CIS built-in to its benchmark key and its os-release match (CB-11), exported as
  `profile.CISBenchmark(name)` for `cmd/muster` (no user-visible `benchmark:` key; D33 unchanged). `Builtins()` returns
  the four names and the alias; the "unknown profile" message lists them.
- A file profile may `extends: cis-ubuntu2204-l1` like any built-in; a file may not reuse a built-in name.
- `controls list --profile cis-…` prints the selection as today; references stay out of report and fix output (a CIS
  column there is parked).

## 5. Coverage and documents

- **`docs/reference/coverage.md`** (`tools/coverage`): a "CIS recs" column in both tables (the numbers per benchmark,
  `some` and `none` marked) and one line per benchmark — "N controls map M of K Level 1 – Server recommendations
  (<display> v<version>, via ComplianceAsCode <tag>)", M being the index rows with `l1_server` and K
  `counts.l1_server`. No percentage, no score.
- **Documents** (English and Korean in the same commit where a pair exists): main design §3 `:50` (CIS references exist
  from 3D-1b, in CB-3's keys; "STIG references are identifiers and titles; CIS references are identifiers only"), `:66`,
  the §6.2 example `:238` (respelled `benchmark: ubuntu2204`), §6.6 `:352` and D33 `:551` (the "waits for an index"
  sentences), §12 `:509` and `:510` (the boundary sentence and the beyond rule), §10.2 (3D-1b merged), a decision entry
  **D35** (CB-4's mapped-only index, CB-9's index-as-source, CB-12's beyond rule) — the pair stays line-aligned; the
  3D-1 profiles design's Y-1 and parked list; CONTRIBUTING (the beyond rule; how to map a control: rule ids reviewed
  against the clauses, `recs:` with a reason that describes the control, never a title or the recommendation; the
  regenerated index ships with a map change); README (status, the profiles, the disclaimer, the stale counts at
  `:156-158` — 117 controls, 58 with STIG, 65 with NIST — and the "waits for 3D-1b" sentences at `:165-167` and
  `:241-243`); CLAUDE.md (a Profiles note: the CIS built-ins, the index, the generator, the tests); NOTICE (CB-13's
  sentence; CB-15's section); ATTRIBUTION's "CIS Benchmarks" section replaced (publisher and marks; the benchmarks
  referenced, linked not included; the licence and terms; what is reproduced — version, number and literal levels of
  mapped recommendations and the `l1_server` count, decoded from the pinned ComplianceAsCode files (CB-2), while the
  product key, display name and `applies_to` are muster's own, in `sources.json`; what is not — titles, descriptions,
  rationale, audit or remediation text, the complete list or order; the Rocky 9 inference and the AlmaLinux equality
  proof; the CB-13 sentence; the pointer to NOTICE's ComplianceAsCode section); CHANGELOG; `check`'s and `fix`'s usage
  text (`fix.go:21`); the `controls lint --references` help and `shapeOnlyNote` (`controls.go:25-28`, `:131`).
- **Examples**: the set's digest changes, so the examples are refreshed from the branch's `examples.yml` run before
  the merge (they run `default`, so no verdict moves).

## 6. Tests and CI

- `internal/cisindex`: the decoder over synthetic YAML (a title in the input never reaches the output; the two helper
  ids are dropped and not counted; a selection inside `rules:` is not a rule id; the AlmaLinux equality check passes on
  equal ids and levels and ignores a rules difference), `FuzzDecodeControls`, the `rules` word, the `vars:` readings
  (one value, a conflict, an absent selection, an unnamed selection, `param: none`, each conversion and its refusals, a
  table key outside the CB-8 grammar, a table value a stub `Check` refuses, a parameter that feeds another clause, a
  reviewed-out control's unparsed selection), every failure in §2, and `TestCISIndexImportsNoHostPackages`.
- `internal/controls`: the CIS loader (strict, its own maps, one version per product, absent directory accepted,
  `FuzzLoadCISIndex` over the file bytes), `HasCIS`, the lint rules (grammar, canonical key, index existence,
  duplicates), and `TestEveryCISReferenceIsTheIndex`.
- `internal/profile`: the embedded built-ins load strictly; `default` resolves as before; each CIS built-in resolves
  against the shipped set with every `params` value accepted by its control; `CISBenchmark` for the four names.
- `cmd/muster`: `TestCISProfilesMatchTheIndex` and `TestCISMapAndReviewMatchTheIndex` (CB-7; they read
  `../../docs/reference/cis/` from the tree and the built-ins from the embed), the Y-1 rule for each
  CIS built-in with and without `--references`, the CB-11 line for `check` and `fix --dry-run` (an extending file, a
  matching host, a mismatching host, an empty os-release; stdout and the exit code unchanged), the built-in list in
  the unknown-profile message.
- `tools/coverage`: the CB-13 sentence held across README.md, NOTICE and ATTRIBUTION.md; the "CIS recs" column and
  the per-benchmark line.
- Each test is written before its call site, caller first (CLAUDE.md), and a control reference edit leaves the
  mutation test at zero survivors (references are not mutated; the fixtures do not change).
- CI: `make lint-controls` (the two lint runs plus `--profile` for `default` and the three CIS built-ins, all with
  `--references`; `Makefile` and `ci.yml` gain those lines), `go test` as today, `coverage -check`; `fuzz.yml`, which
  lists its packages by hand, gains `internal/cisindex` and `internal/controls` in the commit that adds the targets;
  `cisindex -check` stays maintainer-run.

## 7. Parked

- More benchmarks: Debian 12/13, Amazon Linux 2023, SLE, Fedora (ComplianceAsCode has files; the generator takes a
  new `sources.json` row), and newer CIS versions once ComplianceAsCode ships them.
- Level 2 and Workstation profiles (with the level-inheritance rule and their counts); CIS's own Rocky 9 Benchmark (no
  public index); an AlmaLinux index of its own (its file's rule lists differ from RHEL 9's).
- A user-visible profile `benchmark:` key or a reference-based selector (a D33 reversal).
- CIS numbers in report or fix output.
- A parameter with no one-to-one ComplianceAsCode selection, or whose selected word has no conversion (its control
  stays on the review list); a mode conversion, until a benchmark selects a file mode; splitting
  `password_policy.min_len` into its login.defs and pwquality lengths.
