# Stage 2M — The Coverage and Reference Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close stage 2 with the two gates the spec names and nothing else claimed — `controls lint` cross-checking every `references.kisa` id against the 67-item inventory (spec §6.8) and a facts-used-over-facts-collected report in the committed coverage table (spec §11) — and resolve the sixteen items eight plans parked "to 2M": the evaluator's missing-field and vacuous-selection paths, evidence for MANUAL controls, the U-28 libwrap gate, the denied-directory `Glob`, the undeclared-path convention, the pam drop-in migration, the redaction header, the set's version and changelog, and the two READMEs. **Control set stays at 64 (auto 55, partial 5, manual 4); no new fact key; `schema_version` unchanged.**

**Architecture:** Lint gains an inventory-aware rule set (`internal/controls/kisa.go`, loaded from `docs/reference/kisa/`) and a shared `FactUsage` that both the lint note and `tools/coverage` print. The evaluator (`internal/check`) learns three things the spec already promised: a record lacking a judged field fails the clause with a reason naming the field (never `ERROR`), an `each … where "${param}"` that selects nothing from a non-empty list is MANUAL (a typo'd override must not pass vacuously), and a collection clause's evidence names the elements it judged instead of counting them. `automation: manual` controls carry an `evidence:` list. The collect side fixes one primitive (`hostAccess.Glob` reports a directory it was denied) and settles the cross-collector convention for paths the model chose not to read (absent with the path in the reason, never `error`). Two developer commands — `controls new` and `snapshot extract` — and `CONTRIBUTING.md` make the fixture workflow the spec describes real. CI gains a capability matrix.

**Tech Stack:** Go 1.25 (`internal/controls`, `internal/check`, `internal/collect`, `cmd/muster`, `tools/coverage`), the embedded control set, the `fsAccess` test double, the lab host for the Linux-only suite (root and `runuser -u nobody` runs), GitHub Actions (`.github/workflows/ci.yml`).

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` — line 345 (§6.8 cross-check), line 454 (§11 facts-used report), line 466 (§11 capability matrix), line 483 (`CONTRIBUTING.md`, `controls new`), line 206 (§5.7 missing field), line 202 (§5.6 redaction), line 220 / D16 (control-set version and changelog), line 436 (2M and the stage-3 walk items). Scope brief: the session scratchpad `2m-scope-brief.md`. Parked items: the Execution notes of plans 2A, 2B, 2C, 2D, 2E, 2F, 2H, 2I, 2J, 2L (all under `docs/superpowers/plans/`).

## Global Constraints

- **Branch base:** `stage2m-coverage-gate` at `d2d4d65` (post-2L main, 64 controls). Nothing else is in flight, so there is no rebase step; Task 7 confirms `git merge-base HEAD main` is main's tip before the final gates. Registry: **no new key** in this plan (every item below reuses existing leaves); `since`/`schema_version` untouched; the facts schema golden must not change.
- **Ruling M-1 (scope):** 2M is the stage-2 closing gate: the two spec deliverables (the §6.8 inventory cross-check, the §11 facts-used report), the sixteen distinct items parked "to 2M" resolved by the rulings below, the un-attributed stage-2 deliverables that are pure Go and cheap (`controls new`, `snapshot extract`, `CONTRIBUTING.md`, a capability-matrix CI step), and the set's version/changelog (D16). **No new control.** Explicitly OUT and recorded in Parked: parser oracle tests and example snapshots captured from public images (stage-3 test hardening, beside mutation testing and fuzzing); the shadow `rounds` value (no control needs it — U-02 judges `login.defs`); U-15/U-23/U-33 (the deep walk, stage 3 — recorded in `kisa_deferred.json` so the cross-check can pass honestly); `rsyslog.rules` row volume (measured on the lab host in Task 4 and recorded, changed only if the snapshot exceeds 1 MiB).
- **Ruling M-2 (the KISA cross-check, spec line 345):** `LintOptions.KISA *KISAInventory`, loaded by `controls lint --kisa <dir>` (default `docs/reference/kisa`; a missing directory is an error the way a missing fixture directory is — R35). Per control: every id under `references.kisa["<year>"]` must exist in `kisa_items_<year>.json` (`2026` reads `kisa_items_latest.json`; a year with no inventory file is an error), rule `references_kisa`; the control's `importance` must equal the 2026 item's importance (rule `kisa_importance` — the R117 class of bug, automated). Set-level, reported once with an empty `Path` and `ControlID` (rule `kisa_coverage`): every 2026 item is cited by exactly one control or listed in `kisa_deferred.json`; an item cited by two controls, an item cited by none and not deferred, and a deferred item that a control cites (a stale deferral) are each an error naming the ids. A nil `KISA` (unit tests that build a one-control set) keeps today's shape-only behaviour.
- **Ruling M-3 (the facts-used report, spec line 454):** `controls.FactUsage(set, reg) []CollectorUsage` — `{Collector string; Registered, Used, Engine int; Unused []string}` in registry order of first appearance — is the one computation. `tools/coverage` renders it as a second section of `docs/reference/coverage.md` ("## Fact keys used by controls": one summary line `N of M registered keys are read by a control (K by the engine); U unused.` and a per-collector table); `controls lint` prints `note: N of M registered fact keys are used by a control (K read by the engine); unused: …` in place of today's note. `UnusedKeys` stays as a wrapper. `engineReadKeys` remains the hand-maintained list — the report is where a forgotten entry becomes visible.
- **Ruling M-4 (lint hardening, 2A's parked items):** `ReferenceIndex` records the directory it was loaded from and the unindexed-id message names `<dir>/stig` instead of the literal `docs/reference/stig`; `LoadReferenceIndex` rejects two files for the same product (`duplicate index for product %s: %s and %s`); when no `--references` is given lint prints `note: stig and nist_800_53 references checked for shape only; pass --references docs/reference to check them against the index` (stdout, not a failure — R98's opt-in stays); a new rule `shell_valid_screen` requires a clause whose `where`/`require` names the field `shell_valid` to be preceded, in the same `checks` or mechanism list, by `{fact: accounts.shells, op: present}` (R126 as a rule, 2B's candidate).
- **Ruling M-5 (missing field, spec line 206):** `fieldClause` returns a typed `missingFieldError{Field}`; `evalCollection` turns it into a failing observation `{subject, expected, actual: null, verdict: fail}` and a clause reason `element <subject> has no field "<field>"` (`clauseOutcome.Reason`, which `evalOne` prefers over `describe(cl)`), for `where` and `require` alike and for every op except `present`/`absent` — never `ERROR(internal_error)`, never PASS, never "not selected" (a missing `where` field that silently deselected would be the vacuous PASS the spec forbids). A `partial` control reads WARN as usual.
- **Ruling M-6 (vacuous selection, IR-19/L-19 — one fix):** an `each` with `where` over a NON-EMPTY list that selects zero elements always records one observation `{subject: "<kind>:*", expected: <where described>, actual: "0 of N elements selected", verdict: pass}` so the fact is visible in every report; when `where.expected` is a `${param}` reference the outcome also carries `Vacuous` and the control ends **MANUAL** with reason `parameter "<name>" selected no element of <fact> (N elements)` and the clause's fact as evidence. `none` is untouched (zero hits is its PASS by definition) and an EMPTY list stays a vacuous PASS (2F/R204: a genuinely empty enumeration is an ok `[]`).
- **Ruling M-7 (collection evidence, 2A's "5 elements"):** the evidence value of an `each`/`none` clause names what it judged: for `each` `"N elements; K selected; failing: s1, s2"` (the `selected` part only when a `where` exists; `failing:` only when some fail), for `none` `"N elements; matching: s1, s2"` (or `"N elements; none matching"`); at most five subjects, then `+K more`; the observations stay the complete record. Report goldens are regenerated; the facts golden is untouched.
- **Ruling M-8 (`evidence:` for manual controls, L-11):** `Control.Evidence []string` (yaml `evidence`), lint rule `evidence`: valid only on `automation: manual`, every key registered; the evaluator's step 4 appends `evidenceFor(c.Evidence)` (deduped). U-45 and U-49 list `patch.pending_security_count`, `patch.metadata_age_s`, `patch.security_metadata_available`; U-46 lists `mail.postfix.authorized_submit_users`, `mail.sendmail.privacy_options`; U-47 lists `services.mail.reachable`, `mail.postfix.inet_interfaces`, `mail.postfix.mynetworks`, `mail.postfix.smtpd_relay_restrictions`. Their `manual-*.json` fixtures carry every evidence leaf, and the fixture test asserts that no evidence entry of a MANUAL result has status `missing`.
- **Ruling M-9 (the U-28 libwrap gate, L-9/L-19):** mechanism 1's `when` becomes `[{files.etc_hosts_deny_all eq true}, {files.libwrap_present eq true}]`; mechanism 3 (`firewall.backend eq none`) checks BOTH `files.libwrap_present eq true` and `files.etc_hosts_deny_all eq true`; mechanism 2 is unchanged. Every U-28 fixture and both e2e snapshots gain `files.libwrap_present` (a mechanism's `when` facts are screened, so a fixture without it is `ERROR(missing_fact)`); new fixture `fail-tcpwrappers-no-libwrap.json` (deny-all present, libwrap absent, backend none → FAIL). The description gains the sentence that the gate now enforces what it described.
- **Ruling M-10 (the denied directory — R204 and IR-8 are one fix):** `hostAccess.Glob` first probes the pattern's literal directory (the longest leading part with no `*`, `?` or `[`; `path.Dir` of it when the final segment holds the meta-character) by opening it with `openNoFollow(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)`: EACCES/EPERM → return `nil, fmt.Errorf("%s: %w", dir, err)` (an `Errno` that `errors.Is(err, fs.ErrPermission)` recognises, so every caller's `FromReadError` reads `denied`); any other probe result (success, ENOENT, ENOTDIR, ErrSymlink, ELOOP) falls through to `filepath.Glob` exactly as today. No new `ReadDir` primitive. The 25 call sites are audited in a table (Task 4): a site that already routes the error is unchanged; the four that ignore it — `env.go` (`profile.d`), `files_dev.go` (`/dev/*`), `services_super.go` (xinetd fragments), `firewall.go` (`globNonEmpty`) — route it to the leaves that depend on the listing (C3), or keep ignoring it with a comment naming the other path that already reports the denial. The lab proof is a non-root run in which `cron.files`/`cron.dirs` read `denied` (the crontabs spool is 1730 on Ubuntu) where today they read an empty list.
- **Ruling M-11 (`Getxattr`):** size the value with `unix.Fgetxattr(fd, name, nil)`, allocate exactly, retry once on `ERANGE` with the new size; never a flat 64 KiB.
- **Ruling M-12 (the symlink convention — LR-16, 2C, 2D-S6 settled):** `FromReadError` does NOT change. A symlink a stock distribution ships is modelled where it appears (LR-1's crypto-policy chain is the precedent); a symlink an administrator placed at a MAIN configuration file stays an honest `error` — the control is ERROR, the run partial, and `--require-complete` failing there is correct because muster did not see the configuration (2C's question: no, a degraded-but-complete run is not wanted for an unread main file). What IS wrong today is a path muster **chose** not to read: an undeclared sshd `Banner` (2D-S6) becomes `absent` with reason `Banner <p> is outside the collector's declaration: recorded, never read` (U-62 → MANUAL via its `absent_means: manual`), and an interactive account whose home is outside the declaration (2E-S2) makes the whole `files.home_dirs` leaf `absent` with a reason naming each such `user (path)` (the L-43/L-53 whole-leaf precedent; U-31/U-32 → MANUAL, never the false FAIL). This is convention **C4**, added to `CLAUDE.md` and `CONTRIBUTING.md` (Task 8): *a path the model declined to read is `absent` with the path in the reason; a declared file that exists and cannot be read is the read's status; a symlink an administrator made at a declared main file is `error` by design.*
- **Ruling M-13 (2E-S1):** a `.rhosts`/`.shosts` that exists but cannot be read makes `files.user_rhosts` `denied` with the path in the reason (C3), never a dropped row; ENOENT stays "no row". (`files.env_files` already follows C3 per R183 — verified, no change.) U-27 reads ERROR(permission_denied) on such a host, which is honest.
- **Ruling M-14 (pam drop-ins onto `mergeDropins`, I-5):** pwquality only — `mergeDropins(a, pwqualityConf, []string{"/etc/security/pwquality.conf.d"}, "*.conf")` — preserving R148 (the first read error of an existing file poisons every derived value) and lexicographic order; `faillock.conf` has no drop-in directory and stays on `readKV`. `parseDropin` records `Section/Key` pairs pwquality never uses; the derivation reads bare keys only.
- **Ruling M-15 (the redaction header, J-7):** `run.redaction.redacted_fields` lists, sorted, every registered `sensitivity: secret` key a collector set with status `ok` in this run (the keys whose values the collector stored in reduced form); `profile` and `include_secrets` are unchanged and `--include-secrets` is still not offered. The e2e snapshots and the lab host have no snmpd, so the field stays absent there (`omitempty`); a `run_test.go` double that sets `snmp.communities` ok proves the list.
- **Ruling M-16 (`controls new` and `snapshot extract`, spec line 483 and 454):** `muster controls new <id> --kisa-id U-NN [--automation auto|partial|manual] [--kisa-dir docs/reference/kisa] [--out controls] [--fixtures controls/testdata]` writes `controls/<area>/<name>.yaml` (area and name from the id; `importance` and both titles' placeholders from the inventory item's name; `references.kisa` with the 2026 id and the 2021 ids from `kisa_mapping.json` (`mapping[].latest_id` → `from_2021`, a list — `"2021": []` when it is empty); `requires_facts: ">=1"`; `absent_means: manual`; a `checks:` placeholder the loader accepts; `remediation` placeholders) plus `pass-example.json` and `fail-example.json` synthetic stubs; it refuses to overwrite and never touches an existing directory. `muster snapshot extract --facts <snapshot> --control <id> [--out <file>]` writes the partial snapshot a fixture needs: exactly the leaves the control reads (`applies_when`, `checks`, every mechanism's `when`/`checks`, `evidence`, and `walk.complete` when a `walk.*` key is read), `schema_version`, an empty `run`, `"synthetic": false` and a `_provenance` block `{muster_version, collected_at, os_id, os_version_id}` — never a hostname. The fixture test still requires `synthetic: true` (D02): an extracted file is reviewed and marked by hand, as `CONTRIBUTING.md` says.
- **Ruling M-17 (exhaustive e2e):** `assertStatuses` additionally fails when the report carries an id `want` does not name and when a loaded control id is missing from `want`; both e2e maps must therefore be complete (L-29 kept them in step — verify, then rely on it).
- **Ruling M-18 (the capability matrix, spec line 466):** `docs/reference/capability-matrix.json` — `{"nonroot": {"denied": [...]}, "no-systemd": {"unsupported": [...]}}` — is checked by one `jq` step in `collect-nonroot` and in `collect-containers` for the `init: "false"` images: every named fact must carry exactly the named status. The non-root list is derived on the lab host (`runuser -u nobody -- muster collect --out -`) and restricted to facts that are root-only by permission on both families — at least five keys from at least three collectors (shadow-derived `accounts.*` leaves, `cron.files`/`cron.dirs` after M-10, sudoers leaves); the no-systemd list names the `installed` leaf of four rows the services table already degrades (`ssh`, `ntp`, `syslog`, `ftp` — `services.ssh.installed` is asserted `unsupported` in CI today; the implementer confirms the other three follow the same table path in `services.go` before listing them).
- **Ruling M-19 (D16):** `controls/VERSION` → `kisa-unix-2026+2026.09.09`; goldens and e2e snapshot headers regenerated; `CHANGELOG.md` is created (Keep-a-Changelog shape, `## Unreleased`, a `### Controls` section listing the stage-2 growth 8 → 64 by plan and the verdict-affecting changes of this plan — M-5, M-6, M-9 — and a `### Tooling` section). CHANGELOG is English-only like the plans; `CONTRIBUTING.md` says so.
- **Ruling M-20 (README, L-32):** roadmap item 2 in both READMEs is rewritten to the live numbers: 64 of the 67 items (auto 55, partial 5, manual 4 with evidence attached), the remaining three — U-15 file ownership, U-23 SUID/SGID/sticky, U-33 hidden files — waiting for the deep filesystem walk of stage 3. `tools/coverage -check` additionally verifies that `README.md` contains the fragment `<enrolled> of the 67 items` and `README.ko.md` the fragment `67개 중 <enrolled>개`, so the sentence can never go stale silently again. Task 2 changes the two numbers only; Task 8 (controller) rewrites the sentences.
- **Ruling M-21 (work split):** `README*.md`, `CONTRIBUTING*.md`, `CHANGELOG.md`, the `CLAUDE.md` C4 line and the Execution notes are authored by the controller in Task 8; implementers write code, tests, fixtures, the coverage table and `controls/VERSION`.
- **Ruling M-22 (lab and gates):** the LAB TOKEN is 2M's from Task 1 (2L has merged). Tasks 4 and 5 run the Linux suite on the lab host through the read-only `lab-sync.sh`/`lab-run.sh`; a root `collect --require-root --require-complete` exits 0 after every collect-side task; the non-root run after Task 4 is the M-10 proof; `gitleaks git --no-banner` over the branch (PowerShell) and the controller's host-string grep (the lab alias, the organisation name and the lab address prefix — the pattern lives in the session notes, never in a tracked file) → 0 before every commit that adds a file. Windows: `gofmt -l .`, `go vet ./...`, `GOOS=linux GOARCH=amd64 go vet ./... && go test -c ./internal/collect/collectors/ -o NUL`, `go test ./... -count=1`, `go run ./cmd/muster controls lint --references docs/reference` → `ok: 64 controls`, `go run ./tools/coverage -check`.
- **Pre-flight rulings M-23 … M-34 (folded 2026-09-09).** A fresh Fable pre-flight (`.superpowers/sdd/2026-09-09-stage2m-coverage-gate/preflight-scan.md`) verified every ruling against the code, ran the M-5/M-6/M-7/M-8 shapes through an overlay prototype (no fixture, golden or e2e status moved) and scripted the KISA cross-check over the 64 controls (passes with `kisa_deferred.json` as written). Its findings fold in below and amend the rulings they name.
- **Ruling M-23 (B-1, amends M-14):** `parseDropin` discards a line without `=` (`dropin.go:127-130`) while pwquality's real syntax has bare-word flags (`enforce_for_root`, `local_users_only` — fixtured at `testdata/pam/rocky/90-local.conf:2`, asserted at `pam_test.go:392`, judged by U-02). The helper therefore gains a parser parameter: `mergeDropinsWith(a, main, dirs, glob, parse func([]byte, map[string]string))`, with `mergeDropins` kept as the systemd wrapper that passes `parseDropin`; pwquality passes a `parseKV`-compatible parser (bare words kept as `""`, keys lower-cased). `TestPwqualityDropinsMergeLikeSystemd` includes a bare `enforce_for_root` line in a drop-in and asserts the flag.
- **Ruling M-24 (B-2, amends M-20):** `README.ko.md:122-123` wraps `67개 중` / `58개를` across a line break, so the fragment guard normalises whitespace on both sides (`strings.Join(strings.Fields(text), " ")`) before matching, and Task 2 changes `58개를` → `64개를` on line 123 without rewrapping; `TestCheckVerifiesTheReadmeCountFragments` includes a wrapped-fragment case.
- **Ruling M-25 (B-3, amends M-8):** the fixture assertion is scoped to controls with `automation: manual`: for every key in `c.Evidence` the `manual-*.json` fixture carries a leaf, so no evidence entry of that result has status `missing`. The walk gate's `walk.complete` evidence on `muster.file.world_writable/manual-no-walk.json` is `missing` by design (R16, `eval.go:573-578`) and stays.
- **Ruling M-26 (S-1, amends M-2):** `controls lint` validates its directories in the order fixtures → references → kisa; `cmd/muster/controls_test.go` gains `repoKisa = filepath.Join("..", "..", "docs", "reference", "kisa")` and the three existing lint tests (`TestControlsLintFixturesFlagAndUnusedKeysNote`, `TestControlsLintReferencesFlagRejectsAMissingIndex`, `TestControlsLintWithoutReferencesFlagChecksShapeOnly`) pass `--kisa repoKisa`, as does `TestControlsLintNotesAndKisaFlag`. `kisa_coverage` is a 2026-only rule (a 2021 id may legitimately be cited by two controls — `U-14` is today).
- **Ruling M-27 (S-2, amends M-3):** Task 2 retargets `controls_test.go:226` (`used by no control`) to the new note (`registered fact keys are used by a control` and `unused:`); `sockets.listening` stays in the unused list.
- **Ruling M-28 (S-3, amends M-17):** the third `assertStatuses` call (`e2e_test.go:78`, the waiver test) is extended to all 64 ids — the ten waived controls (`root_remote_login` and the nine 2G services listed at `:53-63`) as `WAIVED`, every other id exactly as the full-fail map at `:273-338`. No non-exhaustive variant is kept.
- **Ruling M-29 (S-4, amends M-19):** the report goldens render the literal `ControlsVersion` of `internal/report/report_test.go:36` and `table_test.go:153`, not `controls/VERSION`; Task 7 changes both literals to `kisa-unix-2026+2026.09.09` and then regenerates (`-run TestJSON -update`, `-run TestTableGolden -update`), so the goldens document the live version; `cmd/muster/testdata/full-*.json` `run.controls_version` is updated too (cosmetic — `check.go:164-165` warns on a digest mismatch only, and both snapshots carry an empty digest). `internal/controls/testdata/valid/VERSION` is a test set and is not touched.
- **Ruling M-30 (S-5, amends M-13):** `readReason` STRIPS the path prefix (`pam_parse.go:144-146`); the path-prefixed envelope is `readErrorEnv(p, err)` (`pam_derive.go:63-67`). `userRhosts` keeps the FIRST `readErrorEnv` in a variable local to the function and returns it instead of the list — the read's status per C3 (`denied` for EACCES, `error` for a symlinked or non-regular file); ENOENT stays "no row". Never a package-level variable.
- **Ruling M-31 (S-6, amends M-9):** an `absent` `files.libwrap_present` would skip mechanism 1 and route a deny-all host to mechanism 3's `absent_means: manual`; the collector always writes an ok bool, so `fail-tcpwrappers-no-libwrap.json` carries `{"status":"ok","value":false}` and every other U-28 fixture and both e2e snapshots carry `{"status":"ok","value":true}` (hand-traced: no existing fixture changes status; U-28 stays PASS in both e2e runs via mechanism 2).
- **Ruling M-32 (S-7, amends M-12):** the undeclared-home rule applies to INTERACTIVE rows only (`interactive(r.shell, shells)`), sorted by user in the reason; a non-interactive account with an undeclared home (`/nonexistent`, `/var/lib/…`) keeps today's `denied` row, so the leaf stays `ok` on a stock host (`collectors_test.go:2672-2700` pins that). `TestSshdBannerOutsideDeclarationIsRecordedNotRead` (`collectors_test.go:492-508`) flips from `!= StatusError` to `== StatusAbsent` and asserts the `recorded, never read` reason.
- **Ruling M-33 (S-8, amends M-6):** `clauseOutcome` gains `Count int` (the list length, set by `evalCollection`) so `evalOne` never parses the evidence string; `Vacuous` is set only while `out.Holds` is still true (a missing `where` field — M-5 — is a FAIL, never overridden to MANUAL); the MANUAL return carries the evidence and observations of every clause evaluated so far plus this clause's (`append(append(res.Evidence, all.Evidence...), out.Evidence...)`, likewise observations). A list fact without `subject_kind` (e.g. `logging.rsyslog.rules`) yields the synthetic subject `item:*`.
- **Ruling M-34 (S-9, amends M-18):** the matrix names plain-envelope keys only — a setting's sides are not addressed by the jq `.status` — and never a `files.*.{mode,uid,gid}` leaf (Stat opens with `O_PATH` and needs no read permission). Candidates, to be confirmed on the lab host as non-root: `accounts.shadow_in_use`, `sudo.includedir`, `sudo.secure_path`, `files.etc_shadow.acl_present`, `files.etc_sudoers.acl_present`, `cron.files`, `cron.dirs` (three collectors). The container variant of the step reads `"$RUNNER_TEMP/muster/containers/c.json"`.
- **Determinism:** sorted subjects in evidence strings; `redacted_fields` sorted; `FactUsage` in registry order; no map iteration reaches output. **Attribution:** no KISA/CIS text; `kisa_deferred.json` carries ids and muster's own reason only. **Parked to stage 3:** parser oracles, public-image example snapshots, shadow `rounds`, the walk items.

## File Structure

- Create `internal/controls/kisa.go` (+ `kisa_test.go`) — `KISAItem`, `KISAInventory{Items map[year][]KISAItem, Deferred []Deferral}`, `LoadKISA(dir)`.
- Create `internal/controls/usage.go` (+ `usage_test.go`) — `CollectorUsage`, `FactUsage`; `UnusedKeys` moves here as a wrapper.
- Modify `internal/controls/lint.go`, `lint_test.go` — M-2, M-4 rules, `evidence` rule (M-8), `shell_valid_screen`.
- Modify `internal/controls/references.go`, `references_test.go` — `Dir`, duplicate product.
- Modify `internal/controls/schema.go` — `Evidence []string`.
- Modify `internal/controls/fixtures_test.go` — MANUAL evidence never `missing`.
- Modify `cmd/muster/controls.go`, `controls_test.go` — `--kisa`, the two notes, `controls new`.
- Create `cmd/muster/snapshot.go` (+ `snapshot_test.go`) — `snapshot extract`; modify `main.go` (dispatch + usage).
- Modify `cmd/muster/e2e_test.go`, `testdata/full-pass.json`, `testdata/full-fail.json` — M-9 leaf, M-17.
- Create `docs/reference/kisa/kisa_deferred.json`, `docs/reference/capability-matrix.json`.
- Modify `tools/coverage/render.go`, `render_test.go`, `main.go`; create `main_test.go` (`unifiedDiff`); regenerate `docs/reference/coverage.md`.
- Modify `internal/check/collection.go`, `clause.go`, `eval.go`, `value.go` and their tests — M-5, M-6, M-7, M-8.
- Modify `internal/report/testdata/*.golden` — regenerated (M-7, M-19).
- Modify `internal/collect/registry.go`, `registry_test.go` — M-10, M-11; `run.go`, `run_test.go` — M-15.
- Modify `internal/collect/collectors/{env,files_dev,services_super,firewall}.go` (M-10 audit), `collectors_test.go` (`fsAccess.deniedDirs`), `sshd.go` (S6), `files_home.go` (S1, S2), `pam_derive.go` (M-14) and their tests.
- Modify `controls/file/ip_port_restriction.yaml` + `controls/testdata/muster.file.ip_port_restriction/*` (M-9); `controls/service/{mail_version,mail_user_execution,mail_relay,dns_version}.yaml` + their `manual-*.json` (M-8); `controls/testdata/muster.service.login_banner/manual-banner-undeclared.json`, `muster.file.home_dir_{exists,permissions}/manual-home-undeclared.json`, `muster.file.rhosts_forbidden/error-rhosts-denied.json` (M-12, M-13).
- Modify `controls/VERSION`; `.github/workflows/ci.yml` (M-18).
- Controller (Task 8): `README.md`, `README.ko.md`, `CONTRIBUTING.md`, `CONTRIBUTING.ko.md`, `CHANGELOG.md`, `CLAUDE.md`.

## Interfaces (produced by this plan)

```go
// internal/controls/kisa.go
type KISAItem struct { ID, NameKo, Category, Importance string; Page int }   // json tags id, name_ko, category, importance, page
type Deferral struct { ID, Stage, Reason string }                              // json tags id, stage, reason
type KISAInventory struct { Items map[string][]KISAItem; Deferred []Deferral } // Items keyed by edition year; "2026" is kisa_items_latest.json
func LoadKISA(dir string) (*KISAInventory, error)                             // reads kisa_items_latest.json (as "2026"), kisa_items_2021.json, kisa_deferred.json
func (x *KISAInventory) Item(year, id string) (KISAItem, bool)

// internal/controls/usage.go
type CollectorUsage struct { Collector string; Registered, Used, Engine int; Unused []string }
func FactUsage(s *Set, reg *facts.Registry) []CollectorUsage                   // registry order of first appearance; Unused sorted as registered
func UnusedKeys(s *Set, reg *facts.Registry) []string                          // unchanged signature, now derived from FactUsage

// internal/controls/lint.go
type LintOptions struct { CustomFuncs map[string]bool; FixtureDir string; References *ReferenceIndex; KISA *KISAInventory }
// set-level problems: Problem{ControlID: "", Path: "", Rule: "kisa_coverage", Message: ...}; String() prints "controls: <rule>: <msg>" when Path == ""

// internal/controls/references.go
type ReferenceIndex struct { Dir string; ... }                                  // Dir is the directory LoadReferenceIndex was given

// internal/controls/schema.go
Evidence []string `yaml:"evidence,omitempty"`                                  // on Control; manual controls only (lint)

// internal/check
type clauseOutcome struct { ...; Reason string; Vacuous string; Count int }    // Reason: clause-level reason (M-5); Vacuous: param name (M-6); Count: list length (M-33)
type missingFieldError struct{ Field string }                                  // returned by fieldClause; errors.As in evalCollection
func paramName(expected any) (string, bool)                                    // value.go: the ${name} of a param reference, if it is one

// internal/collect/collectors/dropin.go
func mergeDropinsWith(a collect.Access, main string, dirs []string, glob string, parse func([]byte, map[string]string)) (map[string]string, []facts.Source, error) // M-23; mergeDropins wraps it with parseDropin

// cmd/muster
func runSnapshot(args []string, stdout, stderr io.Writer) int                  // snapshot extract
// controls new: runControls(args...) case "new"

// docs/reference/kisa/kisa_deferred.json
[{"id": "U-15", "stage": "3", "reason": "file and directory ownership needs the deep filesystem walk"},
 {"id": "U-23", "stage": "3", "reason": "SUID/SGID/sticky discovery needs the deep filesystem walk"},
 {"id": "U-33", "stage": "3", "reason": "hidden file discovery needs the deep filesystem walk"}]

// docs/reference/capability-matrix.json
{"nonroot": {"denied": ["<fact keys>"]}, "no-systemd": {"unsupported": ["services.ssh.installed", "services.ntp.installed", "services.syslog.installed", "services.ftp.installed"]}}
```

---

### Task 1: the inventory cross-check and lint hardening (M-2, M-4, the `evidence` and `shell_valid_screen` rules)

**Files:** create `internal/controls/kisa.go`, `kisa_test.go`, `docs/reference/kisa/kisa_deferred.json`; modify `internal/controls/lint.go`, `lint_test.go`, `references.go`, `references_test.go`, `schema.go` (the `Evidence` field only — the evaluator side is Task 3), `cmd/muster/controls.go` (`--kisa`, the shape-only note), `controls_test.go`.

**Interfaces:** consumes `Set`, `facts.Registry`, `LoadReferenceIndex`; produces `KISAInventory`, `LoadKISA`, `LintOptions.KISA`, `ReferenceIndex.Dir`, the rules `references_kisa` (existence), `kisa_importance`, `kisa_coverage`, `evidence`, `shell_valid_screen`.

- [ ] **Step 1: Failing tests** (`kisa_test.go`, `lint_test.go`, `references_test.go`, `cmd/muster/controls_test.go`)
```go
// LoadKISA reads the three files of docs/reference/kisa (relative path from the package: ../../docs/reference/kisa) — 67 items under "2026", the 2021 list, three deferrals.
func TestLoadKISAReadsTheInventoryAndDeferrals(t *testing.T) {}
// A missing kisa_items_latest.json is an error naming the file; a missing kisa_deferred.json is an empty list, not an error.
func TestLoadKISAMissingFiles(t *testing.T) {}
// lintOne with KISA set: "2026": ["U-99"] → references_kisa; "1999": ["U-01"] → references_kisa (no inventory for that edition).
func TestLintKISAReferenceMustExistInTheEdition(t *testing.T) {}
// importance 하 on a control citing U-01 (상) → kisa_importance naming both values.
func TestLintKISAImportanceMustMatchTheInventory(t *testing.T) {}
// A two-control set citing U-01 twice → kisa_coverage "U-01 is cited by 2 controls"; a set citing nothing but U-01 → kisa_coverage listing every uncited, undeferred id; a set citing U-15 → kisa_coverage "deferred item U-15 is cited by muster.x.y".
func TestLintKISACoverageIsSetLevel(t *testing.T) {}
// The embedded set with the real inventory: zero problems (this is the gate).
func TestLintEmbeddedSetPassesTheKISACrossCheck(t *testing.T) {}
// LintOptions.KISA nil → none of the three rules fires (shape-only, as before).
func TestLintWithoutInventoryIsShapeOnly(t *testing.T) {}
// evidence: on an auto control → rule "evidence"; on a manual control naming an unregistered key → rule "evidence"; registered keys on a manual control → clean.
func TestLintEvidenceOnlyOnManualControlsAndRegistered(t *testing.T) {}
// a require on shell_valid without a preceding accounts.shells present clause in the same list → shell_valid_screen; with it → clean (system_account_shells.yaml is the shape).
func TestLintShellValidNeedsTheShellsScreen(t *testing.T) {}
// two index files with product "rhel9" → LoadReferenceIndex error naming both files; ReferenceIndex.Dir is the dir given.
func TestLoadReferenceIndexRejectsADuplicateProduct(t *testing.T) {}
// the unindexed-id message names <dir>/stig for a custom dir, not docs/reference/stig.
func TestLintUnindexedMessageNamesTheIndexDir(t *testing.T) {}
// cmd: lint without --references prints the shape-only note on stdout and still "ok: 64 controls"; --kisa missing-dir → exit 1 naming the dir.
func TestControlsLintNotesAndKisaFlag(t *testing.T) {}
```
- [ ] **Step 2: Run red.** `go test ./internal/controls/ ./cmd/muster/ -run 'KISA|Evidence|ShellValid|Duplicate|IndexDir|Notes' -count=1`.
- [ ] **Step 3: Implement.** `kisa.go`: decode the two item files into `[]KISAItem` (the shape `tools/coverage/render.go` already uses), `kisa_deferred.json` into `[]Deferral` (absent file → empty); `lint.go`: inside the control loop, when `opts.KISA != nil`, for each `year, items`: `x.Items[year]` missing → `references_kisa` "no inventory for edition %s"; each id not found → `references_kisa` "%s is not in the %s inventory"; the 2026 item's importance ≠ `c.Importance` → `kisa_importance`. After the loop, when `opts.KISA != nil`: count citations of every 2026 id across the set, then one `kisa_coverage` problem per offence (duplicate, uncited-and-undeferred, deferred-but-cited), messages listing ids sorted. `Problem.String()`: `controls: <rule>: <msg>` when `Path == ""`. `evidence` rule: `len(c.Evidence) > 0 && c.Automation != "manual"` → "evidence is only valid on manual controls"; each key `reg.Lookup` → "evidence key %q is not registered". `shell_valid_screen`: walk each `checks` list and each mechanism's `checks`; when a clause's `Where.Field` or `Require.Field` is `shell_valid` and no earlier clause in that list is `{Fact: "accounts.shells", Op: "present"}` → problem. `references.go`: `Dir` field; duplicate product error. `cmd/muster/controls.go`: `--kisa <dir>` (default `docs/reference/kisa`, `FixtureDirExists`-style check), pass `KISA` in `LintOptions`, print the shape-only note when `references == ""`; usage text updated. Directory checks run in the order fixtures → references → kisa (M-26); `controls_test.go` gains `repoKisa` and the three existing lint tests pass `--kisa repoKisa`. `kisa_coverage` counts 2026 citations only. `LoadReferenceIndex` also rejects an `applies_to` alias that equals another file's product.
- [ ] **Step 4: Gates.** `go test ./internal/controls/ ./cmd/muster/ -count=1`, `go run ./cmd/muster controls lint --references docs/reference` → `ok: 64 controls` with the unused-keys note only; `gofmt -l .`; `go vet ./...`.
- [ ] **Step 5: Commit.** "Cross-check every KISA reference against the inventory and harden the reference lint".

### Task 2: the facts-used report, the deferred rows and the README count guard (M-3, M-20 numbers, `unifiedDiff` test)

**Files:** create `internal/controls/usage.go`, `usage_test.go`, `tools/coverage/main_test.go`; modify `internal/controls/lint.go` (`UnusedKeys` → wrapper), `cmd/muster/controls.go` (the note), `controls_test.go`, `tools/coverage/render.go`, `render_test.go`, `main.go`; regenerate `docs/reference/coverage.md`; change the two numbers only: `README.md:137` `58 of the 67 items` → `64 of the 67 items`, `README.ko.md:123` `58개를` → `64개를` (the line wrap stays — M-24); retarget `controls_test.go:226` to the new note (M-27).

**Interfaces:** consumes `KISAInventory` (Task 1); produces `FactUsage`, the coverage section, the README fragment check.

- [ ] **Step 1: Failing tests**
```go
// A two-collector registry double and a set citing one key → [{a, 2, 1, 0, [a.other]}, {b, 1, 0, 0, [b.k]}]; engine keys count in Engine and not in Unused; order is first appearance in the registry.
func TestFactUsagePerCollectorInRegistryOrder(t *testing.T) {}
// UnusedKeys(set, reg) equals the concatenation of every CollectorUsage.Unused.
func TestUnusedKeysIsDerivedFromFactUsage(t *testing.T) {}
// render(): a deferred item renders "| U-15 | … | — | — | deferred (stage 3) |" and is NOT counted as enrolled; the summary line stays "64 of 67 items enrolled (auto 55, partial 5, manual 4)."
func TestRenderMarksDeferredItems(t *testing.T) {}
// render(): the "## Fact keys used by controls" section carries the summary line and one row per collector with the FactUsage numbers.
func TestRenderFactUsageSection(t *testing.T) {}
// unifiedDiff: a one-line change in the middle yields exactly one hunk with the right offsets; identical inputs yield an empty hunk (@@ -n,0 +n,0 @@).
func TestUnifiedDiffTrimsCommonPrefixAndSuffix(t *testing.T) {}
// -check fails when README.md lacks "64 of the 67 items" or README.ko.md lacks "67개 중 64개"; matching is whitespace-normalised, so a fragment wrapped across a line break passes (temp READMEs under a temp dir passed as -readme-dir).
func TestCheckVerifiesTheReadmeCountFragments(t *testing.T) {}
// cmd: the lint note reads "note: N of M registered fact keys are used by a control (K read by the engine); unused: …".
func TestControlsLintPrintsTheUsageNote(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `usage.go`: mark used keys exactly as `UnusedKeys` does today (plus `Evidence` lists), then walk `reg.Keys` grouping by `Collector` in first-appearance order. `render.go`: `render(items, deferred, usage, set)` — a deferred id renders `deferred (stage <n>)`; append the section:
```
## Fact keys used by controls

N of M registered keys are read by a control (K by the engine); U unused.

| Collector | Registered | Used by a control | Read by the engine | Unused |
|---|---|---|---|---|
| accounts | 22 | 20 | 1 | accounts.x, accounts.y |
```
`main.go`: factor `run(args []string, stderr io.Writer) int` out of `main` (which only calls `os.Exit(run(...))`) so `-check` is testable; load the inventory with `controls.LoadKISA(dir)` (flag `-kisa-dir docs/reference/kisa` replaces `-kisa`), compute `controls.FactUsage`, and in `-check` mode also verify the README fragments (flag `-readme-dir .`) after whitespace normalisation (M-24); the failure message names the fragment and the file. Regenerate `docs/reference/coverage.md`; edit the two README numbers.
- [ ] **Step 4: Gates.** `go test ./tools/coverage/ ./internal/controls/ ./cmd/muster/ -count=1`; `go run ./tools/coverage && go run ./tools/coverage -check`; lint `ok: 64 controls`.
- [ ] **Step 5: Commit.** "Report fact usage per collector in the coverage table and guard the README count".

### Task 3: the evaluator — missing field, vacuous selection, named evidence, manual evidence (M-5, M-6, M-7, M-8)

**Files:** modify `internal/check/collection.go`, `clause.go`, `eval.go`, `value.go`, `collection_test.go`/`clause_test.go`/`eval_test.go` (whichever holds the collection tests today — `clause_test.go:150-243`), `internal/controls/fixtures_test.go`; the four manual controls under `controls/service/` and their `manual-*.json`; regenerate `internal/report/testdata/*.golden` (`go test ./internal/report -run TestJSON -update`, `-run TestTableGolden -update`) and review the diff: only evidence strings of collection clauses may change.

**Interfaces:** consumes `Control.Evidence` (Task 1), `paramRef`; produces `clauseOutcome.Reason/Vacuous`, `missingFieldError`, `paramName`.

- [ ] **Step 1: Failing tests**
```go
// each require on a field one element lacks → Holds false, one failing observation with actual nil, Reason `element user:bob has no field "shell_valid"`; the control is FAIL (WARN on partial), reason_code empty, never internal_error.
func TestEachMissingRequireFieldFailsTheClauseNamingTheField(t *testing.T) {}
// each where on a field one element lacks → the clause fails the same way (never "not selected").
func TestEachMissingWhereFieldFailsNotDeselects(t *testing.T) {}
// none where {field: x, op: eq} on an element lacking x → fails naming the field; present/absent ops keep today's semantics.
func TestNoneMissingFieldFailsExceptPresentAbsent(t *testing.T) {}
// each where literal selecting nothing from 3 elements → PASS with the "item:*" observation "0 of 3 elements selected".
func TestVacuousLiteralSelectionIsObservedNotFailed(t *testing.T) {}
// each where "${facilities}" selecting nothing from 3 elements → MANUAL, reason `parameter "facilities" selected no element of logging.rsyslog.rules (3 elements)`, evidence carries the fact.
func TestVacuousParamSelectionIsManual(t *testing.T) {}
// an empty list with a param where → PASS (2F: a genuinely empty enumeration).
func TestEmptyListStaysAVacuousPass(t *testing.T) {}
// evidence value: each with where → "3 elements; 2 selected; failing: user:bob"; none with two hits → "3 elements; matching: file:/a, file:/b"; six failing → five names then "+1 more"; no where and no failure → "3 elements".
func TestCollectionEvidenceNamesTheSubjects(t *testing.T) {}
// a manual control with evidence: [k1, k2] → the MANUAL result carries evidence for k1 and k2 after the applies_when evidence, deduped.
func TestManualControlAttachesItsEvidenceList(t *testing.T) {}
// fixtures_test: for a control with automation: manual, a manual-*.json result whose evidence carries a status "missing" entry fails the suite (M-25; the walk gate's missing walk.complete on world_writable is not in scope).
func TestManualFixturesCarryEveryEvidenceLeaf(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `value.go`: `paramName`. `collection.go`: `fieldClause` returns `missingFieldError{Field}` for a nil value under any op but present/absent; `evalCollection` — on `errors.As(err, &mf)` from `where` or `require`: append `Observation{Subject: subject, Expected: <sub.Expected substituted>, Actual: nil, Verdict: "fail"}`, set `out.Holds = false`, `out.Reason = fmt.Sprintf("element %s has no field %q", subject, mf.Field)` (first one wins), continue the loop; set `out.Count = len(list)` and count `selected` for `each`; after the loop, when `cl.Op == "each" && cl.Where != nil && len(list) > 0 && selected == 0`: append the `<kind>:*` observation and, if `paramName(cl.Where.Expected)` is a reference, set `out.Vacuous = name` only if `out.Holds` is still true (M-33); build the evidence value string per M-7 (subjects in observation order, capped at five). `eval.go` steps 11-14: after `evalClause`, `if out.Vacuous != "" { res := fail(r, MANUAL, "", fmt.Sprintf("parameter %q selected no element of %s (%d elements)", out.Vacuous, cl.Fact, out.Count)); res.Evidence = append(append(res.Evidence, all.Evidence...), out.Evidence...); res.Observations = append(append(all.Observations, out.Observations...)); return res }`; when `!out.Holds && r.Reason == ""`: prefer `"clause does not hold: " + out.Reason` when set. Step 4: `if len(c.Evidence) > 0 { r.Evidence = dedupeEvidence(append(r.Evidence, e.evidenceFor(c.Evidence)...)) }`. The four control YAMLs gain `evidence:` per M-8; their `manual-*.json` gain the leaves (`ok` values consistent with the file's story). `fixtures_test.go`: after evaluating a `manual-` fixture of a control with `Automation == "manual"`, assert that no evidence status is `missing` (M-25).
- [ ] **Step 4: Gates.** `go test ./internal/... ./cmd/muster/ -count=1` (the report goldens hold no collection-clause evidence, so the `-update` runs are a check — expect byte-identical files); lint `ok: 64 controls`; coverage `-check` (unchanged — no automation change).
- [ ] **Step 5: Commit** in two: "Fail a clause on a missing field, name the judged elements and observe a vacuous selection" and "Attach an evidence list to the four manual controls".

### Task 4: the collect primitives — denied directories, xattr sizing, the redaction header (M-10, M-11, M-15) — LAB

**Files:** modify `internal/collect/registry.go`, `registry_test.go` (Linux, `//go:build linux`), `run.go`, `run_test.go`, `internal/collect/collectors/{env,files_dev,services_super,firewall}.go` and tests, `collectors_test.go` (`fsAccess.deniedDirs map[string]bool` — `Glob` returns `fmt.Errorf("%s: %w", dir, unix.EACCES)` when the pattern's literal directory is in it).

**Interfaces:** consumes `openNoFollow`, `Builder.Keys`, `facts.Registry` (secret keys); produces the denied-directory `Glob`, `run.redaction.redacted_fields`.

- [ ] **Step 1: Failing tests**
```go
// registry_test (linux): a 0000 temp dir under a readable parent → hostAccess.Glob(dir+"/*") returns an error satisfying errors.Is(err, fs.ErrPermission) naming the dir (run only when not root: the test skips under euid 0 with a message, and the lab run repeats it as nobody); a missing dir → (nil, nil); a symlinked dir → whatever filepath.Glob does today (matches listed).
func TestHostGlobReportsADeniedDirectory(t *testing.T) {}
// Getxattr on a temp file with a 100-byte user.x attribute returns exactly 100 bytes (skip when the fs refuses user xattrs).
func TestGetxattrSizesTheBuffer(t *testing.T) {}
// run_test: a double whose collector sets snmp.communities ok and snmp.v3_users absent → redacted_fields == ["snmp.communities"]; no secret key ok → the field absent from the JSON.
func TestRunRecordsRedactedFields(t *testing.T) {}
// collectors: env — profile.d denied → every leaf derived from the read order carries the denied status (C3), path-prefixed; files_dev — /dev/* denied → the dev leaves denied; services_super — xinetd fragments denied → the xinetd-derived leaves denied; firewall — decide per the audit table and pin it.
func TestProfileDDeniedIsTheAnswer(t *testing.T) {}
func TestDevGlobDeniedIsTheAnswer(t *testing.T) {}
func TestXinetdGlobDeniedIsTheAnswer(t *testing.T) {}
// cron (already routes the error): a denied spool dir → cron.files/cron.dirs denied — a new test in collectors_test.go (there is no cron_test.go; 2F removed the misleading cases rather than keeping a double).
func TestCronDeniedSpoolIsDenied(t *testing.T) {}
```
- [ ] **Step 2: Run red** (cross-compile on Windows; the Linux run on the lab host).
- [ ] **Step 3: Implement.** `registry.go`: `globDir(pattern) string` (the literal prefix per M-10, `path.Clean`ed first so a dynamic pattern with a trailing slash still probes) and the probe in `hostAccess.Glob`; `Getxattr` per M-11. `run.go`: after the collector loop, `hdr.Redaction.RedactedFields = redactedFields(b, reg)` — every `facts.Entry` with `Sensitivity == "secret"` whose leaf (`b.leaf(key)`) is an `Envelope` with `StatusOK`, sorted. Audit the 25 call sites into the report as a table `file:line | today | after | leaves affected`; change the four sites named in M-10 as the audit found them: `env.go:88` — `profileReadOrder` returns the Glob error so `runEnv` writes the seven `envShellKeys` with the denied status (C3); `files_dev.go:38` — route to `files.dev_entries`/`files.dev_nondevice` the way `files.go:129-136` routes `mountsErr`; `services_super.go:132` — `s.noteReadError(xinetdGlob, err)` so the super-server evidence carries it; `firewall.go:785-788` — keep ignoring with a comment: the sibling `statExists(firewalldConf)` is masked by the same non-searchable directory and the ruleset capture is the path that reports.
- [ ] **Step 4: Lab.** `lab-sync.sh` then `lab-run.sh`: `go test ./internal/collect/... -count=1` as root AND `runuser -u nobody -- go test ./internal/collect/ -run TestHostGlob -count=1`; build, root `collect --require-root --require-complete` (exit 0); `runuser -u nobody -- muster collect --out -` → `.facts.cron.files.status == "denied"` and `.facts.cron.dirs.status == "denied"` (quote those two lines only); count `rsyslog.rules` rows and the snapshot size (record in the report — M-1). Windows gates as in M-22.
- [ ] **Step 5: Commit** in two: "Report a directory Glob was denied and size xattr reads exactly" and "Record the secret keys stored in reduced form in the redaction header".

### Task 5: the collector conventions — undeclared paths, unreadable rhosts, pam drop-ins (M-12, M-13, M-14) — LAB

**Files:** modify `internal/collect/collectors/sshd.go` (S6), `files_home.go` (S1, S2), `pam_derive.go` (M-14) and their tests; create fixtures `controls/testdata/muster.service.login_banner/manual-banner-undeclared.json`, `muster.file.home_dir_exists/manual-home-undeclared.json`, `muster.file.home_dir_permissions/manual-home-undeclared.json`, `muster.file.rhosts_forbidden/error-rhosts-denied.json` (`_expect.reason_code: permission_denied`).

**Interfaces:** consumes `declared()`, `mergeDropins`, `FromReadError`; produces the C4 behaviour the docs describe in Task 8.

- [ ] **Step 1: Failing tests**
```go
// Banner /etc/ssh/banner.txt (undeclared) → sshd.banner_file.exists and .nonempty absent with reason "Banner /etc/ssh/banner.txt is outside the collector's declaration: recorded, never read"; the run stays complete (Worst ok).
func TestSshdUndeclaredBannerIsAbsentNotError(t *testing.T) {}
// an interactive account with home /srv/app → files.home_dirs absent with reason naming "app (/srv/app)"; two such accounts → both named, sorted by user; a NON-interactive account with an undeclared home keeps its denied row and the leaf stays ok (M-32); no such account → today's rows.
func TestHomeOutsideTheDeclarationMakesTheLeafAbsent(t *testing.T) {}
// /home/bob/.rhosts EACCES → files.user_rhosts denied, reason "/home/bob/.rhosts: …" (readErrorEnv, M-30); a symlinked .rhosts → error; ENOENT → no row, leaf ok.
func TestUnreadableRhostsIsDenied(t *testing.T) {}
// pwquality: conf + conf.d/{10-a,20-b}.conf → last file wins per key; a bare "enforce_for_root" line in 20-b.conf sets the flag (M-23); a denied 10-a.conf poisons every derived value (R148); an absent conf.d dir is fine; inputs list the files read in order.
func TestPwqualityDropinsMergeLikeSystemd(t *testing.T) {}
// fixtures: the four new fixtures evaluate to MANUAL / MANUAL / MANUAL / ERROR(permission_denied).
// existing: TestSshdBannerOutsideDeclarationIsRecordedNotRead (collectors_test.go:492) now asserts StatusAbsent and the "recorded, never read" reason (M-32).
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `sshd.go:378-384`: replace `ErrorEnv` with `collect.Absent(...)` + the reason. `files_home.go:45-52`: collect the undeclared homes of INTERACTIVE rows only (`interactive(r.shell, shells)`), keep today's denied row for the others; after the loop, if any were collected: return `collect.Absent("home path outside the collector's declaration: " + strings.Join(names, ", "))` with names sorted by user (source unchanged). `userRhosts` `scan`: on a read error other than ENOENT keep the FIRST `readErrorEnv(p, err)` in a local variable and return it instead of the list (M-30). `dropin.go`: `mergeDropinsWith(..., parse)` + `mergeDropins` wrapper (M-23); `pam_derive.go:160-180`: the `readKV`+`Glob` block becomes one `mergeDropinsWith(a, pwqualityConf, []string{"/etc/security/pwquality.conf.d"}, "*.conf", parseKVInto)` call where `parseKVInto(data, values)` applies `parseKV` semantics into the shared map; keep `apply(kv)` semantics (values map → the same keys).
- [ ] **Step 4: Lab.** Linux suite as root; root collect complete; `check` on the lab snapshot shows U-62/U-31/U-32/U-27 unchanged on the stock host (no undeclared home, no `.rhosts`); quote the four status lines only. Windows gates; lint `ok: 64 controls`; coverage `-check`.
- [ ] **Step 5: Commit** in two: "Record an undeclared banner or home as absent and an unreadable rhosts as denied" and "Merge pwquality drop-ins through the shared helper".

### Task 6: `controls new` and `snapshot extract` (M-16)

**Files:** modify `cmd/muster/controls.go`, `controls_test.go`, `main.go` (usage: `snapshot   extract the leaves a control reads from a snapshot into a fixture skeleton`); create `cmd/muster/snapshot.go`, `snapshot_test.go`.

**Interfaces:** consumes `controls.LoadKISA` (Task 1), `Control.Evidence` (Task 3), `facts.Load`, `Registry.Resolve`; produces the two subcommands.

- [ ] **Step 1: Failing tests**
```go
// controls new muster.file.example --kisa-id U-15 --out <tmp> --fixtures <tmp2> → <tmp>/file/example.yaml decodes strictly (write a VERSION file into <tmp> and call controls.LoadFS(os.DirFS(tmp)), which walks every *.yaml), importance 상, references.kisa {"2026": ["U-15"], "2021": ["U-06"]} (kisa_mapping.json: the entry with latest_id U-15 has from_2021 ["U-06"]), two synthetic fixture stubs; a second run → exit 1 "exists", nothing overwritten; a bad id → exit 1 with the id rule; an unknown --kisa-id → exit 1.
func TestControlsNewWritesASkeletonAndRefusesToOverwrite(t *testing.T) {}
// The skeleton for automation manual carries manual_reason and evidence placeholders and no checks.
func TestControlsNewManualShape(t *testing.T) {}
// snapshot extract --facts testdata/full-pass.json --control muster.file.ip_port_restriction --out <tmp>/f.json → exactly the keys U-28 reads (applies_when + every mechanism's when/checks) present, nothing else under facts, schema_version copied, run {}, synthetic false, _provenance {muster_version, collected_at, os_id, os_version_id} with no host name; the file feeds facts.Load and evaluates U-28 to the same status as the full snapshot.
func TestSnapshotExtractKeepsOnlyWhatTheControlReads(t *testing.T) {}
// a walk-based control adds walk.complete; a manual control adds its evidence keys; an unknown control id → exit 1.
func TestSnapshotExtractWalkAndEvidenceKeys(t *testing.T) {}
// two runs produce identical bytes.
func TestSnapshotExtractIsDeterministic(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `controls new`: validate the id with lint's `idRe` (export `ValidControlID`), derive `<area>/<name>`, look the item up in the inventory and the 2021 ids in `kisa_mapping.json` (the object under `mapping` whose `latest_id` matches; its `from_2021` list is the `"2021"` value), write the YAML with `yaml.v3` from a `Control` value so it decodes strictly, and the two stubs `{"synthetic": true, "schema_version": 1, "run": {}, "facts": {}, "_expect": {}}`. `snapshot extract`: load the set and registry, collect the control's fact keys (dedupe, sorted), for each key copy the leaf from the raw `Snapshot.Facts` tree (never through `Registry.Resolve`, which re-decodes — the copy must be byte-faithful for envelopes and settings alike) and place it at its dotted path exactly as `Builder.place` does; `main.go` gains `case "snapshot": return runSnapshot(args[1:], stdout, stderr)` and a usage line, emit with `json.MarshalIndent` and sorted keys.
- [ ] **Step 4: Gates.** `go test ./cmd/muster/ -count=1`; both commands run from the repo root once by hand into a temp dir (nothing committed).
- [ ] **Step 5: Commit.** "Add controls new and snapshot extract for the fixture workflow".

### Task 7: the U-28 gate, exhaustive e2e, the capability matrix and the set version (M-9, M-17, M-18, M-19)

**Files:** modify `controls/file/ip_port_restriction.yaml` + its six fixtures (+ `fail-tcpwrappers-no-libwrap.json`), `cmd/muster/testdata/full-pass.json`, `full-fail.json` (add `files.libwrap_present` `{"status":"ok","value":true}` — M-31; add the M-8 evidence leaves of the four manual controls so their e2e MANUAL rows carry no `missing` evidence; update `run.controls_version`), `cmd/muster/e2e_test.go` (M-17), `controls/VERSION`, `.github/workflows/ci.yml`; create `docs/reference/capability-matrix.json`; change the `ControlsVersion` literals in `internal/report/report_test.go:36` and `table_test.go:153` and regenerate the report goldens (M-29).

**Interfaces:** consumes M-10's `denied` cron leaves (for the matrix), the lab non-root snapshot; produces the matrix file and the CI steps.

- [ ] **Step 1: Failing tests**
```go
// U-28 fixtures: deny-all + libwrap ok:true + backend none → PASS (mechanism 1); deny-all + libwrap ok:false + backend none → FAIL (mechanism 3); deny-all + libwrap ok:false + backend nftables restricting → PASS (mechanism 2); every fixture carries files.libwrap_present as an ok bool (M-31).
// e2e: assertStatuses with a want map missing one loaded id fails; with an extra id fails (refactor the helper to return an error and keep a t.Helper wrapper); the waiver test's map at e2e_test.go:78 is extended to all 64 ids (M-28).
func TestAssertStatusesIsExhaustive(t *testing.T) {}
// capability-matrix.json parses; every key in it is registered; the two status words are the vocabulary.
func TestCapabilityMatrixNamesRegisteredKeys(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** YAML per M-9; fixtures; `assertStatuses` per M-17 (loaded ids via `controls.LoadDefault`); `capability-matrix.json` per M-18 with the non-root list derived from the lab host's `runuser -u nobody` snapshot (record the derivation in the report; at least five plain-envelope keys from three collectors, only keys `denied` on both families by a content read — M-34's candidates; never a setting, never a `files.*.{mode,uid,gid}` leaf, never a key whose status depends on an installed package); `ci.yml`: in `collect-nonroot` after the report step and in `collect-containers` under `if [ "${{ matrix.init }}" = "false" ]`, one step:
```sh
jq -e --slurpfile m docs/reference/capability-matrix.json '
  [ $m[0].nonroot.denied[] as $k | ($k | split(".")) as $p | (.facts | getpath($p) | .status) | select(. != "denied") ] | length == 0' "$RUNNER_TEMP/muster/user.json"
```
(the container variant reads `$m[0]["no-systemd"].unsupported`, tests `"unsupported"` and runs against `"$RUNNER_TEMP/muster/containers/c.json"`); `controls/VERSION` → `kisa-unix-2026+2026.09.09`; change the two `ControlsVersion` literals (M-29), regenerate the report goldens and review that only the version differs.
- [ ] **Step 4: Gates.** Full Windows gate list (M-22); `git merge-base HEAD main` is main's tip; `git log --oneline main..HEAD` reviewed; gitleaks over the branch; the grep for host/org strings → 0.
- [ ] **Step 5: Commit** in two: "Gate the tcp_wrappers mechanism of U-28 on libwrap and make the e2e status maps exhaustive" and "Add the capability matrix to CI and bump the control set version".

### Task 8 (controller): the documents (M-12 C4, M-19, M-20, M-21)

**Files:** `README.md`, `README.ko.md` (roadmap item 2 rewritten to the M-20 wording; both keep the exact count fragments Task 2 guards), `CONTRIBUTING.md` + `CONTRIBUTING.ko.md` (adding a control: `controls new` → fixtures via `snapshot extract` from a public image or by hand, marked `synthetic: true` → `controls lint` → `go test` → `make coverage`; conventions C1–C4 verbatim from `CLAUDE.md`; fixture rules; commit identity and attribution; the security rules — no organisation, host, address or credential in any tracked file, no snapshot captured from a private host), `CHANGELOG.md` (M-19), `CLAUDE.md` (C4 under Stage-2 conventions; `make lint-controls` note unchanged), then the Execution notes appended to this plan.

- [ ] **Step 1:** Write the four documents and the C4 line; `go run ./tools/coverage -check` (the README guard) green; `gofmt`/`vet` untouched.
- [ ] **Step 2: Commit.** "Describe the contribution workflow, the C4 convention and the stage-2 changelog".
- [ ] **Step 3:** Whole-branch review (ultracode workflow), one fix wave, scoped re-review, Execution notes, ledger backup, final gates, merge menu.

## Self-Review

**1. Spec coverage.** Line 345 (cross-check for missing/duplicated KISA references) → Task 1 `kisa_coverage` + `references_kisa` existence; the "missing" half is honest only because `kisa_deferred.json` names the three walk items with a reason. Line 454 (facts-used over facts-collected report) → Task 2 section in `coverage.md` + the lint note. Line 466 (capability matrix) → Task 7 M-18. Line 483 (`CONTRIBUTING.md`, `controls new`) and line 454 (`snapshot extract`) → Tasks 6 and 8. Line 206 (missing field fails the clause naming the field) → Task 3 M-5. Line 202 / D13 (`run.redaction` says what the file contains) → Task 4 M-15. Line 220 / D16 (set version, changelog) → Task 7 + Task 8. Line 436 (walk items stay in stage 3) → deferred, not stubbed. Parked items: 2A ×6 (Tasks 1, 2, 3, 4), 2B ×3 (Tasks 1, 3; `rounds` parked), 2C (M-12), 2D-S6 (Task 5), 2E-S1/S2 (Task 5), 2F R204 (Task 4), 2H→2L libwrap (Task 7), 2I ×3 (Tasks 3, 4, 5), 2J J-7 (Task 4), 2L ×3 (Tasks 2, 3; LR-16 by M-12).

**2. Placeholder scan.** Every test is named with its assertion; the skeleton YAML of `controls new` is described field by field; the jq step is written out; the two README fragments are literal. The `kisa_mapping.json` field names (`latest_id`, `from_2021`) were read from the file while writing this plan.

**3. Type consistency.** `LintOptions.KISA *KISAInventory` (Task 1) is what Task 2's `tools/coverage` also loads via `LoadKISA`; `Control.Evidence []string` is added in Task 1 (schema) and consumed in Task 3 (evaluator, fixtures) and Task 6 (`snapshot extract`); `clauseOutcome.Reason/Vacuous/Count` are read only inside `internal/check`; `mergeDropinsWith` (Task 5) keeps `mergeDropins`' callers (journald, timesync) untouched; `fsAccess.deniedDirs` (Task 4) is what Task 5 does not need; `FactUsage` returns `[]CollectorUsage` in both callers. Count literals: `ok: 64 controls` unchanged throughout; automation counts unchanged, so the coverage summary line is unchanged and only the deferred rows and the new section move.
