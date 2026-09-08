# Stage 2L — FTP, mail and DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enrol the twelve remaining daemon items of the KISA 2026 Unix guide — U-35, U-45, U-46, U-47, U-48, U-49, U-50, U-51, U-53, U-54, U-56, U-57 — through three small evidence collectors (`ftp`, `mail`, `dns`), three new rows of the services table and a `libwrap` presence fact, judging eight of them automatically and enrolling four as MANUAL with evidence. **Control set 52 → 64 (auto 55, partial 5, manual 4).**

**Architecture:** Three collectors that read configuration files only and never invoke a daemon binary (D14): `ftp` parses vsftpd's flat `key=value` file (plus a minimal proftpd/pure-ftpd model) into anonymous/TLS/user-list/banner leaves and the effective access-control files; `mail` reads postfix `main.cf` and sendmail's `O PrivacyOptions=` line into flat evidence leaves and one derived `expn_vrfy_restricted`; `dns` parses the `named.conf` include chain (top-level `options`, `zone`, `acl` blocks only) into per-zone `transfer_restricted`/`update_restricted` records. Every construct outside the model counts in an `unmodelled` leaf and makes the judged leaves ABSENT → MANUAL (H-16: under-claim, never over-claim). Implementations are detected by configuration file AND binary (the 2I IR-7 lesson: a conffile left behind by a removed package must not drive a verdict). The four items whose criterion is a version/advisory match (U-45, U-49) or a semantics muster does not model (U-46, U-47) ship as `automation: manual` — the first manual controls in the set — gated by `applies_when` so a host without the daemon reads NOT_APPLICABLE.

**Tech Stack:** Go 1.25 (`internal/collect/collectors`, Linux build tag), YAML controls under `controls/service/`, the `fsAccess` test double, the lab host for the Linux-only suite.

**Spec:** `docs/superpowers/specs/2026-09-02-muster-design.md` (D09 params, D14 never invoke daemons, D24 no advisory matching, §5.6 embedded lists, §6.5 status order, §7.3 MANUAL below confidence). Scope brief: the session scratchpad `2l-scope-brief.md`. Boundary rulings from 2G (U-54/U-35 belong here) and 2H (the libwrap gate parked to U-56).

## Global Constraints

- **Branch base:** `stage2l-ftp-mail-dns` @ `f6ddbca` (post-2I main, PRE-2J). Plan 2J merges before this plan's last task; **Task 7 rebases onto the post-2J main** and only then reconciles the counts (52 → 64) and writes U-45/U-49, whose evidence gates cite 2J's `patch.*` keys (Ruling L-6). Registry entries go in ONE contiguous block at the END of `internal/facts/registry.yaml` (`LoadRegistry` rejects duplicate keys; 2J's block will sit above ours after the rebase). `since: 1`, `schema_version` stays 1, the facts golden diff is additions-only.
- **Ruling L-1 (scope):** twelve items, all `category: service`, ids `muster.service.{ftp_anonymous (U-35), mail_version (U-45), mail_user_execution (U-46), mail_relay (U-47), mail_expn_vrfy (U-48), dns_version (U-49), dns_zone_transfer (U-50), dns_dynamic_update (U-51), ftp_banner (U-53), ftp_unencrypted (U-54), ftpusers_permissions (U-56), ftpusers_root (U-57)}`. Automation: U-35/48/50/51/53/54/56/57 `auto`; U-45/46/47/49 `manual` (with `manual_reason`). KISA ids from `docs/reference/kisa/kisa_mapping.json`: U-35 ← 2021 U-20; U-45 ← U-30; U-46 ← U-32; U-47 ← U-31; U-48 ← U-70; U-49 ← U-33; U-50 ← U-34; U-51 new (`"2021": []`); U-53 new; U-54 ← U-61; U-56 ← U-63; U-57 ← U-64. Importance: U-35/45/46/47/49/50 상; U-48/51/54/57 중; U-53/56 하.
- **Ruling L-2 (no daemon invocation, no version facts):** none of the three collectors declares a command (`Needs: "none"`, `Declare.Commands` empty). No `vsftpd -v`, `named -v`, `postconf`. There is no `ftp.version`/`mail.version`/`dns.version` fact; version-to-advisory matching is never automated (D24) — U-45/U-49 are MANUAL, and the host's patch state (2J's `patch.metadata_age_s` / `patch.pending_security_count`) is in the snapshot for the operator; their gates never cite `patch.*` (Ruling L-6).
- **Ruling L-3 (implementation = conffile AND binary):** `ftp.implementation` is `vsftpd` iff `/etc/vsftpd.conf` or `/etc/vsftpd/vsftpd.conf` is readable AND `/usr/sbin/vsftpd` exists; `proftpd` iff `/etc/proftpd/proftpd.conf` or `/etc/proftpd.conf` AND `/usr/sbin/proftpd`; `pure-ftpd` iff `/etc/pure-ftpd/` (dir) or `/etc/pure-ftpd/pure-ftpd.conf` AND `/usr/sbin/pure-ftpd`; else `none`. `mail.implementation`: `postfix` (`/etc/postfix/main.cf` + `/usr/sbin/postfix`), `sendmail` (`/etc/mail/sendmail.cf` + `/usr/sbin/sendmail.sendmail` or `/usr/sbin/sendmail-mta`), `exim` (`/etc/exim4/update-exim4.conf.conf` or `/etc/exim/exim.conf` + `/usr/sbin/exim4` or `/usr/sbin/exim`), else `none`. `dns.implementation`: `bind` (`/etc/bind/named.conf` or `/etc/named.conf` + `/usr/sbin/named`), `unbound` (`/etc/unbound/unbound.conf` + `/usr/sbin/unbound`), else `none`. A conffile without its binary → `none` with a reason naming the leftover file. The binary probes are guarded `Stat`s of literal `Declare.Reads` entries.
- **Ruling L-4 (H-16 under-claim):** each parser has an explicit model; a construct outside it increments `<collector>.unmodelled` and makes every JUDGED leaf of that collector ABSENT (`absent_means: manual`). vsftpd: extra `*.conf` instances under `/etc/vsftpd/` → unmodelled. proftpd: `<VirtualHost>`, `<Global>`, `<IfModule>` wrapping a modelled directive, `Include` outside the declaration → unmodelled. named.conf: `view`, an ACL name that is not defined in the parsed chain, a nested `{}` inside an address-match list, an `include` outside the declaration → unmodelled. Evidence leaves (`config_files`, raw parameter strings, `parse_complete`) stay `ok`.
- **Ruling L-5 (read guard):** every Stat/Glob/Read matches the collector's `Declare.Reads` (`path.Match`, one `*` per segment). Config-supplied paths (vsftpd `userlist_file`, `banner_file`, `chroot_list_file`; PAM `pam_listfile … file=`; proftpd `Include`; named `include`, zone `file`) go through the `declared()` probe (`sshd.go`): read when covered, otherwise RECORDED (path in the reason, `parse_complete false`/unmodelled) and never touched.
- **Ruling L-6 (2J seam):** this plan does NOT quote or add `packages.installed`. U-45 and U-49 are written in Task 7, after the rebase, so that their descriptions and `manual_reason` can name 2J's `patch.*` leaves as the operator's evidence — but their `applies_when` gates cite `services.<x>.installed eq true` and `<x>.implementation present` ONLY: `present` does not gate on ok (I-21), and an `absent` `patch.metadata_age_s` on a no-cache host must never flip a MANUAL control to NOT_APPLICABLE. (Ruling L-11 explains why a manual control cannot list extra evidence facts in v1.)
- **Ruling L-7 (honest degradation, R220/H-17):** an ENOENT on any candidate is `absent`/`ok:false` as the model says; an EACCES on an existing file → `FromReadError` → `denied` (honest ERROR; vsftpd.conf is 0644 on both distros, `/etc/pam.d/vsftpd` 0644, `named.conf` 0640 root:named on RHEL → non-root `denied` — expected and honest); never `error` for an environment limitation; never `missing`. `collect-contract` (`--read-only --network none`, no daemons) must stay `run.complete == true`: with no conffiles every judged leaf is `absent` (or `ok:false` where the model says so) and every evidence leaf `ok`.
- **Ruling L-8 (services rows):** three rows appended to `var services` (services.go), registered as 5 keys each (`installed, active, unit_file_state, enabled, reachable`): `ftp` units `vsftpd.service`, `vsftpd.socket`, `vsftpd@.service`? — NO template units (probeUnits takes concrete names): `vsftpd.service`, `vsftpd.socket`, `proftpd.service`, `proftpd.socket`, `pure-ftpd.service`, `pure-ftpd-mysql.service`? — keep `pure-ftpd.service` only; `inetdNames: ftp`, `servers: vsftpd, proftpd, in.ftpd, pure-ftpd`, `ports: tcp 21`. `mail` units `postfix.service`, `postfix@-.service`, `sendmail.service`, `exim4.service`, `exim.service`; no inetd; `ports: tcp 25`. `dns` units `named.service`, `bind9.service`, `named-chroot.service`, `unbound.service`; no inetd; `ports: udp 53, tcp 53`. All `provesInstall: true` (genuinely new units, R63).
- **Ruling L-9 (libwrap):** `files.libwrap_present` (bool, collector `files`) = a guarded Stat succeeds on any of `/usr/lib/x86_64-linux-gnu/libwrap.so.0`, `/usr/lib/aarch64-linux-gnu/libwrap.so.0`, `/usr/lib64/libwrap.so.0`, `/lib64/libwrap.so.0`, `/usr/lib/libwrap.so.0`; ENOENT on all → `ok:false`. Consumed by U-56's tcp_wrappers mechanism (the 2H S1 gap: RHEL 8+ ships no libwrap, so `tcp_wrappers=YES` and a `hosts.deny` deny-all restrict nothing there). U-28 is NOT amended in this plan (2M may add the same gate).
- **Ruling L-10 (mail scope):** no permission facts of the MTA binaries (`/usr/sbin/sendmail` is a symlink on postfix hosts and the no-follow read primitive refuses it — an `error` there would flip `run.complete`). U-46's evidence is the flat `authorized_submit_users` (postfix) / `privacy_options` (sendmail) leaves.
- **Ruling L-11 (MANUAL evidence in v1):** `internal/check/eval.go:85-92` returns at step 4 for `automation: manual` with `Reason = manual_reason` and whatever evidence `applies_when` accumulated (M10). `checks` are never evaluated for a manual control, and there is no `evidence:` field. Therefore a manual control's attached evidence is exactly its `applies_when` facts: use `[{ services.<x>.installed eq true }, { <x>.implementation present }]` (`implementation` is always `ok`, so the second clause cannot screen). The detailed leaves are in the snapshot for the operator. An `evidence:` list for manual controls is parked to 2M.
- **Ruling L-12 (references):** `references.kisa` only for all twelve. The four indexed RHEL 9 rules (`RHEL-09-215015` FTP package absent, `215020` sendmail absent, `215101` postfix present, `672050` bind crypto policy) judge package presence or crypto policy — opposite or unrelated polarity — and neither Ubuntu benchmark has an FTP/mail/DNS rule. No `make refindex`.
- **Ruling L-13 (fixtures and e2e, H-15):** every fixture address is RFC 5737 / `example.org`; `synthetic: true`; the eight auto controls are PASS in BOTH shared e2e fixtures; the four manual controls appear as the fixed string `"MANUAL"` in both e2e maps (the `muster.file.world_writable` precedent, `cmd/muster/e2e_test.go:200,264`) with their gate facts `ok:true` in both fixtures so the MANUAL branch is exercised; the waiver e2e literal (`Applied != 10 || Unknown != 1`) is untouched. A `manual` control is exempt from the pass-/fail- pair (`fixtures_test.go:107-113`) but ships `manual-*.json` and `na-*.json`; every fixture carries EVERY leaf the selected mechanism's `when`/`checks` and `applies_when` read.
- **Ruling L-14 (grammar, verified in 2I):** `each` = `{fact, op: each, subject, where?, require}` with ONE `require` (two requirements = two `each` clauses); list params substitute QUOTED `"${name}"`; `mechanisms[]` has no `name` (use `#` comments); `applies_when op: present` holds for `ok:false` (gate with `eq true`); an `absent` fact read by the chosen mechanism screens the control via `absent_means` before clauses run; `mergeSoft`: `unsupported` beats `absent` (a MANUAL shape needs `absent`); `risk` ∈ none|restart_service|reboot_required|lockout_risk; `subject_kind` ∈ file|dir|user|group|unit|port|module|mount|key|facility|zone (list types only). "Mode ≤ NNN" is `op: in` over the subsets of NNN (copy the shape of `controls/file/passwd_permissions.yaml`).
- **Determinism:** records sorted (access files by path; zones by name; config_files by path); no map iteration reaches a value; no `time.Now`. **Attribution:** no KISA/CIS text; descriptions in muster's own words. **Lab:** the LAB TOKEN is 2J's until 2J merges — 2L's Linux-only tests are cross-compiled (`GOOS=linux GOARCH=amd64 go vet ./... && go test -c ./internal/collect/collectors/ -o NUL`) until the token passes to 2L; CI runs them.

## File Structure

- Create `internal/collect/collectors/ftp.go` — `ftp` collector: implementation, config chain, vsftpd flat parse, proftpd/pure-ftpd minimal models, access files, banner. `ftp_test.go` + `testdata/vsftpd.conf.*`, `proftpd.conf.*`, `pam.d.vsftpd.*`, `ftpusers.*`, `user_list.*`.
- Create `internal/collect/collectors/mail.go` — `mail` collector: implementation, `main.cf` flat parse (continuations), `sendmail.cf` `O PrivacyOptions`, `expn_vrfy_restricted`. `mail_test.go` + `testdata/main.cf.*`, `sendmail.cf.*`.
- Create `internal/collect/collectors/dns.go` — `dns` collector: implementation, named.conf tokenizer + top-level block parser with includes and ACL resolution, zones. `dns_test.go` + `testdata/named.conf.*`.
- Modify `internal/collect/collectors/services.go` — three rows appended to `var services` (L-8).
- Modify `internal/collect/collectors/files.go` (the `files` collector) — `files.libwrap_present` (L-9), declared paths.
- Modify `internal/collect/collectors/register.go` — register `ftp`, `mail`, `dns`.
- Modify `internal/facts/registry.yaml` + `internal/facts/testdata/facts-schema.golden.json` — one contiguous EOF block (≈47 keys).
- Create `controls/service/ftp_anonymous.yaml`, `ftp_banner.yaml`, `ftp_unencrypted.yaml`, `ftpusers_permissions.yaml`, `ftpusers_root.yaml`, `mail_expn_vrfy.yaml`, `mail_user_execution.yaml`, `mail_relay.yaml`, `dns_zone_transfer.yaml`, `dns_dynamic_update.yaml` (Tasks 5–6) and `mail_version.yaml`, `dns_version.yaml` (Task 7) + `controls/testdata/<id>/*.json`.
- Modify (Task 7 only) `cmd/muster/controls_test.go`, `cmd/muster/e2e_test.go`, `cmd/muster/testdata/full-{pass,fail}.json`, `docs/reference/coverage.md` (regenerated).

## Interfaces (produced by this plan)

Registry keys (all `since: 1`; `sensitivity: public` unless noted; collector as named):

- `services.{ftp,mail,dns}.{installed,active,unit_file_state,enabled,reachable}` — 15 keys, collector `services`, the 2G shapes verbatim (`reachable` bool: the fixed port has a listener).
- `files.libwrap_present` bool — collector `files` (L-9).
- `ftp.implementation` string (`vsftpd|proftpd|pure-ftpd|none`, always ok); `ftp.config_files` list<string> (`subject_kind: file`; files actually read, sorted); `ftp.parse_complete` bool; `ftp.unmodelled` int; `ftp.local_enabled` bool (vsftpd `local_enable`, default NO; proftpd/pure-ftpd true); `ftp.anonymous_enabled` bool (vsftpd `anonymous_enable`, DEFAULT YES when unset — the compiled default; proftpd: an `<Anonymous` block exists; pure-ftpd: `NoAnonymous` is not `yes`); `ftp.tls_enforced` bool (vsftpd: `ssl_enable=YES` AND `force_local_logins_ssl`≠NO AND `force_local_data_ssl`≠NO (both default YES) AND (`anonymous_enable=NO` OR `force_anon_logins_ssl=YES` AND `force_anon_data_ssl=YES`); proftpd: `TLSEngine on` AND `TLSRequired on` at top level; pure-ftpd: `TLS` ≥ 2); `ftp.tcp_wrappers` bool (vsftpd `tcp_wrappers`, default NO; proftpd: absent; pure-ftpd: absent); `ftp.userlist_enable` bool (default NO), `ftp.userlist_deny` bool (default YES), `ftp.userlist_file` string (explicit value, else the distro default `/etc/vsftpd.user_list` (Debian build) / `/etc/vsftpd/user_list` (RHEL build) — whichever candidate exists; absent when neither); `ftp.access_files` list<record> `{path, role (pam_deny|userlist_deny|userlist_allow|ftpusers), exists, root_listed, mode, uid, gid, stat_status}` (`subject_kind: file`; sorted by path; the PAM deny file(s) from `/etc/pam.d/vsftpd` `pam_listfile.so … sense=deny file=X`, the vsftpd user list with its role from `userlist_deny`, proftpd's `/etc/ftpusers` when `UseFtpUsers` is not `off`); `ftp.access_file_present` bool (any record `exists`); `ftp.root_denied` bool (vsftpd: `local_enable=NO`, OR root listed in a `pam_deny`/`userlist_deny` file, OR `userlist_allow` exists and does NOT list root; proftpd: `RootLogin` is not `on` (default off) OR root listed in `/etc/ftpusers` with `UseFtpUsers` on; pure-ftpd: always true — `MinUID` ≥ 1 by design, evidence reason); `ftp.banner_source` string (`ftpd_banner|banner_file|serverident|default|none`); `ftp.banner_text` string (the configured text; the compiled default text is NOT invented — `default` source carries an empty text and the reason names the product); `ftp.banner_discloses_version` bool (vsftpd: `default` source → true; `ftpd_banner`/`banner_file` text matching `(?i)\b(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)\b` → true, else false; proftpd: `ServerIdent off` → false, `ServerIdent on "text"` → the pattern, unset → true (the product's default ident names it); pure-ftpd → ABSENT "banner is not configurable in this version's model"). ≈ 17 keys; `sensitivity: internal` for `banner_text`.
- `mail.implementation` string (`postfix|sendmail|exim|none`); `mail.config_files` list<string>; `mail.postfix.inet_interfaces`, `mail.postfix.mynetworks`, `mail.postfix.smtpd_relay_restrictions`, `mail.postfix.smtpd_recipient_restrictions`, `mail.postfix.disable_vrfy_command`, `mail.postfix.authorized_submit_users` — string each, the raw `main.cf` value (`$name` references left unexpanded), ABSENT when the key is unset with the reason naming postfix's compiled default (`all`, computed, `permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination`, empty, `no`, `static:anyone`); `mail.sendmail.privacy_options` list<string> (the `O PrivacyOptions=` list with `goaway` expanded to `authwarnings, needmailhelo, needexpnhelo, noexpn, needvrfyhelo, novrfy, noetrn, nobodyreturn, noreceipts`; sorted); `mail.expn_vrfy_restricted` bool (postfix: `disable_vrfy_command` is `yes` — postfix implements no EXPN; sendmail: `novrfy` AND `noexpn` present after expansion; exim: ABSENT "exim ACLs are not modelled"). 10 keys.
- `dns.implementation` string (`bind|unbound|none`); `dns.config_files` list<string>; `dns.parse_complete` bool; `dns.unmodelled` int; `dns.options.allow_transfer` string (the rendered address-match list of `options { allow-transfer {…} }`, ABSENT when unset with reason "not set; BIND 9.16/9.18 default is any"); `dns.options.allow_update` string (ABSENT "not set; default none"); `dns.zones` list<record> `{name, type, file, allow_transfer, allow_update, transfer_restricted, update_restricted}` (`subject_kind: zone`; sorted by name; `type` ∈ primary|master|secondary|slave|forward|hint|stub|mirror|redirect; effective lists = zone-level else options-level; `transfer_restricted` = the effective list is set AND contains no `any` (an ACL name resolved through the chain; `key`/`localhost`/`localnets`/`none`/addresses restrict); `update_restricted` = `allow-update` unset/`none`/no `any`, or `update-policy` present; the whole list is ABSENT when `parse_complete` is false or `unmodelled` > 0). 7 keys.

Controls consume: U-35 `ftp.anonymous_enabled`; U-53 `ftp.banner_discloses_version`; U-54 `services.ftp.active` + `ftp.tls_enforced`; U-56 `ftp.access_file_present` + `each` over `ftp.access_files`; U-57 `ftp.root_denied`; U-48 `mail.expn_vrfy_restricted`; U-50/U-51 `each` over `dns.zones`; all gated by `services.<x>.installed eq true` (and `dns.implementation eq bind` for U-50/U-51 — unbound serves no zones).

---

### Task 1: services rows, `files.libwrap_present`, and the `ftp` collector core

**Files:** modify `services.go` (three rows), `files.go` (libwrap), `register.go`; create `ftp.go`, `ftp_test.go`, `testdata/vsftpd.conf.{debian,rhel,anon-default,tls,userlist-allow,extra-instance}`, `testdata/proftpd.conf.{stock,virtualhost,ident-off}`, `testdata/pure-ftpd.conf.stock`; registry block (15 services + 1 files + the `ftp.*` keys of this task: implementation, config_files, parse_complete, unmodelled, local_enabled, anonymous_enabled, tls_enforced, tcp_wrappers, userlist_enable, userlist_deny, userlist_file) + golden.

**Interfaces:** consumes `collect.Access`, `FromReadError`, `declared()`, `pathPresent`, `buildBegun`, the `fsAccess` double; produces the keys above.

- [ ] **Step 1: Failing tests** (`ftp_test.go`; `ftpAccess` seeds all five maps — the I-20 lesson; the binary stats are seeded for the implementation cases)
```go
// Debian stock vsftpd.conf: anonymous NO, local YES, ssl NO → tls_enforced false, tcp_wrappers absent-from-file → false.
func TestFtpVsftpdDebianStock(t *testing.T) { /* files: /etc/vsftpd.conf=vsftpd.conf.debian; stats: /usr/sbin/vsftpd */ }
// An empty vsftpd.conf leaves anonymous_enable at the compiled default YES (a real misconfiguration, never a guess).
func TestFtpVsftpdAnonymousDefaultIsYes(t *testing.T) {}
// ssl_enable=YES with the force_local_* defaults → tls_enforced true; force_local_data_ssl=NO → false.
func TestFtpVsftpdTLSEnforced(t *testing.T) {}
// /etc/vsftpd/vsftpd.conf plus /etc/vsftpd/extra.conf → unmodelled 1 and the judged leaves absent.
func TestFtpVsftpdSecondInstanceIsUnmodelled(t *testing.T) {}
// Conffile without /usr/sbin/vsftpd → implementation none, reason names the leftover (L-3).
func TestFtpLeftoverConffileIsNotAnImplementation(t *testing.T) {}
// proftpd stock: anonymous false (no <Anonymous>), RootLogin unset; a <VirtualHost> block → unmodelled.
func TestFtpProftpdStockAndVirtualHost(t *testing.T) {}
// EACCES on an existing vsftpd.conf → every judged leaf denied with the path (C3), never a default.
func TestFtpUnreadableConfIsDenied(t *testing.T) {}
// No FTP at all → implementation none, judged leaves absent, config_files ok:[], Worst == ok.
func TestFtpNoDaemonIsAbsentNotMissing(t *testing.T) {}
// services rows: no-systemd → all fifteen new leaves unsupported (the 2G/2I table test extended).
func TestServicesFtpMailDnsRowsDegradeWithTheTable(t *testing.T) {}
// files.libwrap_present: any candidate stat → true; none → ok:false; EACCES → denied.
func TestFilesLibwrapPresent(t *testing.T) {}
```
- [ ] **Step 2: Run red.** Cross-compile (`GOOS=linux GOARCH=amd64 go test -c ./internal/collect/collectors/ -o NUL`); the Linux run happens on the lab host once the LAB TOKEN is 2L's, else in CI.
- [ ] **Step 3: Implement `ftp.go`.** `Declare.Reads`: `/etc/vsftpd.conf`, `/etc/vsftpd/vsftpd.conf`, `/etc/vsftpd/*.conf`, `/etc/vsftpd/ftpusers`, `/etc/vsftpd/user_list`, `/etc/vsftpd.user_list`, `/etc/vsftpd.ftpusers`, `/etc/ftpusers`, `/etc/pam.d/vsftpd`, `/etc/proftpd/proftpd.conf`, `/etc/proftpd.conf`, `/etc/proftpd/*.conf`, `/etc/proftpd/conf.d/*.conf`, `/etc/pure-ftpd/pure-ftpd.conf`, `/etc/pure-ftpd/conf/*`, `/usr/sbin/vsftpd`, `/usr/sbin/proftpd`, `/usr/sbin/pure-ftpd`. vsftpd flat parse: `key=value` per line, `#` comments, keys case-insensitive, values `YES`/`NO` case-insensitive, LAST wins; the booleans above with their compiled defaults; every read file appended to `config_files`. proftpd: line directives at top level (`ServerIdent`, `UseFtpUsers`, `RootLogin`, `TLSEngine`, `TLSRequired`, `<Anonymous` opener); `Include` → `declared()` → read or unmodelled; `<VirtualHost`/`<Global`/`<IfModule` → unmodelled (the directives inside are not attributed). pure-ftpd: `/etc/pure-ftpd/conf/<Name>` one-setting files (Debian) or `Name value` lines (RHEL). The judged leaves (`anonymous_enabled`, `tls_enforced`, `local_enabled`, `tcp_wrappers`, `userlist_*`) are ABSENT when `parse_complete` is false or `unmodelled` > 0, with the reason naming the construct.
- [ ] **Step 4: services rows + libwrap + registry + golden + gates.** `gofmt -l .`, `go vet ./...` (host + linux), `go test ./internal/facts`, `go run ./cmd/muster controls lint --references docs/reference` → "ok: 47 controls" (this base has 47), coverage -check.
- [ ] **Step 5: Commit.** "Add the ftp collector core, the ftp/mail/dns service rows and the libwrap presence fact".

### Task 2: FTP access files, root denial and banner

**Files:** modify `ftp.go`, `ftp_test.go`; testdata `pam.d.vsftpd.{debian,rhel,nolistfile}`, `ftpusers.{root,noroot}`, `user_list.{root,noroot}`, `vsftpd.conf.{banner,banner-file,userlist-deny,userlist-allow,local-disabled}`; registry keys `ftp.access_files`, `ftp.access_file_present`, `ftp.root_denied`, `ftp.banner_source`, `ftp.banner_text`, `ftp.banner_discloses_version` + golden.

- [ ] **Step 1: Failing tests**
```go
// Debian: /etc/pam.d/vsftpd names /etc/ftpusers (sense=deny); root listed → root_denied true; access_files has the pam_deny record with mode/uid.
func TestFtpAccessFilesDebianPamDeny(t *testing.T) {}
// RHEL: pam names /etc/vsftpd/ftpusers; userlist_enable=YES (deny) with /etc/vsftpd/user_list → two records.
func TestFtpAccessFilesRhelUserlistDeny(t *testing.T) {}
// userlist_deny=NO turns user_list into an allow-list: root NOT listed → root_denied true; root listed → false.
func TestFtpUserlistAllowSemantics(t *testing.T) {}
// No deny file lists root and no allow-list → root_denied ok:false (a definite finding, not absent).
func TestFtpRootNotDeniedIsFalse(t *testing.T) {}
// local_enable=NO → root_denied true with the reason "local logins disabled".
func TestFtpLocalDisabledDeniesRoot(t *testing.T) {}
// pam_listfile file= outside the declaration → recorded, never read; root_denied absent (MANUAL).
func TestFtpUndeclaredPamListfileIsRecorded(t *testing.T) {}
// Banner: unset → source default, discloses true; ftpd_banner "Welcome" → false; "vsFTPd 3.0" → true; banner_file read via declared().
func TestFtpBannerDisclosure(t *testing.T) {}
// proftpd: ServerIdent off → false; unset → true; RootLogin on → root_denied false.
func TestFtpProftpdIdentAndRootLogin(t *testing.T) {}
```
- [ ] **Step 2: Run red** (cross-compile / lab when the token is ours).
- [ ] **Step 3: Implement.** Access records use the same stat primitive as `writePermFacts` for `mode/uid/gid` (mode as the octal string the perm facts use) and the three-value `stat_status` (`exists|missing|denied`) of 2E's home_dirs. `root_listed` = a non-comment, trimmed line equal to `root`. Banner: `ftpd_banner` wins over `banner_file` (vsftpd's precedence); `banner_file` is a config-supplied path (`declared()`; the default declaration covers `/etc/vsftpd/*` and `/etc/issue.net`? — NO: declare `/etc/issue.net` and `/etc/vsftpd/banner*` only; anything else is recorded). Disclosure regexp compiled once: `(?i)\b(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)\b`.
- [ ] **Step 4: Registry + golden + gates.**
- [ ] **Step 5: Commit.** "Derive the FTP access-control files, root denial and banner disclosure".

### Task 3: the `mail` collector

**Files:** create `mail.go`, `mail_test.go`, `testdata/main.cf.{debian,relay-open,vrfy-disabled,continuation}`, `testdata/sendmail.cf.{goaway,novrfy-only,none}`; registry `mail.*` (10 keys) + golden; `register.go`.

- [ ] **Step 1: Failing tests**
```go
// Debian stock main.cf: inet_interfaces "all", mynetworks "127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128", disable_vrfy_command absent (default no) → expn_vrfy_restricted false.
func TestMailPostfixDebianStock(t *testing.T) {}
// A continued value (line starting with whitespace) is joined; the last assignment wins.
func TestMailPostfixContinuationAndLastWins(t *testing.T) {}
// disable_vrfy_command = yes → expn_vrfy_restricted true.
func TestMailPostfixVrfyDisabled(t *testing.T) {}
// sendmail: O PrivacyOptions=goaway → expanded list contains novrfy and noexpn → restricted true; novrfy alone → false.
func TestMailSendmailPrivacyOptions(t *testing.T) {}
// exim: implementation exim, expn_vrfy_restricted absent, config_files lists the files.
func TestMailEximIsDetectedNotParsed(t *testing.T) {}
// main.cf without /usr/sbin/postfix → none (L-3); EACCES → denied on every judged leaf; no MTA → absent, Worst ok.
func TestMailImplementationAndDegradation(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `Declare.Reads`: `/etc/postfix/main.cf`, `/etc/mail/sendmail.cf`, `/etc/exim4/update-exim4.conf.conf`, `/etc/exim/exim.conf`, `/usr/sbin/postfix`, `/usr/sbin/sendmail.sendmail`, `/usr/sbin/sendmail-mta`, `/usr/sbin/exim4`, `/usr/sbin/exim`. `main.cf` grammar: `name = value`, a line beginning with whitespace continues the previous value, `#` at column 0 is a comment, last wins; `$` references are NOT expanded (evidence). `sendmail.cf`: the first line matching `^O PrivacyOptions=` (also `^OpPrivacyOptions=`), comma-separated, `goaway` expanded; an unreadable `sendmail.cf` → denied leaves.
- [ ] **Step 4: Registry + golden + gates.**
- [ ] **Step 5: Commit.** "Add the mail collector: postfix and sendmail evidence with the EXPN/VRFY derivation".

### Task 4: the `dns` collector

**Files:** create `dns.go`, `dns_test.go`, `testdata/named.conf.{debian,rhel,open-transfer,acl,view,key,nested,include-undeclared}` and the include fragments; registry `dns.*` (7 keys) + golden; `register.go`.

- [ ] **Step 1: Failing tests**
```go
// Debian: named.conf includes named.conf.options (allow-transfer { none; }) and named.conf.local (one primary zone) → zone transfer_restricted true (inherited), update_restricted true (unset = none).
func TestDnsBindDebianChain(t *testing.T) {}
// RHEL: /etc/named.conf with named.rfc1912.zones included; options allow-transfer unset → a primary zone → transfer_restricted false (BIND default any).
func TestDnsBindDefaultTransferIsOpen(t *testing.T) {}
// zone-level allow-transfer { 192.0.2.0/24; } overrides an open options level; allow-update { any; } → update_restricted false; update-policy → true.
func TestDnsZoneLevelOverridesAndUpdatePolicy(t *testing.T) {}
// acl "xfer" { 198.51.100.0/24; }; allow-transfer { xfer; } → resolved, restricted true; an undefined name → unmodelled → zones absent.
func TestDnsAclResolution(t *testing.T) {}
// view "internal" { … } → unmodelled 1, zones absent, evidence leaves ok.
func TestDnsViewIsUnmodelled(t *testing.T) {}
// include "/etc/named/custom.conf" (declared) is read; include "/srv/x.conf" (undeclared) → recorded, parse_complete false.
func TestDnsIncludeGuard(t *testing.T) {}
// Comments in all three syntaxes, strings with braces inside, a key "tsig" reference → restricted true.
func TestDnsTokenizerEdges(t *testing.T) {}
// unbound → implementation unbound, zones ok:[], options absent; named.conf without /usr/sbin/named → none; EACCES → denied.
func TestDnsImplementationAndDegradation(t *testing.T) {}
```
- [ ] **Step 2: Run red.**
- [ ] **Step 3: Implement.** `Declare.Reads`: `/etc/bind/named.conf`, `/etc/bind/named.conf.*`, `/etc/bind/*.conf`, `/etc/named.conf`, `/etc/named/*.conf`, `/etc/named.rfc1912.zones`, `/etc/named.root.key`, `/etc/named/*.zones`, `/var/named/chroot/etc/named.conf`, `/etc/unbound/unbound.conf`, `/usr/sbin/named`, `/usr/sbin/unbound`. Tokenizer: `{`, `}`, `;`, quoted strings, bare words; comments `//`, `#`, `/* */`. Parser: top-level statements only — `options {…}`, `acl name {…}`, `zone "name" [class] {…}`, `include "path";`, `view` → unmodelled; other top-level statements (`logging`, `key`, `controls`, `server`, `trust-anchors`, `managed-keys`, `statistics-channels`, `dnssec-policy`, `masters`/`primaries`) skipped as neutral with their block consumed by brace depth. Address-match list: elements `any`, `none`, `localhost`, `localnets`, an address/CIDR, `!elem`, `key name`, an ACL name (resolved from the chain, in any order — two passes), a nested `{}` → unmodelled. Effective per zone as in Interfaces; `zones` ABSENT when `parse_complete` false or `unmodelled` > 0.
- [ ] **Step 4: Registry + golden + gates.**
- [ ] **Step 5: Commit.** "Add the dns collector: the named.conf chain, ACLs and per-zone transfer and update restrictions".

### Task 5: the FTP controls U-35, U-53, U-54, U-56, U-57 + fixtures

**Files:** create `controls/service/ftp_anonymous.yaml`, `ftp_banner.yaml`, `ftp_unencrypted.yaml`, `ftpusers_permissions.yaml`, `ftpusers_root.yaml` and `controls/testdata/muster.service.<id>/*.json`.

All five: `category: service`, `automation: auto`, `requires_facts: ">=1"`, `absent_means: manual`, `applies_when: [{ fact: services.ftp.installed, op: eq, expected: true }]`, `references.kisa` only, `decision: D09`, `risk: restart_service` (U-56/U-57: `none` — file edits), EN+KO descriptions in muster's words that state the boundary (pure-ftpd/proftpd MANUAL shapes, the vsftpd compiled defaults).

- **U-35 `muster.service.ftp_anonymous`** (importance 상, kisa `{ "2026": ["U-35"], "2021": ["U-20"] }`): `checks: [{ fact: ftp.anonymous_enabled, op: eq, expected: false }]`. Fixtures: `pass-vsftpd-debian`, `pass-proftpd`, `pass-pure-ftpd`, `fail-vsftpd-default` (anonymous_enabled ok:true — the empty-config default), `fail-proftpd-anonymous-block`, `manual-unmodelled` (absent), `na-not-installed` (services.ftp.installed ok:false).
- **U-53 `muster.service.ftp_banner`** (하, `{"2026":["U-53"],"2021":[]}`): `checks: [{ fact: ftp.banner_discloses_version, op: eq, expected: false }]`. Fixtures: `pass-vsftpd-custom`, `pass-proftpd-ident-off`, `fail-vsftpd-default`, `fail-proftpd-default`, `manual-pure-ftpd` (absent), `na-not-installed`.
- **U-54 `muster.service.ftp_unencrypted`** (중, `{"2026":["U-54"],"2021":["U-61"]}`): two `mechanisms` — (1) `when: [{ services.ftp.active eq false }]` → `checks: [{ services.ftp.active eq false }]` (an installed but stopped FTP is not an unencrypted service); (2) `when: [{ services.ftp.active eq true }]` → `checks: [{ ftp.tls_enforced eq true }]`. Fixtures: `pass-inactive`, `pass-vsftpd-tls`, `fail-vsftpd-plain`, `fail-vsftpd-anon-plain` (ssl on, anonymous on without force_anon_*), `manual-proftpd-unmodelled` (tls_enforced absent), `na-not-installed`.
- **U-56 `muster.service.ftpusers_permissions`** (하, `{"2026":["U-56"],"2021":["U-63"]}`): `checks`: `{ ftp.access_file_present eq true }`, `{ fact: ftp.access_files, op: each, subject: path, where: { field: exists, op: eq, expected: true }, require: { field: uid, op: eq, expected: 0 } }`, and the same `each` with `require: { field: mode, op: in, expected: [<subsets of 0640 in the passwd_permissions shape>] }`; `params.allowed_modes` (type `list<string>`, default the subsets, quoted `"${allowed_modes}"` in `expected`). Fixtures: `pass-debian`, `pass-rhel-userlist`, `fail-world-readable` (mode 0644 → FAIL), `fail-not-root-owned`, `fail-no-access-file` (access_file_present ok:false), `manual-unmodelled`, `na-not-installed`.
- **U-57 `muster.service.ftpusers_root`** (중, `{"2026":["U-57"],"2021":["U-64"]}`): `checks: [{ fact: ftp.root_denied, op: eq, expected: true }]`. Fixtures: `pass-pam-deny`, `pass-userlist-allow`, `pass-local-disabled`, `pass-proftpd-rootlogin-off`, `fail-root-not-listed`, `fail-proftpd-rootlogin-on`, `manual-undeclared-listfile` (absent), `na-not-installed`.

- [ ] **Step 1:** write the five YAMLs; `go run ./cmd/muster controls lint --references docs/reference` → "ok: 52 controls" (47 + 5). If a YAML fails to decode, STOP and report — never drop a clause.
- [ ] **Step 2:** write the fixtures with every leaf the selected mechanism reads (L-13); `go test ./internal/controls/...` → every fixture yields its prefix status; run the real binary on the `manual-*`/`na-*`/`fail-*` ones and confirm the reason names the cause.
- [ ] **Step 3: Commit.** "Add the FTP controls: anonymous access, banner disclosure, unencrypted service, access-file permissions and root denial".

### Task 6: the mail and DNS controls U-46, U-47, U-48, U-50, U-51 + fixtures

**Files:** create `controls/service/mail_expn_vrfy.yaml`, `mail_user_execution.yaml`, `mail_relay.yaml`, `dns_zone_transfer.yaml`, `dns_dynamic_update.yaml` + fixtures.

- **U-48 `muster.service.mail_expn_vrfy`** (auto, 중, `{"2026":["U-48"],"2021":["U-70"]}`): `applies_when: [{ services.mail.installed eq true }]`; `checks: [{ mail.expn_vrfy_restricted eq true }]`; `absent_means: manual`. Fixtures: `pass-postfix`, `pass-sendmail-goaway`, `fail-postfix-default`, `fail-sendmail-novrfy-only`, `manual-exim` (absent), `na-not-installed`.
- **U-46 `muster.service.mail_user_execution`** (MANUAL, 상, `{"2026":["U-46"],"2021":["U-32"]}`) and **U-47 `muster.service.mail_relay`** (MANUAL, 상, `{"2026":["U-47"],"2021":["U-31"]}`): `automation: manual`, `manual_reason` (EN, one sentence naming what the operator checks — U-46: whether ordinary users can run the MTA's queue/submission commands, from `mail.postfix.authorized_submit_users` / `mail.sendmail.privacy_options` `restrictqrun`/`restrictmailq`; U-47: whether the MTA relays for off-host clients, from `mail.postfix.{inet_interfaces,mynetworks,smtpd_relay_restrictions}` / sendmail's access map — not modelled), `applies_when: [{ services.mail.installed eq true }, { mail.implementation, op: present }]` (L-11), NO `checks`, `requires_facts: ">=1"`, no `absent_means`. Fixtures: `manual-postfix` (installed ok:true, implementation ok), `na-not-installed`. Lint requires `manual_reason`; the fixtures test exempts the pass/fail pair.
- **U-50 `muster.service.dns_zone_transfer`** (auto, 상, `{"2026":["U-50"],"2021":["U-34"]}`) and **U-51 `muster.service.dns_dynamic_update`** (auto, 중, `{"2026":["U-51"],"2021":[]}`): `applies_when: [{ services.dns.installed eq true }, { dns.implementation eq bind }]`; U-50 `checks: [{ fact: dns.zones, op: each, subject: name, where: { field: type, op: in, expected: [primary, master] }, require: { field: transfer_restricted, op: eq, expected: true } }]`; U-51 the same with `update_restricted`. `absent_means: manual`. Fixtures (each): `pass-restricted`, `pass-no-primary-zones` (only hint/secondary → vacuous), `fail-open` (a primary zone with `any`), `manual-view` (zones absent), `na-unbound` (implementation unbound), `na-not-installed`. Description states the BIND default (`allow-transfer` any; `allow-update` none) and that views read MANUAL.

- [ ] **Step 1:** YAMLs; lint → "ok: 57 controls".
- [ ] **Step 2:** fixtures; `go test ./internal/controls/...`; the MANUAL invariant (reason + evidence) holds for U-46/U-47's `manual-*` fixtures through the real binary.
- [ ] **Step 3: Commit.** "Add the mail and DNS controls: EXPN/VRFY, user execution, relay, zone transfer and dynamic update".

### Task 7: rebase onto the post-2J main, U-45/U-49, and the reconciliation 52 → 64

**Files:** `git rebase main` (after 2J merges); create `controls/service/mail_version.yaml`, `dns_version.yaml` + fixtures; modify `cmd/muster/controls_test.go` (`"ok: 52 controls"` → `"ok: 64 controls"`), `cmd/muster/e2e_test.go` (count words and BOTH maps: eight PASS + four `"MANUAL"`), `cmd/muster/testdata/full-{pass,fail}.json` (every leaf the eight auto controls read, PASS-shaped; the four gates `installed ok:true` + `implementation ok`), `docs/reference/coverage.md` (regenerated → line 4 `64 of 67 items enrolled (auto 55, partial 5, manual 4).`); README pair only if a count sentence exists (none today — the 58-of-67 roadmap sentence is a target, leave it).

- [ ] **Step 1: Rebase.** `git rebase main`; resolve `registry.yaml` by keeping 2J's block ABOVE ours (ours stays last), `go test ./internal/facts` at once (duplicate keys rejected), golden `-update`, `services.go` rows (2J touches no rows), `register.go` (append). Confirm `git log` shows 2J's commits below ours and `git diff main --stat` lists only 2L files.
- [ ] **Step 2: U-45 `muster.service.mail_version`** (MANUAL, 상, `{"2026":["U-45"],"2021":["U-30"]}`) and **U-49 `muster.service.dns_version`** (MANUAL, 상, `{"2026":["U-49"],"2021":["U-33"]}`): `manual_reason` names the check (the MTA/BIND package is at the vendor's patched level; muster never matches versions to advisories — D24 — and the host's patch state is in `patch.pending_security_count` / `patch.metadata_age_s`), `applies_when: [{ services.<x>.installed eq true }, { <x>.implementation present }]`, fixtures `manual-installed`, `na-not-installed`. Lint → "ok: 64 controls".
- [ ] **Step 3: Count seams and fixtures** as listed; `go test ./...`; coverage regenerated and `-check`; `GOOS=linux GOARCH=amd64 go vet ./... && go build ./...`; the standing secret guard over the whole branch (the lab alias prefix, the organisation name and the lab network prefix — the pattern lives only in the session notes, never in the repository) → 0 matches.
- [ ] **Step 4: Commit.** "Enrol the FTP, mail and DNS controls in the coverage and end-to-end snapshots".

## Self-Review

- **Spec coverage:** twelve items → twelve controls (Tasks 5, 6, 7); three collectors (Tasks 1–4); the 2G/2H boundary rulings honoured (U-54/U-35 here; libwrap gate consumed by U-56 via L-9); D14 (no daemon invocation) and D24 (no advisory matching) honoured by L-2; §6.5 order (applies_when before manual) relied on per `eval.go:65-92`.
- **Placeholder scan:** none — every test has a name and a stated assertion; every key has a type and a stated default/absent reason; the YAML shapes reuse the verified 2I/2H grammar.
- **Type consistency:** `ftp.access_files` record fields are the same in Task 2 (producer) and Task 5 (`each` consumer: `exists`, `uid`, `mode`, subject `path`); `dns.zones` fields in Task 4 and Task 6 (`type`, `transfer_restricted`, `update_restricted`, subject `name`); `services.<x>.installed` from Task 1 gates every control; `mail.expn_vrfy_restricted` in Tasks 3 and 6.
- **Known risk for the pre-flight to probe:** (a) the exact `mode` representation of the perm facts (string vs int) for U-56's `in` list; (b) whether `each … where` on `exists` handles a record whose `mode` is empty when `exists` is false (the `where` filters it out first); (c) the compiled vsftpd defaults per distro (`userlist_file`, `pam_service_name`); (d) sendmail `goaway` expansion list; (e) BIND 9.18 `allow-transfer` default; (f) the fixtures test's treatment of a `manual` control with only `manual-*`/`na-*` fixtures.
