# Stage 3D-3 — `snapshot anonymize` and `--max-age`

Korean pair: `2026-10-30-stage3d3-anonymize-maxage-design.ko.md`. Main design: `2026-09-02-muster-design.md` (§5.1
the snapshot, §5.6 redaction, §5.7 schema, §7.2 and §7.5 exit codes and refusals, §8 `:426` snapshot confidentiality,
§9 output, §10.2 roadmap, D11, D13, D34). Rulings of this design are the AX list (single letters collide with earlier
stages). The scope maps it was written from are the cycle's ignored workspace
(`scope-{identifiers,verdicts,age,surface,prior,critic}.md`); their findings are restated here where they bind. A
first review round (`design-review-r1.md`, 33 findings) is folded in: it moved free text from a token pass to a
placeholder, parked the mapping of site files, and replaced the address cycle-walk. A second
(`design-review-r2.md`, 20 findings) widened AX-6's name positions and pinned the read rule per field and op; a
third (`design-review-r3.md`, 8 findings) made the host-or-address dispatch one ordered rule. Rulings made while
building it (the plan's ledger) are folded in: every home on a path is rewritten, paths are rewritten in place,
mount targets are paths, and four classes were added (`host_or_netgroup`, `unit`, `blank`, option grammars).

## 1. Scope and intent

The roadmap closes stage 3 with "3D-3: `--anonymize` with its invariant test, `--max-age`". The main design gives the
first one sentence — "a `--anonymize` mode for sharing (stable hashing of hostnames, addresses and user names) arrives
in stage 3 together with the invariant test that anonymised and original snapshots produce identical verdicts" — and
the second only its name. This cycle builds both:

- **Anonymisation** lets an owner hand a snapshot to someone outside — a vendor, a consultant, a muster bug report —
  without handing over which host and which people it describes, while the receiver gets the verdicts the owner gets
  under the built-in profiles.
- **`--max-age`** lets a pipeline refuse to judge, or to plan a fix from, a snapshot older than a bound, so an old
  snapshot is not mistaken for the host's current state (§5.1).

What the scope work established, and what drives the shape below:

- The evaluator never joins two facts: no custom functions exist (`internal/check/custom.go:11`), `${param}` is the
  only substitution (`internal/check/value.go:40`), and every comparison between identifiers is worked out in a
  collector and stored as a bool or a class (`uid_duplicate`, `owner_ok`, `has_plus`, `loopback`, `exposed`, …). So
  a transform over the **finished** snapshot that leaves derived fields alone cannot break a join.
- What it can break: clauses that compare an identifier with a literal or a parameter — `root`
  (`root_only_uid_zero`), `ftp` (`ftp_account_shell`, which would turn FAIL into a vacuous PASS), lp/uucp/nuucp, the
  root/adm/syslog/utmp groups; a value whose emptiness a mechanism tests (`logging.journal_upload.url ne ""` picks
  `remote_log_forwarding`'s mechanism); and any rewrite of a string it was never told the meaning of (a mount target
  rewritten by a user called `log` turns `separate_partitions` PASS into MANUAL).
- The registry's `sensitivity` label cannot drive it: of 511 keys, 465 are `public`, and many carry user names,
  paths or addresses; only the two SNMP keys are redacted today. The registry lists no record fields
  (`internal/facts/registry.go:22-31`), so the anonymiser's own table is the source of truth for them.

- **AX-1 — Anonymisation is an offline command over a finished snapshot: `muster snapshot anonymize`.** Not a
  `collect` flag in this stage: collect never parses a control, tuning or waiver file (THREAT_MODEL, main design
  `:424`); a key file would be a read outside the collector registry; and the original is not the threat — it sits
  0600 on the host it describes. Sharing happens afterwards, and that is where the transform runs. D36 rewords main
  design `:426`; `collect --anonymize` is parked.
- **AX-2 — Keyed pseudonyms, never plain hashes.** HMAC-SHA256 under a 256-bit key, one derived sub-key per class
  (`HMAC(key, "muster/anon/v1/<class>")`), standard library only (D28). A plain hash of a user name, a host label or
  an IPv4 address is reversible by enumeration (`collectors/snmp.go:30-33` says so for community strings). The key is
  as sensitive as the original snapshot.
- **AX-3 — The key is an input; a throwaway key is an explicit choice.** `--key <file>` (exactly 32 bytes, read
  through `trustedFile` when root) makes the output deterministic — same input, same key, same bytes. `--ephemeral`
  draws 32 bytes from `crypto/rand`, never written, for a one-off public report; the header says so and its bytes
  differ on every run. Exactly one of the two is required.
- **AX-4 — Each value class has one rule; the empty string maps to itself in every class.**

  | Class | Rule |
  |---|---|
  | account (user and group names, one namespace) | `u` + 12 base32 characters (lower case, no padding) of HMAC; case-sensitive; a sigil before it (`%`, `+`, `-`, `@`, `#` before a non-number) is kept |
  | host (DNS names) | lower-cased, label by label, `h` + 10 base32 per label; the final label kept; a single-label name maps whole |
  | address | §1.1 below |
  | host-or-address (a field that holds either: an NTP server, a syslog target, an NFS client, a lastlog host) | one ordered decision: (1) an address form of §1.1; (2) a host form — a DNS name of letter-digit-hyphen labels (a trailing dot kept), `host:port`, `transport:host[:port]`, syslog's `[@\|@@][(opts)]host[:port]`, a `*.`-prefixed wildcard (`*` kept), `@netgroup` (the name by the account rule) — with the host part by the host rule and the rest kept as syntax; (3) anything else `[anonymised]` |
  | host-or-netgroup (hosts.equiv hosts, NFS clients) | a leading `@` names a netgroup mapped by the account rule; otherwise the host-or-address rule |
  | unit (unit names) | a name without `@` kept; a template instance `<name>@<instance>.<suffix>` keeps `<name>@` and `.<suffix>` and maps the instance to `i` + 12 base32 of HMAC |
  | blank (`boot_id`, `uptime_s`, firewall raw dumps) | a string becomes `""`, a number `0`; presence kept |
  | option list (mount and NFS export options) | comma tokens kept byte for byte, except the values of `username`, `user`, `domain`, `addr`, `ip`, `clientaddr`, `mountaddr`, `mounthost`, `credentials`, `cred`, export `mp`, `mountpoint`, `refer`, `replicas` (mapped by their class) and `password`, `pass` (placeholder) |
  | url | scheme, port and `user@` kept as syntax, query, fragment and password `[anonymised]`, host by the host or address rule, user by the account rule, path by AX-6 |
  | fingerprint (SSH key fingerprints) | `SHA256:` + 43 base64 characters (no padding) of HMAC |
  | machine id hash | keyed 64 lowercase hex (AX-11) |
  | path | AX-6 |
  | placeholder (free text no clause reads) | AX-7 |
  | kept | uids, gids, ports, modes, package names and versions, kernel release, interface names, enums, booleans, numbers, `collected_at`, statuses, list lengths, every derived field |

  The kept row is part of the contract: verdicts read those values (`uid eq 0`, the numeric ACL qualifier, `target eq
  "/tmp"` — mount targets are paths, and AX-6 never rewrites the ones a control names —, package joins, `--max-age`). They are quasi-identifiers, and the documents say so (§5).
- **AX-5 — The keep set is a closed list, pinned to the control set.** A name is kept only when it is in a closed list
  in `internal/anonymize`: `root`; the system accounts and groups the control set names (`ftp`, `lp`, `uucp`,
  `nuucp`, `adm`, `syslog`, `utmp`, `wheel`, `sudo`, `admin`, …); the sudo and NFS tokens `ALL`, `*`. Every other
  account or group name is mapped — a site's own system accounts and a second uid-0 account included (a backdoor
  `toor` is not published; `root_only_uid_zero` still sees a name that is not `root`). Keeping wins across classes.
  A test in `internal/controls` fails when a literal or a default compared against an account-class value — a scalar
  fact, a list element or a record field, in the control set or a built-in profile — is not in the list, so a new
  literal fails CI, not a shared report. The header records `keep_set: v1`.
- **AX-6 — Paths are rewritten at known positions only, by one function.** The mapped account names are every value the
  account rule maps anywhere in the snapshot (sigils stripped), collected in a first pass before any path is rewritten —
  so a sudo principal or a crontab owner that is not in `/etc/passwd` counts. A component equal to a mapped account name
  is replaced by its pseudonym when it is the last component of a non-kept account's home (unless the home is `/`,
  `/tmp`, `/var/tmp`, `/dev/null`, `/nonexistent`, a mount target any control names, or has fewer than two components),
  the component after `/home/`, the name position of `/var/spool/cron/crontabs/<n>`, `/var/spool/cron/<n>`,
  `/var/mail/<n>`, `/var/spool/mail/<n>`, `/var/lib/systemd/linger/<n>` and `/var/lib/AccountsService/users/<n>`, and
  the base name of a file directly under `/etc/sudoers.d/` or `/etc/cron.d/` that equals a mapped account name; a path
  under such a home is rewritten as a prefix. Every eligible home on the path has its last component rewritten, a component's position is decided on the
  cleaned prefix before it, and the path is rewritten in place, never returned cleaned; a home's last component that equals the
  name of any account sharing the home is replaced by that name's pseudonym; `/home/<x>` whose `<x>` is no account maps
  `<x>` in the account class. Never a mount target, never by component equality elsewhere. The same function maps every
  path in the snapshot, so a file's subject stays one string.
- **AX-7 — Free text that no clause reads is replaced, not scanned.** A `text` value — the envelope `reason`, every
  `Source` (top level, `winner`, a setting's sides, nested `inputs`) `raw` and `cmd`,
  `run.collectors[].reason`, `partial_failures`, and every raw-text record field the table marks — becomes the fixed
  string `[anonymised]`; its emptiness is kept (`""` stays `""`). `firewall.raw_dumps[].content` becomes `""` with
  `truncated` kept. A token pass over free text cannot be made complete (a host name found only in prose, an address
  with a zone, a name cut at a truncation marker), and pairing a mapped path with its own original in prose would
  publish the key's work. The cost is evidence readability, said in the README; a key named only in a control's
  `evidence:` list is placeholdered like any other (no verdict reads its text). A placeholder keeps presence as it
  was: an absent field stays absent, a present one stays present, `""` stays `""`. A text value that a clause reads
  by value (`eq`, `ne`, `in`, `not_in`, `matches`, `not_matches`, `contains`, a comparison: `hosts.equiv` lines and
  their `^\+`, securetty's `^pts/`) is rewritten token by token under a grammar the table declares for that field
  (whitespace tokens; each token by its declared class; sigils kept); the pin of AX-8 lists them.
- **AX-8 — Every path in the document is classified; an unclassified one refuses the input.** A table in
  `internal/anonymize` names the class of every run-header field, every envelope field (`status`, `value`, `source.*`,
  `truncated`, `reason`; a setting's `runtime`, `persisted` and `effective` sides, its `winner` and persona keys), every
  registry key's value and, for records, every field path (nested records included) with its class, its grammar when it
  is read text, and for lists whether they are sorted by a mapped field or keep their order (`firewall.rules`, root's
  PATH, the admin group's member order). A sorted list carries an explicit sort spec in the table — the ordered key
  fields, string or numeric comparison for each, and whether it deduplicates — and is re-sorted by it after mapping
  (`accounts.lastlog`, sorted by name, is one; a choice made by name order before mapping, such as `ssh.rsa_keys`
  keeping a shared file under the first account by name, stays as collected). Table paths are resolved from the
  registry's dotted keys, never from the tree's shape. The table is filled from the collectors' code. Tests: every
  registry key is in the table; every field path that occurs in any corpus snapshot (§4, the union) is classified; a
  Linux-tagged test in the collectors package checks every record its unit tests emit against the table, and re-sorts
  each sorted list by its spec and asserts nothing moves; a reflection test over `facts.Run`, `facts.Envelope` and
  `facts.Setting` covers the header and the envelope (`truncated` included); a field path any clause, `applies_when` or
  mechanism `when` reads **by value** is never `placeholder` (a `present`/`absent` read is allowed, AX-7). The fixtures'
  top-level keys are classified too: `synthetic`, `_expect.*` and `_provenance.*` kept, `_notes` `placeholder`. At run
  time an input carrying a path outside the table is refused: when the snapshot's `muster_version` is newer than the
  binary, "anonymise with muster ≥ <its muster_version>"; otherwise "unclassified field <path>: a muster bug, please
  report it" (both pinned by a test). A newer collector's field is neither leaked nor dropped.
- **AX-9 — Pseudonyms are injective, and a collision refuses.** Within one class and one run every distinct input
  maps to a distinct output; a collision, or a mapped value equal to a kept one or to another class's output in the
  same field, fails the command naming the class.
- **AX-10 — The output says what it is.** `run.anonymization {scheme: "muster-anon-v1", mode: "keyed" | "ephemeral",
  key_id, keep_set, classes, replaced}` (omitempty): `key_id` is the first 16 hex characters of `HMAC(key,
  "muster/anon/v1/key-id")` (empty in ephemeral mode), so a receiver can tell whether two files share a key; `classes`
  is the sorted list, from the tokens `account`, `host`, `address`, `url`, `fingerprint`, `machine_id_hash`, `path`, `unit`, of
  the classes that mapped at least one value; `replaced` is the sorted list of document paths whose values were
  placeholdered or emptied, written with `[]` for any list index — for example `facts.cron.files.value[].reason`,
  `facts.firewall.raw_dumps.value[].content`, `run.collectors[].reason`. `check` and `fix` carry it as they carry `run`;
  an input already marked is refused. Adding the field keeps `schema_version` (§5.7).
- **AX-11 — The host guard fails closed.** `machine_id_hash` becomes a keyed 64-hex value, so an older muster that
  ignores the header still renders a guard that refuses every host. This muster's `fix --format script` refuses an
  anonymised snapshot (exit 2, nothing on stdout: "plan the script from the original snapshot"); `--format table` and
  `json` stay, for a reviewer. `run.host.hostname` is mapped by the host rule; `boot_id` and `uptime_s` (no reader)
  are blanked.
- **AX-12 — The invariant, stated honestly.** For every snapshot in the corpus (§4) and every built-in profile, with
  no tuning and no waiver file, the original and the anonymised snapshot give equal `(id, status, reason_code)` for
  every row, the same mechanism choice, the same multiset of observation verdicts per row, and the same exit code.
  Site files — a tuning file, a waiver file, a site profile — are not mapped in this stage: a site value naming a real
  user, path or address can flip a verdict on the anonymised snapshot, and the documents say so. The owner keeps
  their own results; a receiver judges the built-in questions.
- **AX-13 — `--max-age <duration>` on `check` and `fix`: a refusal before evaluation.** Off by default (no flag, no
  change, byte for byte). With it, a snapshot whose age exceeds the bound is refused — exit 2, nothing on stdout,
  `muster: snapshot collected at <ts> is <age> old, older than --max-age <d>` — the shape of a refused profile or a
  schema mismatch (§7.2, §7.5). `--allow-error` and `--fail-on none` do not lift it; `fix` keeps "never exits 1".
  Not a control and not a reason code: age is a property of the whole input, and verdicts stay a pure function of the
  snapshot.
- **AX-14 — Time is read once, strictly.** One clock reading per command in `cmd/muster`, shared by waiver expiry and
  the age test (an injectable `now`). `collected_at` must be exactly `YYYY-MM-DDTHH:MM:SSZ` (round-trip equal); under
  `--max-age`, an empty or malformed value refuses ("no usable collected_at; cannot judge --max-age"), and a value
  more than 5 minutes in the future refuses (a fixed skew allowance; within it the age is 0). The age is whole
  seconds: `now` truncated to the second minus `collected_at`; the bound is inclusive.
  The grammar: one or more whole-number terms in descending unit order, each unit at most once, units `w`, `d`, `h`,
  `m`, `s` (`7d`, `2w`, `1d12h`, `90m`); no fractions, no `ms`/`us`/`ns`; at least 1 second, at most 100 years;
  anything else refused. The result records the bound, never the age: `check.max_age_s` (last field of the check
  block) and the plan's `fix.max_age_s` (last field of the fix block), omitempty, whole seconds. Max-age measures two
  machines' clocks and attests nothing; THREAT_MODEL says so.

### 1.1 Addresses

- **Kept unchanged** (no identity): IPv4 `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255`,
  and the documentation ranges `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; IPv6 `::`, `::1`, `ff00::/8`,
  `2001:db8::/32`.
- **Mapped inside their range** (the range prefix kept, the remaining bits by a keyed Crypto-PAn construction):
  IPv4 `10.0.0.0/8`, `100.64.0.0/10`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`, `198.18.0.0/15`; IPv6
  `fc00::/7`, `fe80::/10`. `::ffff:a.b.c.d` (`::ffff:0:0/96`) and `64:ff9b::a.b.c.d` (`64:ff9b::/96`) map their
  IPv4 part by the IPv4 rules and keep their prefix; both are boundaries of the IPv6 tree below.
- **Public** (everything else): the fixed-bit tree construction — at each bit, the bit is flipped by the keyed PRF of
  the prefix only when the subtree under that prefix contains no kept or mapped-range boundary; otherwise it is kept.
  The map is prefix-preserving and bijective on public space, so an address never changes class and a CIDR maps by
  its network bits with containment kept. A CIDR written with host bits set maps its address part as an address and
  keeps the length. What leaks: the kept ancestor bits near the special ranges (THREAT_MODEL).
- **Forms parsed** in an address or host-or-address field: an address, a CIDR, an address with a dotted netmask
  (`a.b.c.d/255.255.255.0`), `addr:port` and `[v6]:port`, a transport prefix (`udp:`, `tcp:`, `udp6:`, `tcp6:`), a
  zone (`fe80::1%eth0`: the zone is an interface name, kept), a range `a-b` (each end mapped; the order may invert,
  evidence only), an nft set `{ a, b }` (each element). In an address field a value matching no form becomes
  `[anonymised]`; in a host-or-address field the host forms of AX-4 are tried first, and only a value matching no
  address and no host form becomes `[anonymised]` — no verdict reads an address leaf (the derived booleans carry the
  class).

## 2. The command

```
muster snapshot anonymize --facts <in|-> (--key <file> | --ephemeral) --out <file|-> [--force]
```

- The whole document is decoded once into a tree with `json.Number` (top level, `run` and `facts`), so integers above
  2^53 and the fixture keys `synthetic`, `_provenance` and `_expect` survive, and an empty or partial `run` block is
  written back as it was (absent keys stay absent; a fixture keeps `synthetic: true`, D02). `facts.Load` runs only as
  the schema and size gate. The output is encoded the way `collect` writes a snapshot.
- Refuses, before anything is written: an input that is not a snapshot of this `schema_version`; an already
  anonymised input; `run.redaction.include_secrets` true; a path outside the table (AX-8); a collision (AX-9); a key
  file that is not exactly 32 bytes or (as root) not trusted; `--out` naming the input file (by cleaned path or
  `os.SameFile`).
- Writes the output with `O_CREATE|O_EXCL` and mode 0600 (`--force`, after every refusal has passed, removes an
  existing regular file first; `--out` naming the key file or the input is refused even with `--force`), and
  removes a partial file on a write error; this lives in `cmd/muster`, built on every platform. `-` is stdout. Exit 0
  written, 2 refused. As root it warns, as `check` does.
- The transform is pure: `internal/anonymize` imports no `os`, `os/exec`, `net`, `syscall` (a test enforces it) and
  takes the key and the decoded tree; `cmd/muster` reads and writes. Every `[]byte` entry point has a `Fuzz<Name>`
  target and the package joins `fuzz.yml`'s list.

## 3. `--max-age`

- `check --max-age <d>` and `fix --dry-run --max-age <d>`; `fixValueFlags` gains it (a test ties the map to the
  parser). Not on `collect`, `snapshot extract`, `snapshot anonymize` or `controls`.
- The test runs after the snapshot is read and its schema accepted, before the profile is resolved — so a stale
  snapshot is refused even with a broken profile file, and nothing else runs.
- `snapshot anonymize` keeps `collected_at` byte-identical, so an anonymised snapshot ages like its original.

## 4. Tests and CI

- **The invariant corpus:** every `controls/testdata/<id>/*.json`, `controls/testdata/_hosts/*`, `cmd/muster/testdata/
  full-{pass,fail}.json`, `examples/ubuntu-24.04-{vm,container}.json`, and new synthetic fixtures: one per keep-set
  clause where the compared name is a mapped non-system name, the same fixture with the preserved name; a mount table
  where a human account named `log` has its home at `/tmp`; nested and shared homes; a `journal_upload.url` of `""`
  with an active, enabled upload unit and no rsyslog forward. Compared: status, reason_code, mechanism, the
  observation verdict multiset, the exit code — under every built-in profile. Not `snapshot_digest`, subjects or
  evidence text.
- **Delete the call, see red:** removing `root` or `ftp` from the keep set; letting the path rule rewrite by
  component; mapping `""` to a pseudonym; mapping an address before `exposure` is derived (a synthetic test).
- **Canary sweep:** a synthetic host with one unique canary per class in every classified location — the host's own
  short name, `source.raw` at a cut ending in `…`, every text field, every header field, an account-named
  `/etc/sudoers.d/` drop-in and an EL `/var/spool/mail/` spool — and the anonymised snapshot, and the check JSON,
  plan JSON and table made from it, contain none of them.
- **Fix on an anonymised snapshot:** `fix --dry-run --format script` exits 2 with an empty stdout while `table` and
  `json` succeed; deleting the refusal turns it red.
- **Host-or-address forms:** one canary per address form and per host form (a bare name, `host:port`, a syslog
  target, a wildcard, a netgroup).
- **Presence:** a `cron.files` row with a `reason` next to one without; after anonymisation the first still has a
  (placeholdered) `reason` and the second none.
- **Properties:** deterministic per key; injective per class; class kept for every address; an anonymised input
  refused; the output passes `facts.Load`; the classification tests (AX-8) and the keep-set pin (AX-5).
- **`--max-age`:** the grammar table; inclusive bound; future within and beyond 5 minutes; empty and malformed
  `collected_at`; refusal before a broken profile; stdout empty and exit 2; `--allow-error`/`--fail-on none` do not
  lift it; without the flag the output is byte-identical (goldens and examples unchanged); `remedy.Build` copies
  `max_age_s` into the plan (a test pins it).
- CI: `go test` as today; the fuzz list; no examples change (no flag in the examples run).

## 5. Documents

Main design pair (line-aligned): §5.6 corrected (authorized_keys stores no comment, `sshkeys_parse.go:21-28`), §7.2 and
§7.5 (the max-age refusal and `fix --format script`'s refusal of an anonymised snapshot), §8 `:426` reworded, §9
(`check.max_age_s`, `fix.max_age_s`, `run.anonymization`), §10.2 (3D-3 merged), D36 (AX-1, AX-2, AX-7, AX-11, AX-12,
AX-13, AX-14). THREAT_MODEL (the scheme; what it resists — dictionary inversion, searching for a known name, cross-key
linkage; what it does not — key compromise, quasi-identifiers, the address structure kept near special ranges, linkage
within one key, site files, timing; max-age attests nothing; the stale `--include-secrets` sentence at `:71`).
SECURITY.md (an anonymised snapshot carrying an identity the policy says it must not is in scope). README pair (the
command, the invariant, the placeholdered evidence, what an anonymised snapshot is not: secret-free, unidentifiable,
harmless). CLAUDE.md (a 3D-3 note). CHANGELOG. Usage texts of `check`, `fix` and `snapshot`.

## 6. Parked

- `collect --anonymize` (a pipe-only use with `--out -` to a remote host).
- Mapping site files — tuning, waivers, site profiles — under the same key, with a rule for each parameter's and
  subject's class.
- A token pass over free text that keeps evidence readable.
- A warn-only age mode (`--warn-age`), and age shown on table line 1.
- Anonymising check JSON or plan JSON directly (the receiver regenerates them from the anonymised snapshot).
- Stage 4 retention (`snapshot prune --keep-days`) reusing the duration parser and the strict `collected_at` reader.
