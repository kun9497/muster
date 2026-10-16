# Threat model

muster runs as root on production hosts and produces the most concentrated description of a host an
attacker could ask for. This document says what the tool trusts, what it refuses, and what it cannot do.
The contracts here are tested; the design specification (section 8) is the source.

## Trust boundary

- `collect` runs as root. It reads only paths its collector registry declares and runs only commands on a
  fixed whitelist (absolute path, fixed arguments, timeout, output cap, no shell, rebuilt environment).
  It never parses a control file, a waiver file or a previous snapshot. It writes exactly one file: the
  snapshot. It makes no network connection. Reading a POSIX ACL requires opening the file, so without
  root the `files` collector reports `/etc/shadow`'s ACL leaves as denied and the run is partial even
  though its mode and owner were read.
- `check` does not need root and warns when run as root. It treats the snapshot as untrusted input
  (size and nesting limits, no execution of anything it contains, escaped rendering) and, when root,
  refuses waiver, profile, tuning and control files that are not root-owned or are group/other-writable.
- `fix --dry-run` reads what `check` reads, under the same rules, and writes its plan and review script to
  stdout only. muster never executes the script; the operator reviews and runs it by hand.
- The review script carries the snapshot's `host.machine_id_hash` (the sha256 of `/etc/machine-id`, never
  the id itself) as its one host value in a command, admitted only as 64 lowercase hex characters, which
  carry no shell syntax. Before it changes anything, as root, it hashes the running host's
  `/etc/machine-id` and exits 2 when the hashes differ or the id cannot be read; `MUSTER_ANY_HOST=1` runs it
  anyway with a warning. A profile's or tuning's parameter value is policy, not a host value: it enters a
  command only as a `P_<name>='<value>'` assignment at the head of its block, and only when it passes its
  type's charset (an optionally signed integer, `^-?[0-9]+$`; `true`/`false`; or `[A-Za-z0-9._/@:+,=-]` per
  element), which holds no quote, blank, `$`, backtick, `;`, `|`, `&` or `\`; any other value leaves the
  item text-only. Each block records what it changes under its own `$MUSTER_BACKUP/blocks/<fn>/` — file copies and absent-path markers, unit
  enablement and activity (`units/`), owners, groups and modes (`modes.list`), kernel values
  (`sysctl.list`), module load states (`modules.list`) — and, when the block fails, runs its declared
  rollback and restores that state rather than enabling every unit. Neither restore writes through a
  symlink: `restore` replaces a symlink found at a destination with the copy and leaves a path that became
  a directory, and `restore_modes` logs and leaves a path that has become a symlink or changed type (a
  file now a directory). `restore_modes` also refuses a path whose directories up to `/` are not all
  root-owned and not other-writable, or a path recorded as non-root-owned in a group- or other-writable
  directory, so
  its `chown`/`chmod` cannot be redirected by someone who can rename entries there; a root-owned
  group-writable directory (Ubuntu's `root:syslog 0775 /var/log`) is accepted, which trusts that group with
  the paths under it — the trust the host already gives it. The bodies that change files under such
  directories (`log_dir_permissions`; every file pass of `cron_permissions` and `audit_log_permissions`,
  which fix their directories first) apply the same rule and leave an untrusted directory to the operator.
  A system crontab or sudoers file not owned by root is never chowned or re-moded: cron and sudo ignore
  it, and adopting it would activate content another user wrote, so the block logs it and rolls back.
  `restore_modules` reloads a module that was loaded with `modprobe --ignore-install`, bypassing the
  `install … /bin/false` line the restore has just put back (and any vendor `install` line for that module). A block's first record
  is kept across runs with the same `MUSTER_BACKUP`, except an absent-path marker: when a later run finds the path (an earlier run
  created it), it records that file, and a failure restores it rather than removing it. The script
  refuses a backup directory root does not own or others can write.
- Controls are embedded in the binary. An external control directory is opt-in, logged with digests and
  refused on id collision.

## What the snapshot contains and does not

By default: derived attributes instead of secrets — hash algorithm rather than hash, key fingerprint
rather than key, whether an SNMP community is a default value rather than the string. `--include-secrets`
records itself in the snapshot header. Files are 0600 in a 0700 directory, written atomically, never
under `/tmp` by default.

## Reads and the filesystem walk

Every read goes through one primitive that never follows a symbolic link in any path component
(`openat2` with `RESOLVE_NO_SYMLINKS`, or a component-wise `O_NOFOLLOW` walk), refuses FIFOs, devices
and sockets, and caps size. The deep walk is off by default, stays on local filesystems, never enters
`/proc`, `/sys`, `/dev`, `/run` or autofs mount points, and ends with `complete=false` when over budget.

## Limits

- A host that is already compromised — `LD_PRELOAD`, replaced binaries, settings reverted before a run —
  can make muster report `PASS`. muster is not an intrusion detector and does not attest the host.
- muster evaluates configuration, not exposure: it does not scan ports from outside or match CVEs.
- Results depend on the control set version; a report names the set it was produced with.
- The review script's host guard stops a script planned from one snapshot running on another host; it is
  not an authentication. It fails open when the snapshot has no well-formed hash (a container without a
  machine id, a symlinked or malformed `/etc/machine-id`, a hand-edited snapshot): the script then carries
  no guard and says so in a comment (`# host guard: off (the snapshot has no machine id)`). It does not
  catch a crafted snapshot, which can carry any hash. It cannot tell apart hosts cloned from one image
  without regenerating the id.

## Reporting

See `SECURITY.md`.
