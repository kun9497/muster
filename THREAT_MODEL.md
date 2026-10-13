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
  anyway with a warning. A service block records each unit's enablement and activity under
  `$MUSTER_BACKUP/muster-units/` and, when the block fails, restores that state rather than enabling every
  unit; the script refuses a backup directory root does not own or others can write.
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
  without regenerating the id. It fails closed on one edge: an id surrounded by Unicode whitespace the
  collector trims (U+00A0, U+0085) but the script's `tr -d '[:space:]'` keeps is hashed by the collector and
  not by the script, so the guard refuses its own host; `MUSTER_ANY_HOST=1` overrides it.

## Reporting

See `SECURITY.md`.
