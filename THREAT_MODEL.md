# Threat model

muster runs as root on production hosts and produces the most concentrated description of a host an
attacker could ask for. This document says what the tool trusts, what it refuses, and what it cannot do.
The contracts here are tested; the design specification (section 8) is the source.

## Trust boundary

- `collect` runs as root. It reads only paths its collector registry declares and runs only commands on a
  fixed whitelist (absolute path, fixed arguments, timeout, output cap, no shell, rebuilt environment).
  It never parses a control file, a waiver file or a previous snapshot. It writes exactly one file: the
  snapshot. It makes no network connection.
- `check` does not need root and warns when run as root. It treats the snapshot as untrusted input
  (size and nesting limits, no execution of anything it contains, escaped rendering) and, when root,
  refuses waiver and control files that are not root-owned or are group/other-writable.
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

## Reporting

See `SECURITY.md`.
