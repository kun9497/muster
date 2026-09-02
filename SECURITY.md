# Security policy

## Reporting a vulnerability

Open a private security advisory on the GitHub repository (Security → Report a vulnerability). Do not
open a public issue for a vulnerability in muster itself. Expect an acknowledgement within seven days.

Findings about hosts that muster reported on are not vulnerabilities in muster; do not send them here.

## Supported versions

Until 1.0, only the latest tagged release receives fixes.

## Scope

The threat model is in `THREAT_MODEL.md`. In scope: anything that makes `collect` write, execute or
transmit more than it declares; anything that makes `check` execute content from a snapshot, control or
waiver file; a data file turning an `ERROR` into a clean exit; a snapshot storing a secret that the
redaction policy says it must not.
