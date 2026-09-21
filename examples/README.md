# Example snapshots and reports

What a real `muster collect` snapshot and the reports `muster check` makes from it look like,
so nobody has to run anything to see the shape of the output.

**No file in this directory comes from anyone's host.** One snapshot is collected inside a
public `ubuntu:24.04` container, the other on the throwaway GitHub Actions runner VM that
builds this repository, and both are rewritten (below) before they are kept.

| File | Where it comes from |
| --- | --- |
| `ubuntu-24.04-container.json` | `muster collect --deep` inside the public `ubuntu:24.04` image: an overlay root, no systemd, the walk lists `unsupported`. |
| `ubuntu-24.04-container-report.json` / `-report.txt` | `muster check` on that snapshot, as JSON and as the table. |
| `ubuntu-24.04-vm.json` | `muster collect --deep` on the GitHub Actions `ubuntu-24.04` runner VM, with the walk exclusions of `.github/walk-excludes` — the same file `ci.yml` reads — so the walk lists carry real rows. |
| `ubuntu-24.04-vm-report.json` / `-report.txt` | `muster check` on that snapshot, as JSON and as the table. |

When a refresh is pending, the six files may be missing; the test that checks the examples
then skips, saying so.

Produced by run [`35548200943`](https://github.com/kun9497/muster/actions/runs/35548200943) of [`.github/workflows/examples.yml`](../.github/workflows/examples.yml).
The snapshot headers carry the rest of the provenance: `muster_version`, `commit`,
`collected_at` and `host.os_release` — the workflow builds the binary with `make build`, so those
are the real version and commit and not the unstamped defaults.

## The commands

```sh
make build                                  # stamps the version and commit

# in the container
docker run --rm --platform linux/amd64 -v "$PWD/bin:/m:ro" -v "$RUNNER_TEMP/ex:/out" \
  ubuntu:24.04 /m/muster collect --deep --out /out/ubuntu-24.04-container.json

# on the runner VM (the --walk-exclude list of .github/walk-excludes, which
# ci.yml's collect-root job reads from the same file)
sudo ./bin/muster collect --deep --walk-budget 15m --walk-max-entries 6000000 \
  --walk-exclude ... --require-root --out "$RUNNER_TEMP/ex/ubuntu-24.04-vm.json"

# the reports, after the rewrite below
NO_COLOR=1 ./bin/muster check --facts <snapshot> --format json > <snapshot>-report.json
NO_COLOR=1 ./bin/muster check --facts <snapshot> --format table > <snapshot>-report.txt
```

## The rewrite

Before `check` runs, the workflow rewrites each snapshot with `jq` so that nothing
host-shaped is committed:

- `run.host.hostname` becomes `ubuntu-container` or `github-runner`;
- `run.host.boot_id` (a boot UUID), `run.host.kernel` and `run.host.uptime_s` are blanked —
  they describe the runner's kernel, not the image;
- every `addr` in `facts.sockets.listening.value` that is neither loopback (`127.`, `::1`) nor
  a wildcard (`0.0.0.0`, `::`) becomes `192.0.2.1` (RFC 5737) or, for an IPv6 address,
  `2001:db8::1` (RFC 3849);
- every RFC 1918 address (`10/8`, `172.16/12`, `192.168/16`) a host's own configuration put
  into a fact is renumbered into `198.51.100.0/24`, keeping its last octet and any `/prefix`,
  so a 10/8 network like `10.<x>.<y>.0/24` becomes `198.51.100.0/24`. The facts scanned are the firewall's
  `raw_dumps[].content` and `rules[].saddr`, the `files.etc_hosts_allow_lines`,
  `files.etc_hosts_deny_lines` and `files.etc_hosts_equiv_lines` line lists,
  `time_sync.servers`, and each `nfs.exports[].client`;
- `run.host.machine_id_hash` is already a hash and stays.

The workflow refuses an example over 4 MiB, and asserts the rewrite afterwards rather than
assuming it — first per fact, and then over the whole file, which is grepped for the three
shapes [`.gitleaks.toml`](../.gitleaks.toml) refuses in a tracked file (an RFC 1918 address, a
private DNS suffix, a non-personal e-mail address), with that file's own literal allowlists
applied. A fact nobody thought of is caught there rather than by the secrets job after the
commit.

## Refreshing them

```sh
gh workflow run examples.yml --ref main
make examples-fetch RUN=<run id>          # gh run download into examples/
```

Then review the diff — the whole point of this directory is that a person looks at the files
before they are committed — update the run id above, and commit.

`cmd/muster/examples_test.go` reloads every snapshot here, re-runs `check` in process and
compares both reports byte for byte, ignoring only the four provenance fields that differ
between a release binary and `go test` (`muster_version`, `commit`, `controls_version`,
`controls_digest`) and the table's first line.

A stale example never fails the suite. The test reads the committed report's own
`check.controls_digest` and compares it with the digest of the control set this build
embeds: when they differ, the example was collected against a set whose verdicts this
binary cannot reproduce, so the test logs `collected against control set <digest>, this
build is <digest>; byte comparison skipped` and skips **only** that comparison. Loading the
snapshot, evaluating it and the assertion that no control ends in `ERROR(internal_error)`
are properties of the snapshot, not of the control set, and they run either way. When the
two digests match, both reports are compared as above and any difference is a failure —
refresh the examples.
