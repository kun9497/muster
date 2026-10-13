#!/bin/sh
# wait.sh <cid> <key>: wait for systemd in the container to settle; fail the job otherwise.
set -eu
cid=$1 key=$2 state=
i=0
while [ "$i" -lt 30 ]; do
  state=$(timeout 60 docker exec "$cid" systemctl is-system-running --wait 2>/dev/null) || :
  case "$state" in running|degraded) exit 0;; esac
  i=$((i+1)); sleep 2
done
printf '%s: boot did not settle (state %s)\n' "$key" "${state:-none}" >&2
docker exec "$cid" systemctl --failed --no-pager >&2 || :
exit 1
