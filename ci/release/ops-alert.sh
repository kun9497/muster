#!/bin/sh
# ops-alert.sh <workflow> <result> <run url>: open, update or close the one
# pinned "<workflow> failed" issue (spec §4.10; assay's scripts/ops-alert.sh).
#
# Run by release.yml's alert job with the goreleaser job's result:
#
# failure:   the open issue titled "<workflow> failed" (label ops) gets the
#            run URL in its body; with none open, one is created and pinned,
#            so a failed release is on the repository's front page, not only
#            in the Actions tab.
# success:   the open issue, if any, is unpinned and closed with the run URL.
# cancelled, skipped: nothing (a person stopped the run, or the job never ran).
#
# One issue per workflow, found by its exact title. Needs GH_TOKEN with
# issues: write and GH_REPO (the alert job passes both).
set -eu
usage() {
  echo "usage: sh ci/release/ops-alert.sh <workflow> <result> <run url>" >&2
  exit 2
}
[ "$#" -eq 3 ] || usage
workflow=$1
result=$2
url=$3
[ -n "$workflow" ] && [ -n "$url" ] || usage
title="$workflow failed"
label=ops
when=$(date -u +%Y-%m-%dT%H:%MZ)

case "$result" in
  success | failure) ;;
  cancelled | skipped)
    echo "ops-alert: $workflow $result; nothing to do"
    exit 0
    ;;
  *)
    echo "error: unknown result '$result'" >&2
    exit 2
    ;;
esac

# Captured on its own, not piped: a failed lookup must fail this script
# (set -e), never read as "no open issue".
found=$(gh issue list --label "$label" --state open --limit 100 --json number,title \
  --jq ".[] | select(.title == \"$title\") | .number")
open=$(printf '%s\n' "$found" | head -n 1)

body="\`$workflow\` failed at $when.

Run: $url

This issue stays open and pinned while the workflow keeps failing; each
failure replaces this body with its run. The next successful run closes it."

if [ "$result" = failure ]; then
  if [ -n "$open" ]; then
    gh issue edit "$open" --body "$body"
    echo "ops-alert: updated #$open"
    exit 0
  fi
  # --force: create the label if it does not exist, leave it if it does.
  gh label create "$label" --color B60205 --description "A release or ops workflow is failing" --force >/dev/null
  new=$(gh issue create --title "$title" --label "$label" --body "$body")
  n=${new##*/}
  # Pinning fails once three issues are pinned; the issue still notifies.
  gh issue pin "$n" || echo "ops-alert: could not pin #$n" >&2
  echo "ops-alert: opened #$n"
  exit 0
fi

if [ -n "$open" ]; then
  gh issue unpin "$open" || true
  gh issue close "$open" --comment "Recovered at $when: $url"
  echo "ops-alert: closed #$open"
else
  echo "ops-alert: $workflow succeeded; no open issue"
fi
