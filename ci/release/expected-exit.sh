#!/bin/sh
# expected-exit.sh <report.json> -- print the exit code `muster check` gives for
# the report's results with no --fail-on and no --allow-error (spec §4.7 RL-11,
# internal/report/exitcode.go): 2 if any result is ERROR, else 1 if any is FAIL,
# else 0. It runs on the CI runner (jq); the install contract runs in bare
# images without jq and takes the number as an argument.
set -eu
if [ "$#" -ne 1 ]; then
	echo "usage: expected-exit.sh <report.json>" >&2
	exit 2
fi
jq -r '
	[.results[].status] as $s
	| if any($s[]; . == "ERROR") then 2
	  elif any($s[]; . == "FAIL") then 1
	  else 0 end' "$1"
