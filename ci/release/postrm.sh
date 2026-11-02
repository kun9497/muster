#!/bin/sh
# Debian postrm for the muster package (spec §4.6 RL-13, RA-40). On purge only,
# and on no other action (remove, upgrade, ...):
#   - a symlink at /var/lib/muster is removed, never followed;
#   - a directory that is a mount point (its device differs from
#     /var/lib's) is left untouched, content and all, and a line on stderr
#     says so;
#   - any other directory is removed with rm -rf --one-file-system, so a
#     filesystem mounted below it keeps its content.
# Nothing else is touched. The purge never fails because of this script: a
# command that fails prints a line and the script still exits 0. rpm has no
# purge; the rpm package carries no scripts and erase leaves the directory.
set -eu
d=/var/lib/muster
case "${1:-}" in
	purge)
		if [ -L "$d" ]; then
			rm -f "$d" || echo "muster: could not remove the symlink $d" >&2
		elif [ -d "$d" ]; then
			own=$(stat -c %d "$d" 2>/dev/null) || own=''
			parent=$(stat -c %d /var/lib 2>/dev/null) || parent=''
			if [ -z "$own" ] || [ -z "$parent" ]; then
				echo "muster: could not stat $d or /var/lib; $d left for the operator" >&2
			elif [ "$own" != "$parent" ]; then
				echo "muster: $d is a mount point; left for the operator" >&2
			else
				rm -rf --one-file-system "$d" || echo "muster: could not remove $d entirely" >&2
			fi
		fi
		;;
esac
exit 0
