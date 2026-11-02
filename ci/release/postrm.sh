#!/bin/sh
# Debian postrm for the muster package (spec §4.6 RL-13). On purge only it
# removes /var/lib/muster -- the snapshots, the lock and `latest` that
# `muster collect` created -- and nothing else; on remove, upgrade and every
# other action it does nothing. A symlink at /var/lib/muster is removed, never
# followed. --one-file-system: a filesystem mounted at /var/lib/muster keeps
# its content, and the mount point stays. rpm has no purge; the rpm package
# carries no scripts and erase leaves the directory.
set -e
case "$1" in
	purge)
		if [ -L /var/lib/muster ]; then
			rm -f /var/lib/muster
		elif [ -d /var/lib/muster ]; then
			rm -rf --one-file-system /var/lib/muster
		fi
		;;
esac
exit 0
