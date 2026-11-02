#!/bin/sh
# contract.sh <deb|rpm|tar> <artefact> <snapshot.json> <expected exit> <version>
# -- the install contract (spec §4.6 RL-11, RL-13; §4.7). It runs inside a bare
# distribution image, as root, with no network and no package installation:
# CI's install-contract job mounts dist/ at /dist, ci/release/ at /ci and
# examples/ at /ex. It installs the artefact (dpkg -i, rpm -U --replacepkgs --
# RA-42: rpm -U of an installed NEVRA exits 2 -- or tar -xzf into
# /opt/muster-tar) and asserts what the package does and does not do:
#   - the installed file list (dpkg -L / rpm -ql, or the archive's tar -tzf,
#     sorted) equals the committed ci/release/contract-files.<deb|rpm|tar>.txt
#     exactly, compared with comm, since the EL images carry no diff;
#   - deb/rpm: /usr/bin/muster is mode 755, owned by 0:0;
#   - the package metadata and version (nfpm's spelling: - becomes ~, plus -1);
#   - nothing named muster* anywhere under /etc/systemd, /usr/lib/systemd or
#     /lib/systemd (a unit or a *.wants/ enablement link), no process named
#     muster, no /var/lib/muster;
#   - muster version prints five lines, the first `muster <version>`;
#   - muster check over the example snapshot exits with <expected exit>;
# then installs the same package again (the upgrade) and asserts the same;
# then removes it: a snapshot under /var/lib/muster survives and /usr/bin/muster
# is gone. deb only, purge: a real /var/lib/muster is removed; a symlink at
# /var/lib/muster is removed and its target survives.
set -eu

if [ "$#" -ne 5 ]; then
	echo "usage: contract.sh <deb|rpm|tar> <artefact> <snapshot.json> <expected exit> <version>" >&2
	exit 2
fi
kind=$1 pkg=$2 snap=$3 want=$4 version=$5
here=$(dirname "$0")

fail() {
	echo "contract: FAIL: $*" >&2
	exit 1
}
step() {
	echo "contract: $*"
}

case "$kind" in
deb | rpm) bin=/usr/bin/muster ;;
tar) bin=/opt/muster-tar/muster ;;
*)
	echo "contract: unknown kind $kind" >&2
	exit 2
	;;
esac
[ -f "$pkg" ] || fail "no artefact at $pkg"
[ -f "$snap" ] || fail "no snapshot at $snap"

# nfpm's conventional package version: 0.0.1-next -> 0.0.1~next-1.
pkgversion="$(printf '%s' "$version" | sed 's/-/~/g')-1"

install_it() {
	case "$kind" in
	deb) dpkg -i "$pkg" >/dev/null ;;
	rpm) rpm -U --replacepkgs "$pkg" ;;
	tar)
		mkdir -p /opt/muster-tar
		tar -xzf "$pkg" -C /opt/muster-tar
		;;
	esac
}

metadata() {
	case "$kind" in
	deb)
		got=$(dpkg-deb -f "$pkg" Maintainer Homepage Section Priority)
		exp=$(printf '%s\n' \
			'Maintainer: seonggyun.seo <40746364+kun9497@users.noreply.github.com>' \
			'Homepage: https://github.com/kun9497/muster' \
			'Section: admin' \
			'Priority: optional')
		[ "$got" = "$exp" ] || fail "deb metadata is
$got
want
$exp"
		got=$(dpkg-deb -f "$pkg" Version)
		[ "$got" = "$pkgversion" ] || fail "deb Version is $got, want $pkgversion"
		;;
	rpm)
		got=$(rpm -qp --qf '%{PACKAGER}\n%{URL}\n%{GROUP}\n%{RELEASE}\n' "$pkg")
		exp=$(printf '%s\n' \
			'seonggyun.seo <40746364+kun9497@users.noreply.github.com>' \
			'https://github.com/kun9497/muster' \
			'Applications/System' \
			'1')
		[ "$got" = "$exp" ] || fail "rpm metadata is
$got
want
$exp"
		got=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$pkg")
		[ "$got" = "$pkgversion" ] || fail "rpm version is $got, want $pkgversion"
		;;
	esac
}

# same_list <committed list> <what> -- /tmp/contract-files.txt equals the
# list. The EL images carry no diff (diffutils); comm is coreutils'.
same_list() {
	if [ "$(cat "$1")" != "$(cat /tmp/contract-files.txt)" ]; then
		echo "contract: < only in $(basename "$1"), > only in $2:" >&2
		LC_ALL=C comm -3 "$1" /tmp/contract-files.txt | sed 's/^\t/> /; t; s/^/< /' >&2
		fail "$2 differs from $(basename "$1")"
	fi
}

assert_installed() {
	step "assert installed ($1)"
	case "$kind" in
	deb)
		dpkg -L muster | LC_ALL=C sort >/tmp/contract-files.txt
		same_list "$here/contract-files.deb.txt" "dpkg -L muster"
		;;
	rpm)
		rpm -ql muster | LC_ALL=C sort >/tmp/contract-files.txt
		same_list "$here/contract-files.rpm.txt" "rpm -ql muster"
		;;
	tar)
		tar -tzf "$pkg" | LC_ALL=C sort >/tmp/contract-files.txt
		same_list "$here/contract-files.tar.txt" "tar -tzf $(basename "$pkg")"
		;;
	esac
	[ -f "$bin" ] && [ -x "$bin" ] || fail "$bin is not an executable file"
	if [ "$kind" != tar ]; then
		got=$(stat -c '%a %u %g' "$bin")
		[ "$got" = "755 0 0" ] || fail "$bin is '$got' (mode uid gid), want '755 0 0'"
	fi
	# An enabling maintainer script would leave a *.wants/ link that no file
	# list records; look under every systemd tree, at any depth.
	found=$(find /etc/systemd /usr/lib/systemd /lib/systemd -name 'muster*' 2>/dev/null || true)
	[ -z "$found" ] || fail "a unit or an enablement link was installed: $found"
	for c in /proc/[0-9]*/comm; do
		[ "$(cat "$c" 2>/dev/null)" != muster ] || fail "a process named muster runs ($c)"
	done
	[ ! -e /var/lib/muster ] && [ ! -L /var/lib/muster ] || fail "/var/lib/muster exists after install"
	"$bin" version >/tmp/contract-version.txt || fail "muster version exited $?"
	n=$(wc -l </tmp/contract-version.txt)
	[ "$n" -eq 5 ] || fail "muster version printed $n lines, want 5"
	line1=$(sed -n 1p /tmp/contract-version.txt)
	[ "$line1" = "muster $version" ] || fail "muster version line 1 is '$line1', want 'muster $version'"
	rc=0
	"$bin" check --facts "$snap" --format json >/dev/null || rc=$?
	[ "$rc" -eq "$want" ] || fail "muster check exited $rc, want $want"
}

metadata
step "install $pkg"
install_it
assert_installed install
step "upgrade (the same package again)"
install_it
assert_installed upgrade

[ "$kind" != tar ] || {
	step "PASS"
	exit 0
}

mkdir -p /var/lib/muster/snapshots
touch /var/lib/muster/snapshots/keep.json
step "remove"
case "$kind" in
deb) dpkg -r muster >/dev/null ;;
rpm) rpm -e muster ;;
esac
[ -f /var/lib/muster/snapshots/keep.json ] || fail "remove deleted /var/lib/muster/snapshots/keep.json"
[ ! -e /usr/bin/muster ] || fail "/usr/bin/muster survives the remove"

if [ "$kind" = deb ]; then
	step "purge (a): a real /var/lib/muster"
	dpkg -i "$pkg" >/dev/null
	dpkg -P muster >/dev/null
	[ ! -e /var/lib/muster ] && [ ! -L /var/lib/muster ] || fail "purge left /var/lib/muster"

	step "purge (b): /var/lib/muster a symlink"
	dpkg -i "$pkg" >/dev/null
	mkdir -p /srv/muster-elsewhere/snapshots
	touch /srv/muster-elsewhere/snapshots/keep.json
	ln -s /srv/muster-elsewhere /var/lib/muster
	dpkg -P muster >/dev/null
	[ ! -e /var/lib/muster ] && [ ! -L /var/lib/muster ] || fail "purge left the /var/lib/muster symlink"
	[ -d /srv/muster-elsewhere ] && [ ! -L /srv/muster-elsewhere ] || fail "purge removed the symlink's target"
	[ -f /srv/muster-elsewhere/snapshots/keep.json ] || fail "purge removed the file under the symlink's target"
fi
step "PASS"
