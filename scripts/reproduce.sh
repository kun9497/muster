#!/bin/sh
# Rebuilds a git ref of muster the way the release builds it and compares the
# binary's bytes with a published artefact's (spec §4.3 RL-8). The release is
# reproducible because every input is the commit's: the toolchain named by its
# go.mod, -trimpath and -buildvcs=false, and -X values that are the version,
# the full commit and the commit date in UTC (RA-1) -- never the build's clock.
#
#   sh scripts/reproduce.sh --ref <git ref> --version <string> [--arch amd64|arm64] <artefact>
#   sh scripts/reproduce.sh --print-date --ref <git ref>
#
# --version is the exact version string the release used (dist/metadata.json
# .version; a tag vX.Y.Z is released as X.Y.Z). <artefact> is a release
# .tar.gz, .deb or .rpm, or a bare binary; --arch is the artefact's (default
# amd64). Run it inside a muster checkout that holds the ref: it builds in a
# temporary detached worktree, removed on exit, under GOTOOLCHAIN set to the
# ref's toolchain line (downloaded when absent) and proves that toolchain with
# scripts/check-go-toolchain.sh --exact. --print-date prints the -X main.date
# value of the ref and builds nothing.
#
# Prints `built   <sha256>` and `artefact <sha256>`; exits 0 when they are
# equal, 1 when they differ or a step fails, 2 on a usage error or a missing
# tool.
set -eu

usage() {
	echo "usage: sh scripts/reproduce.sh --ref <git ref> --version <string> [--arch amd64|arm64] <artefact>" >&2
	echo "       sh scripts/reproduce.sh --print-date --ref <git ref>" >&2
	exit 2
}

need() {
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is not on PATH" >&2; exit 2; }
	done
}

ref='' version='' version_set='' arch=amd64 artefact='' print_date=''
while [ "$#" -gt 0 ]; do
	case "$1" in
		--ref) [ "$#" -ge 2 ] || usage; ref=$2; shift 2 ;;
		--version) [ "$#" -ge 2 ] || usage; version=$2; version_set=1; shift 2 ;;
		--arch) [ "$#" -ge 2 ] || usage; arch=$2; shift 2 ;;
		--print-date) print_date=1; shift ;;
		-*) usage ;;
		*) [ -z "$artefact" ] || usage; artefact=$1; shift ;;
	esac
done
[ -n "$ref" ] || usage
if [ -n "$print_date" ]; then
	[ -z "$version_set" ] && [ -z "$artefact" ] || usage
else
	[ -n "$version_set" ] && [ -n "$artefact" ] || usage
	case "$version" in
		'' | *[[:space:]\"\']*) echo "error: --version must be non-empty, without whitespace or quotes" >&2; exit 2 ;;
	esac
	case "$arch" in
		amd64 | arm64) ;;
		*) echo "error: --arch must be amd64 or arm64, not $arch" >&2; exit 2 ;;
	esac
	[ -f "$artefact" ] || { echo "error: $artefact is not a file" >&2; exit 2; }
	case "$artefact" in
		/*) ;;
		*) artefact=$PWD/$artefact ;;
	esac
	case "$artefact" in
		*.tar.gz) need tar ;;
		*.deb) need tar; command -v dpkg-deb >/dev/null 2>&1 || need ar ;;
		*.rpm) need rpm2cpio cpio ;;
	esac
	need go sed head sha256sum mktemp
fi
need git

# A step that fails after the arguments were accepted exits 1, never with the
# failing tool's own status (2 is usage or a missing tool only).
fail() {
	echo "error: $*" >&2
	exit 1
}

# The commit date in UTC, the value GoReleaser's {{ .CommitDate }} renders.
# format-local under TZ=UTC: plain format: prints the committer's own offset
# behind a false Z.
commit_date() {
	TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ "$1"
}

sha=$(git rev-parse --verify --quiet "$ref^{commit}") || { echo "error: $ref is not a commit in this repository" >&2; exit 1; }
if [ -n "$print_date" ]; then
	commit_date "$sha" || fail "cannot read the commit date of $ref"
	exit 0
fi

date=$(commit_date "$sha") || fail "cannot read the commit date of $ref"
tmp=$(mktemp -d) || fail "cannot make a temporary directory"
src=$tmp/src
cleanup() {
	git worktree remove --force "$src" 2>/dev/null || :
	rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

git worktree add --quiet --detach "$src" "$sha" >&2 || fail "git worktree add of $ref failed"
toolchain=$(sed -n 's/^toolchain //p' "$src/go.mod" | head -n 1)
[ -n "$toolchain" ] || fail "$ref's go.mod names no toolchain line"
GOTOOLCHAIN=$toolchain
export GOTOOLCHAIN
(cd "$src" && sh scripts/check-go-toolchain.sh --exact "$src/go.mod") >&2 ||
	fail "the toolchain is not $toolchain, the one $ref's go.mod names"

mkdir "$tmp/out" "$tmp/x" || fail "cannot make directories under $tmp"
(
	cd "$src" &&
		CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOAMD64=v1 GOARM64=v8.0 GOFLAGS=-mod=readonly 			go build -trimpath -buildvcs=false 			-ldflags "-s -w -X main.version=$version -X main.commit=$sha -X main.date=$date" 			-o "$tmp/out/muster" ./cmd/muster
) || fail "go build of $ref failed"

# Only the one member that holds the binary is extracted.
case "$artefact" in
	*.tar.gz)
		tar -xzf "$artefact" -C "$tmp/x" muster || fail "cannot extract muster from $artefact"
		bin=$tmp/x/muster
		;;
	*.deb)
		if command -v dpkg-deb >/dev/null 2>&1; then
			dpkg-deb --fsys-tarfile "$artefact" | tar -xf - -C "$tmp/x" ./usr/bin/muster ||
				fail "cannot extract ./usr/bin/muster from $artefact"
		else
			(cd "$tmp/x" && ar x "$artefact" && tar -xf data.tar.* ./usr/bin/muster) ||
				fail "cannot extract ./usr/bin/muster from $artefact"
		fi
		bin=$tmp/x/usr/bin/muster
		;;
	*.rpm)
		# nfpm's payload names are absolute (/usr/bin/muster); GNU cpio
		# writes them where they say unless told not to, and with
		# --no-absolute-filenames matches the stripped usr/bin/muster
		# (an rpmbuild payload names it ./usr/bin/muster).
		(cd "$tmp/x" && rpm2cpio "$artefact" | cpio -id --quiet --no-absolute-filenames 'usr/bin/muster' './usr/bin/muster') ||
			fail "cannot extract ./usr/bin/muster from $artefact"
		bin=$tmp/x/usr/bin/muster
		;;
	*) bin=$artefact ;;
esac
[ -f "$bin" ] && [ ! -L "$bin" ] || fail "$artefact holds no muster binary"

built=$(sha256sum "$tmp/out/muster" | sed 's/ .*//') || fail "cannot hash the build"
have=$(sha256sum "$bin" | sed 's/ .*//') || fail "cannot hash the artefact's binary"
echo "built   $built"
echo "artefact $have"
[ "$built" = "$have" ] || fail "the build does not reproduce the artefact"
