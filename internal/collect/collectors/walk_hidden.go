//go:build linux

package collectors

// allowRow is one allowlist entry and the reason it is there. The reason is
// not decoration: an allowlist row silences a finding on every host muster
// ever runs on, and a row nobody can justify is a row that should be
// deleted. A test enforces that every row carries one.
type allowRow struct{ value, why string }

// hiddenExactPaths are the hidden entries the hidden rule passes over at
// one exact path each (A-17). The match is on the whole path, so a file
// with the same name anywhere else is still reported: the reason each of
// these is uninteresting is that a known piece of software puts it exactly
// there, and the same name in another directory has no such explanation.
var hiddenExactPaths = []allowRow{
	{"/.dockerenv", "docker marks a container's filesystem root with this file; it is the runtime's own marker, not something an administrator hid"},
	{"/etc/.pwd.lock", "the lock shadow-utils holds while it rewrites /etc/passwd, /etc/shadow and /etc/group"},
	{"/etc/.updated", "systemd-update-done stamps the last offline update here"},
	{"/var/.updated", "systemd-update-done stamps /var the same way it stamps /etc"},
	{"/etc/.resolv.conf.systemd-resolved.bak", "systemd-resolved keeps the resolv.conf it replaced here when it takes the file over"},
	{"/var/lib/rpm/.rpm.lock", "rpm's transaction lock, created by the package manager on every rpm-based distribution"},
	{"/tmp/.X11-unix", "the X server's socket directory; the X protocol fixes both the name and the location"},
	{"/tmp/.ICE-unix", "the ICE socket directory that sits beside it, with the same fixed name"},
	{"/tmp/.XIM-unix", "the X input method socket directory, likewise fixed by the protocol"},
	{"/tmp/.font-unix", "the X font server socket directory, likewise fixed by the protocol"},
	{"/tmp/.Test-unix", "the fifth socket directory the X server family creates, listed with the other four"},
}

// hiddenBareNames are the hidden names the rule passes over wherever they
// appear. Each is a name whose meaning does not depend on the directory it
// is in: it belongs to a deployed source tree, a web root or a toolchain,
// and a host that serves content has thousands of them. Listing them by
// name is what keeps the hidden list about entries somebody hid rather than
// about everything a deployment brought with it.
var hiddenBareNames = []allowRow{
	{".well-known", "the URI path RFC 8615 reserves; a served web root is meant to have one"},
	{".git", "a checked-out repository's metadata directory, carried by any deployment done with git"},
	{".gitignore", "git metadata that comes with a checkout"},
	{".gitattributes", "git metadata that comes with a checkout"},
	{".gitkeep", "the conventional marker that keeps an otherwise empty directory in a checkout"},
	{".keep", "the same empty-directory marker under its other common name"},
	{".placeholder", "the same empty-directory marker again, used by several deployment tools"},
	{".htaccess", "an Apache per-directory configuration file; a served tree is where it belongs"},
	{".bin", "the shim directory package managers create beside their installed modules"},
	{".github", "workflow and issue metadata a checkout of a GitHub-hosted repository brings with it"},
	{".npmignore", "packaging metadata inside a published node module"},
	{".eslintrc", "linter configuration inside a source tree"},
	{".eslintrc.js", "the same linter configuration in its JavaScript form"},
	{".eslintrc.json", "the same linter configuration in its JSON form"},
	{".prettierrc", "formatter configuration inside a source tree"},
	{".editorconfig", "editor configuration inside a source tree"},
	{".travis.yml", "continuous integration configuration inside a source tree"},
	{".package-lock.json", "a node package manager's lock file in the hidden form some tools write"},
	{".yarn-integrity", "yarn's integrity record inside an installed module tree"},
	{".dockerignore", "build context metadata inside a source tree"},
}

// The two tables are indexed once, at start-up, because the rule is asked
// about every entry of a whole-filesystem walk and a linear scan of
// thirty-one rows per entry would be thirty-one string comparisons per file.
var (
	hiddenExactSet = allowIndex(hiddenExactPaths)
	hiddenBareSet  = allowIndex(hiddenBareNames)
)

func allowIndex(rows []allowRow) map[string]bool {
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.value] = true
	}
	return out
}

// hiddenAllowlisted reports whether a hidden entry is one the rule passes
// over: its whole path is an exact row, or its bare name is a name row at
// any depth. name is the entry's own name, which the caller already has
// from the listing — the rule is asked once per entry of the walk, and
// splitting the path again here would be work done millions of times over.
//
// Neither table matches by prefix: /etc/.pwd.lock2 is not /etc/.pwd.lock,
// and .well-known2 is not .well-known. An allowlist that matched loosely
// would be an invitation to name a file just past the end of a row.
func hiddenAllowlisted(path, name string) bool {
	return hiddenBareSet[name] || hiddenExactSet[path]
}

// listCaps bounds how many rows one run records per list, in the order the
// walk's lists are declared: suid_sgid, suid_sgid_unverified,
// world_writable, sticky_missing, unowned, hidden (the entries that are NOT
// allowlisted) and skipped. The findings are capped lower than the two
// informational lists because a host with more than two thousand setuid
// binaries has a problem the two thousandth row will not add to, while the
// hidden and skipped lists are what a reader uses to judge whether the walk
// saw what it should have and are worth carrying further.
var listCaps = [7]int{2000, 2000, 2000, 2000, 2000, 10000, 10000}

// allowlistedHiddenCap bounds the separate count-and-sample the walk keeps
// of hidden entries it DID pass over, so a reviewer can see what the
// allowlist silenced without that sample growing with the size of a
// deployed source tree.
const allowlistedHiddenCap = 2000
