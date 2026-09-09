//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The patch collector answers "is this host patched" from CACHED package
// metadata and cache-only simulations only (D27): it NEVER runs `apt-get
// update`, `dnf makecache`, or `dnf check-update` without `--cacheonly`, and
// never touches a repository. The collect-contract CI leg runs with
// `--network none` and `--read-only`; a refresh would not merely hang there,
// it would be a design violation — muster reports what the host already
// knows, it does not change the host's state.
//
// Because nothing here needs privilege (the dpkg and dnf caches are
// world-readable and both simulations are unprivileged), Needs is "none" and
// EVERY command failure is an environment limitation → `unsupported`, never
// denied or error (R220, the cronTimers shape). A collector that filed
// "dnf is not installed on this Ubuntu host" as an error would make
// `run.complete` false on a perfectly healthy host.
const (
	dpkgStatusPath = "/var/lib/dpkg/status"
	dpkgLogPath    = "/var/log/dpkg.log"

	aptListsDir     = "/var/lib/apt/lists"
	aptListsGlob    = "/var/lib/apt/lists/*"
	aptStampPath    = "/var/lib/apt/periodic/update-success-stamp"
	aptPeriodicConf = "/etc/apt/apt.conf.d/10periodic"
	aptAutoUpgrades = "/etc/apt/apt.conf.d/20auto-upgrades"

	// Ruling J-20: /run, never /var/run. /var/run is a symlink to /run on
	// every supported family; the read primitive refuses a symlinked path
	// component outright (ErrSymlink), FromReadError maps that to `error`,
	// and ONE error envelope flips `run.complete` and breaks both the
	// collect-contract leg and `collect-root --require-complete`. The real
	// path is the precedent os.go sets with /run/.containerenv and
	// services.go with /run/systemd/system.
	rebootRequiredPath     = "/run/reboot-required"
	rebootRequiredPkgsPath = "/run/reboot-required.pkgs"

	dnfCacheDir      = "/var/cache/dnf"
	dnfRepomdGlob    = "/var/cache/dnf/*/repodata/repomd.xml"
	dnfAutomaticConf = "/etc/dnf/automatic.conf"
)

// patchReadLimit caps the package database and the dpkg log, both of which
// are far larger than an ordinary configuration file: /var/lib/dpkg/status
// passes 1 MiB on a stock server install, and readLimit's 1 MiB would
// silently cut the inventory short. A read that still hits this cap comes
// back with ReadMeta.Truncated, which OKRead carries into the envelope, so a
// partial answer is never published as a complete one.
const patchReadLimit = 8 << 20

// rpmQaFormat is the query format the installed-package inventory asks rpm
// for. Ruling J-23: rpm expands \t and \n in a query format ITSELF, so this
// string must hold the literal BACKSLASH-t / BACKSLASH-n characters, never
// real control bytes — a raw TAB or LF here would split a `--list-actions`
// table row (commandString joins Path and Args with spaces onto one line)
// and would put a newline inside every evidence Source.Cmd. Written as a Go
// RAW string so the backslashes survive; the declaration, the run and the
// test key all use this one const.
const rpmQaFormat = `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`

// The commands the patch collector may run. Ruling J-24: RunCommand's
// default Timeout is 5 s and a timeout becomes `unsupported` — a false
// "nothing to report". dnf (Python start-up plus the solv cache) and
// `apt-get -s upgrade` on a large host routinely need more than that, so
// the four heavy commands set both fields explicitly. allowedCommand
// compares Path and Args only, so Timeout and MaxOutput are free to differ
// between the declaration and the run without breaking the byte-identical
// rule.
//
// Ruling J-30: `-o Debug::NoLocking=1` is belt-and-braces so an
// unprivileged simulation never fails on the apt lock; it is part of the
// declared Args, so it appears identically in the declaration, the run and
// the test key.
var (
	aptSimulateCmd     = collect.Command{Path: "/usr/bin/apt-get", Args: []string{"-s", "upgrade", "-o", "Debug::NoLocking=1"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20}
	dnfCheckUpdateCmd  = collect.Command{Path: "/usr/bin/dnf", Args: []string{"--cacheonly", "check-update"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20}
	dnfUpdateinfoCmd   = collect.Command{Path: "/usr/bin/dnf", Args: []string{"--cacheonly", "updateinfo", "list", "security"}, Timeout: 60 * time.Second, MaxOutput: 8 << 20}
	rpmQaCmd           = collect.Command{Path: "/usr/bin/rpm", Args: []string{"-qa", "--qf", rpmQaFormat}, Timeout: 60 * time.Second, MaxOutput: 8 << 20}
	aptMarkHoldCmd     = collect.Command{Path: "/usr/bin/apt-mark", Args: []string{"showhold"}}
	needsRestartingCmd = collect.Command{Path: "/usr/bin/needs-restarting", Args: []string{"-r"}}

	patchCommands = []collect.Command{
		aptSimulateCmd, dnfCheckUpdateCmd, dnfUpdateinfoCmd, rpmQaCmd, aptMarkHoldCmd, needsRestartingCmd,
	}
)

var patchCollector = collect.Collector{
	Name: "patch",
	Declare: collect.Declaration{
		Reads: []string{
			aptListsGlob, aptStampPath, aptPeriodicConf, aptAutoUpgrades,
			dpkgStatusPath, dpkgLogPath,
			rebootRequiredPath, rebootRequiredPkgsPath,
			dnfCacheDir, dnfRepomdGlob, dnfAutomaticConf,
		},
		Commands: patchCommands,
		// Ruling J-5: nothing here needs privilege, so a failure is never a
		// root-only refusal — see the package comment above.
		Needs: "none",
	},
	Run: runPatch,
}

// noCacheReason is the one sentence both leaves Ruling J-25 makes `absent`
// carry. They must be ABSENT, not unsupported: mergeSoft lets a single
// unsupported beat an absent, so an unsupported count would make U-64 read
// NOT_APPLICABLE — "this host has no security updates to worry about" —
// when the truth is that nobody can tell.
const noCacheReason = "no package metadata cache; the host may never have been updated (metadata is never refreshed by muster, D27)"

func runPatch(ctx context.Context, a collect.Access, b *collect.Builder) error {
	now := collectedAt(b)
	switch mgr := detectPatchManager(a); mgr {
	case "apt":
		b.Set("patch.manager", collect.OK(mgr, &facts.Source{Kind: "file", Path: dpkgStatusPath}))
		runPatchApt(ctx, a, b, now)
	case "dnf":
		b.Set("patch.manager", collect.OK(mgr, &facts.Source{Kind: "file", Path: dnfCacheDir}))
		runPatchDnf(ctx, a, b, now)
	default:
		b.Set("patch.manager", collect.OK(mgr, &facts.Source{Kind: "derived"}))
		runPatchUnknown(b)
	}
	return nil
}

// detectPatchManager names the package manager from the artefact each one
// always leaves behind: the dpkg database on the debian family, the dnf
// metadata cache directory on the rhel family. A host with neither is
// "unknown" and every judged leaf says so rather than guessing.
func detectPatchManager(a collect.Access) string {
	switch {
	case exists(a, dpkgStatusPath):
		return "apt"
	case exists(a, dnfCacheDir):
		return "dnf"
	}
	return "unknown"
}

// runPatchUnknown publishes the honest shape for a host muster cannot judge:
// every leaf unsupported, and an EMPTY inventory rather than a missing one —
// a registered key the snapshot lacks is ERROR(missing_fact), never
// absent_means.
func runPatchUnknown(b *collect.Builder) {
	const reason = "no supported package manager"
	e := collect.Unsupported(reason)
	for _, k := range []string{
		"patch.metadata_age_s", "patch.security_metadata_available", "patch.pending_security_count",
		"patch.pending_updates", "patch.reboot_required", "patch.held_packages", "patch.days_since_last_install",
	} {
		b.Set(k, e)
	}
	b.SetSetting("patch.auto_update.enabled", facts.Setting{Runtime: envp(collect.Unsupported(autoUpdateRuntimeReason)), Persisted: envp(e)})
	b.Set("packages.installed", collect.OK([]any{}, &facts.Source{Kind: "derived"}))
}

// --- the metadata cache -------------------------------------------------

// patchCache is what the cached metadata says about itself: whether there is
// a cache at all, how old the newest piece of it is, and whether it carries
// a security channel. Ruling J-26 makes `security` a FILE-based
// determination on both families rather than an exit code — `dnf --cacheonly
// updateinfo list security` exits 0 with empty stdout BOTH when there is no
// updateinfo metadata and when nothing is pending, so exit 0 plus no output
// is never by itself evidence that a host has no security updates.
type patchCache struct {
	present    bool
	newest     time.Time
	newestPath string
	security   bool
	// securityPath is the cached file that PROVED the security channel — the
	// -security list on apt, the repomd declaring updateinfo on dnf — so the
	// fact cites what was actually read rather than whichever file happened
	// to be newest (the J-41 lesson).
	securityPath string
	// failed is the envelope every cache-derived leaf carries when the cache
	// could not be listed at all; nil on every ordinary path.
	failed *facts.Envelope
}

// isSecuritySuite reports whether an apt list file name or a simulated
// upgrade's origin names a security channel. Ubuntu's expanded maintenance
// suites (esm-apps, esm-infra) publish security updates under their own
// names, so they count too.
func isSecuritySuite(s string) bool {
	return strings.Contains(s, "-security") || strings.Contains(s, "esm-apps") || strings.Contains(s, "esm-infra")
}

// aptCache reads nothing: it stats the cached index files apt writes on an
// update and reads their NAMES. The newest modification time is the age
// anchor (Ruling J-21) and a `-security` suite among them is the security
// channel (Ruling J-26).
func aptCache(a collect.Access) patchCache {
	var c patchCache
	matches, err := a.Glob(aptListsGlob)
	if err != nil {
		e := collect.ErrorEnv("glob " + aptListsGlob + ": " + err.Error())
		c.failed = &e
		return c
	}
	sort.Strings(matches)
	for _, m := range matches {
		base := path.Base(m)
		isIndex := strings.HasSuffix(base, "Packages") || strings.HasSuffix(base, "InRelease")
		if !isIndex {
			continue
		}
		if isSecuritySuite(base) && !c.security {
			c.security, c.securityPath = true, m
		}
		// Only a Packages list proves the index itself was fetched; an
		// InRelease alone names a suite without carrying its contents.
		if !strings.HasSuffix(base, "Packages") {
			continue
		}
		c.present = true
		c.noteNewest(a, m)
	}
	// The stamp apt's periodic job writes is the other evidence of a
	// successful refresh, and on a host whose lists were pruned it is the
	// only one left.
	if _, err := a.Stat(aptStampPath); err == nil {
		c.present = true
		c.noteNewest(a, aptStampPath)
	}
	if c.newestPath == "" {
		c.newestPath = aptListsDir
	}
	return c
}

// dnfCache stats every cached repomd.xml for the age anchor and reads them
// for the updateinfo declaration. Ruling J-26 defines the security channel
// from the file; this looks at EVERY cached repomd rather than only the
// newest one, because updateinfo is published per repository — the security
// repository's index is very often not the most recently written file, and
// judging only the newest would report "no security channel" on a host that
// plainly has one, sending U-64 to NOT_APPLICABLE.
func dnfCache(a collect.Access) patchCache {
	var c patchCache
	matches, err := a.Glob(dnfRepomdGlob)
	if err != nil {
		e := collect.ErrorEnv("glob " + dnfRepomdGlob + ": " + err.Error())
		c.failed = &e
		return c
	}
	sort.Strings(matches)
	for _, m := range matches {
		c.present = true
		c.noteNewest(a, m)
		if c.security {
			continue
		}
		if data, _, err := a.ReadFile(m, readLimit); err == nil && strings.Contains(string(data), `type="updateinfo"`) {
			c.security, c.securityPath = true, m
		}
	}
	if c.newestPath == "" {
		c.newestPath = dnfCacheDir
	}
	return c
}

// noteNewest keeps the newest modification time seen so far. A path whose
// time is not known (a stat failure, or a file system that reports none)
// contributes nothing rather than a zero time that would read as 1970.
func (c *patchCache) noteNewest(a collect.Access, p string) {
	meta, err := a.Stat(p)
	if err != nil || meta.ModTime.IsZero() {
		return
	}
	if meta.ModTime.After(c.newest) {
		c.newest, c.newestPath = meta.ModTime, p
	}
}

// age is the metadata_age_s envelope. Ruling J-21: CollectedAt − ModTime,
// both supplied, never time.Now() — the same snapshot must render the same
// bytes on every run.
func (c patchCache) age(now time.Time) facts.Envelope {
	if c.failed != nil {
		return *c.failed
	}
	src := &facts.Source{Kind: "file", Path: c.newestPath}
	switch {
	case !c.present:
		return collect.Absent(noCacheReason)
	case c.newest.IsZero():
		return collect.Unsupported("the package metadata cache modification time is not known, so no age can be derived")
	default:
		age, ok := mtimeAge(now, c.newest)
		if !ok {
			return collect.Unsupported("no usable clock for the age of " + c.newestPath + "; the run header carries no collected_at, or the cache is newer than it")
		}
		return collect.OK(age, src)
	}
}

// securityAvailable is the security_metadata_available envelope.
func (c patchCache) securityAvailable() facts.Envelope {
	if c.failed != nil {
		return *c.failed
	}
	p := c.securityPath
	if p == "" {
		p = c.newestPath
	}
	return collect.OK(c.security, &facts.Source{Kind: "file", Path: p})
}

// securityCount applies Ruling J-25 and Ruling J-26 in that order, before it
// ever looks at what a command reported:
//
//	no cache at all      → ABSENT  (U-64 reads MANUAL)
//	cache, no channel    → UNSUPPORTED, never 0 (U-64 reads NOT_APPLICABLE)
//	channel, query failed→ UNSUPPORTED with the command's reason
//	otherwise            → the count
func (c patchCache) securityCount(count int, counted bool, reason string, src *facts.Source) facts.Envelope {
	switch {
	case c.failed != nil:
		return *c.failed
	case !c.present:
		return collect.Absent(noCacheReason)
	case !c.security:
		return collect.Unsupported("the package metadata cache carries no security channel, so a pending security count cannot be derived from it")
	case !counted:
		return collect.Unsupported(reason)
	default:
		return collect.OK(count, src)
	}
}

// --- apt ----------------------------------------------------------------

func runPatchApt(ctx context.Context, a collect.Access, b *collect.Builder, now time.Time) {
	cache := aptCache(a)
	b.Set("patch.metadata_age_s", cache.age(now))
	b.Set("patch.security_metadata_available", cache.securityAvailable())

	out := a.Run(ctx, aptSimulateCmd)
	src := out.Source(aptSimulateCmd)
	if cmdOK(out) {
		updates := parseAptSimulation(out.Stdout)
		b.Set("patch.pending_updates", withTruncation(collect.OK(updates, src), out.Truncated))
		b.Set("patch.pending_security_count", cache.securityCount(countAptSecurity(out.Stdout), true, "", src))
	} else {
		reason := patchCmdReason(out, aptSimulateCmd)
		b.Set("patch.pending_updates", collect.Unsupported(reason))
		b.Set("patch.pending_security_count", cache.securityCount(0, false, reason, src))
	}

	b.Set("patch.reboot_required", aptRebootRequired(a, b))
	b.SetSetting("patch.auto_update.enabled", facts.Setting{
		Runtime:   envp(collect.Unsupported(autoUpdateRuntimeReason)),
		Persisted: envp(aptAutoUpdate(a)),
	})
	b.Set("patch.held_packages", aptHeldPackages(ctx, a))
	b.Set("patch.days_since_last_install", dpkgDaysSinceLastInstall(a, now))
	b.Set("packages.installed", dpkgPackages(a))
}

// aptRebootRequired answers from the flag file the debian family drops when
// a package asks for a reboot. Ruling J-31 comes first: inside a container
// the kernel is the host's, not this namespace's, and a flag inherited
// through a bind mount would be a finding about someone else's machine.
func aptRebootRequired(a collect.Access, b *collect.Builder) facts.Envelope {
	if e, ok := containerReboot(b); ok {
		return e
	}
	for _, p := range []string{rebootRequiredPath, rebootRequiredPkgsPath} {
		meta, err := a.Stat(p)
		switch {
		case err == nil:
			return collect.OK(true, &facts.Source{Kind: "file", Path: p})
		case errors.Is(err, fs.ErrNotExist):
			continue
		default:
			e := collect.FromReadError(err, meta)
			e.Reason = p + ": " + e.Reason
			return e
		}
	}
	return collect.OK(false, &facts.Source{Kind: "file", Path: rebootRequiredPath})
}

// aptAutoUpdate is the persisted side of auto_update.enabled. apt reads
// apt.conf.d in lexical order and the last setting wins, so 10periodic is
// read before 20auto-upgrades. C3: a file that EXISTS but cannot be read is
// the answer for every value it could set — never the module's default.
func aptAutoUpdate(a collect.Access) facts.Envelope {
	enabled, from := false, ""
	for _, p := range []string{aptPeriodicConf, aptAutoUpgrades} {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			e := collect.FromReadError(err, meta)
			e.Reason = p + ": " + e.Reason
			return e
		}
		if v, ok := aptPeriodicUnattended(data); ok {
			enabled, from = v, p
		}
	}
	if from == "" {
		// Neither file names the option: apt's own default for a periodic
		// action it was never told to take is not to take it.
		return collect.OK(false, &facts.Source{Kind: "file", Path: aptAutoUpgrades})
	}
	return collect.OK(enabled, &facts.Source{Kind: "file", Path: from})
}

// aptPeriodicUnattended finds the last APT::Periodic::Unattended-Upgrade
// setting in one apt.conf fragment. apt treats any non-zero value as "on".
func aptPeriodicUnattended(data []byte) (bool, bool) {
	const key = "apt::periodic::unattended-upgrade"
	enabled, found := false, false
	for _, line := range splitLines(data) {
		l := stripAptComment(line)
		i := strings.Index(strings.ToLower(l), key)
		if i < 0 {
			continue
		}
		v, ok := firstQuoted(l[i+len(key):])
		if !ok {
			continue
		}
		enabled, found = v != "" && v != "0", true
	}
	return enabled, found
}

// stripAptComment cuts an apt.conf line at its first comment introducer.
// apt.conf accepts both the C++ "//" form and the shell "#" form.
func stripAptComment(line string) string {
	cut := len(line)
	if i := strings.Index(line, "//"); i >= 0 && i < cut {
		cut = i
	}
	if i := strings.IndexByte(line, '#'); i >= 0 && i < cut {
		cut = i
	}
	return line[:cut]
}

// firstQuoted returns the content of the first double-quoted run in s.
func firstQuoted(s string) (string, bool) {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return "", false
	}
	j := strings.IndexByte(s[i+1:], '"')
	if j < 0 {
		return "", false
	}
	return s[i+1 : i+1+j], true
}

func aptHeldPackages(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, aptMarkHoldCmd)
	if !cmdOK(out) {
		return collect.Unsupported("held packages unavailable: " + patchCmdReason(out, aptMarkHoldCmd))
	}
	names := []string{}
	for _, line := range splitLines(out.Stdout) {
		if f := strings.Fields(line); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	sort.Strings(names)
	held := make([]any, 0, len(names))
	for _, n := range names {
		held = append(held, n)
	}
	return withTruncation(collect.OK(held, out.Source(aptMarkHoldCmd)), out.Truncated)
}

// dpkgDaysSinceLastInstall reads the newest "status installed" line of the
// dpkg log. Ruling J-21 again: the age is measured against the run header's
// clock, never time.Now(). dpkg writes local time with no zone, so this is a
// whole-day figure by design — evidence that a host is being maintained, not
// a judged value.
func dpkgDaysSinceLastInstall(a collect.Access, now time.Time) facts.Envelope {
	data, meta, err := a.ReadFile(dpkgLogPath, patchReadLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.Absent(dpkgLogPath + " does not exist")
		}
		e := collect.FromReadError(err, meta)
		e.Reason = dpkgLogPath + ": " + e.Reason
		return e
	}
	newest, ok := newestDpkgInstall(data)
	if !ok {
		return collect.Absent("no package installation recorded in " + dpkgLogPath)
	}
	if now.IsZero() {
		return collect.Unsupported("the run header carries no collected_at, so no age can be derived")
	}
	d := now.Sub(newest)
	if d < 0 {
		// dpkg logs local time with no zone: a host east of UTC can record
		// an install that reads as being in the future. Clamp rather than
		// invent a negative age.
		d = 0
	}
	return collect.OKRead(int(d/(24*time.Hour)), &facts.Source{Kind: "file", Path: dpkgLogPath}, meta)
}

// newestDpkgInstall returns the timestamp of the newest "status installed"
// line. Every other dpkg action (unpack, half-configured, remove) is skipped.
func newestDpkgInstall(data []byte) (time.Time, bool) {
	var newest time.Time
	found := false
	for _, line := range splitLines(data) {
		f := strings.Fields(line)
		if len(f) < 5 || f[2] != "status" || f[3] != "installed" {
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05", f[0]+" "+f[1])
		if err != nil {
			continue
		}
		if !found || t.After(newest) {
			newest, found = t, true
		}
	}
	return newest, found
}

// dpkgPackages is the installed inventory on an apt host, read straight from
// the package database — never from a daemon (D14).
func dpkgPackages(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFile(dpkgStatusPath, patchReadLimit)
	if err != nil {
		e := collect.FromReadError(err, meta)
		e.Reason = dpkgStatusPath + ": " + e.Reason
		return e
	}
	return collect.OKRead(parseDpkgStatus(data), &facts.Source{Kind: "file", Path: dpkgStatusPath}, meta)
}

// parseDpkgStatus reads the RFC-822-style stanzas of /var/lib/dpkg/status.
// Only a package whose Status is "install ok installed" is installed: a
// package that was removed but not purged keeps a stanza with its
// configuration files and would otherwise be reported as present.
func parseDpkgStatus(data []byte) []any {
	recs := []any{}
	var name, version, arch, status string
	flush := func() {
		if name != "" && status == "install ok installed" {
			recs = append(recs, map[string]any{"name": name, "version": version, "arch": arch})
		}
		name, version, arch, status = "", "", "", ""
	}
	for _, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			continue // a folded continuation of the previous field
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Package":
			name = v
		case "Version":
			version = v
		case "Architecture":
			arch = v
		case "Status":
			status = v
		}
	}
	flush()
	sortPackageRecords(recs)
	return recs
}

// parseAptSimulation reads the `Inst` lines of `apt-get -s upgrade`. Every
// other line is skipped by construction: the unprivileged NOTE block, the
// "Reading package lists" progress and the `Conf` lines that repeat each
// package all go to stdout too, and a parser that looked for "a line
// mentioning a version" would report each upgrade twice.
func parseAptSimulation(data []byte) []any {
	recs := []any{}
	for _, line := range splitLines(data) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Inst ")
		if !ok {
			continue
		}
		if rec := parseAptInstLine(rest); rec != nil {
			recs = append(recs, rec)
		}
	}
	sortUpdateRecords(recs)
	return recs
}

// countAptSecurity counts the simulated upgrades whose origin names a
// security suite. It is derived from the same lines parseAptSimulation
// publishes, so the count and the evidence can never disagree.
func countAptSecurity(data []byte) int {
	n := 0
	for _, v := range parseAptSimulation(data) {
		if rec, ok := v.(map[string]any); ok {
			if origin, _ := rec["origin"].(string); isSecuritySuite(origin) {
				n++
			}
		}
	}
	return n
}

// parseAptInstLine parses one `Inst NAME [CURRENT] (CANDIDATE ORIGIN [ARCH])`
// line. A package the upgrade would newly install carries no [CURRENT] part,
// and its current version is recorded as empty rather than invented.
func parseAptInstLine(rest string) map[string]any {
	name, rest, _ := strings.Cut(strings.TrimSpace(rest), " ")
	if name == "" {
		return nil
	}
	rest = strings.TrimSpace(rest)
	current := ""
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end > 0 {
			current = rest[1:end]
			rest = strings.TrimSpace(rest[end+1:])
		}
	}
	candidate, origin := "", ""
	if strings.HasPrefix(rest, "(") {
		if end := strings.LastIndexByte(rest, ')'); end > 0 {
			inside := strings.Fields(rest[1:end])
			if len(inside) > 0 {
				candidate = inside[0]
				tail := inside[1:]
				// The architecture apt appends in brackets is not part of
				// the origin; every suite name before it is.
				if n := len(tail); n > 0 && strings.HasPrefix(tail[n-1], "[") && strings.HasSuffix(tail[n-1], "]") {
					tail = tail[:n-1]
				}
				origin = strings.Join(tail, " ")
			}
		}
	}
	return map[string]any{"name": name, "current": current, "candidate": candidate, "origin": origin}
}

// --- dnf ----------------------------------------------------------------

func runPatchDnf(ctx context.Context, a collect.Access, b *collect.Builder, now time.Time) {
	cache := dnfCache(a)
	b.Set("patch.metadata_age_s", cache.age(now))
	b.Set("patch.security_metadata_available", cache.securityAvailable())

	// `dnf --cacheonly check-update` exits 100 when updates are pending and 0
	// when none are: 100 is SUCCESS with something to say, never an error.
	out := a.Run(ctx, dnfCheckUpdateCmd)
	src := out.Source(dnfCheckUpdateCmd)
	switch {
	case out.Err != nil || out.TimedOut:
		b.Set("patch.pending_updates", collect.Unsupported(patchCmdReason(out, dnfCheckUpdateCmd)))
	case out.ExitCode == 100:
		b.Set("patch.pending_updates", withTruncation(collect.OK(parseDnfCheckUpdate(out.Stdout), src), out.Truncated))
	case out.ExitCode == 0:
		b.Set("patch.pending_updates", collect.OK([]any{}, src))
	default:
		b.Set("patch.pending_updates", collect.Unsupported(patchCmdReason(out, dnfCheckUpdateCmd)))
	}

	b.Set("patch.pending_security_count", dnfSecurityCount(ctx, a, cache))
	b.Set("patch.reboot_required", dnfRebootRequired(ctx, a, b))
	b.SetSetting("patch.auto_update.enabled", facts.Setting{
		Runtime:   envp(collect.Unsupported(autoUpdateRuntimeReason)),
		Persisted: envp(dnfAutoUpdate(a)),
	})
	// The versionlock plugin keeps its own list and has no cache-only query
	// in this command table; saying so is honest, inventing an empty list
	// would not be.
	b.Set("patch.held_packages", collect.Unsupported("the dnf versionlock plugin is not probed in this version"))
	b.Set("patch.days_since_last_install", collect.Unsupported("rpm installation times are not probed in this version"))
	b.Set("packages.installed", rpmPackages(ctx, a))
}

// dnfSecurityCount asks the cached updateinfo only when Ruling J-26 says
// there is one to ask; the precedence in patchCache.securityCount decides
// the rest, so the command never runs on a host whose answer could not be
// trusted anyway.
func dnfSecurityCount(ctx context.Context, a collect.Access, cache patchCache) facts.Envelope {
	if !cache.present || !cache.security || cache.failed != nil {
		return cache.securityCount(0, false, "", nil)
	}
	out := a.Run(ctx, dnfUpdateinfoCmd)
	if !cmdOK(out) {
		return cache.securityCount(0, false, patchCmdReason(out, dnfUpdateinfoCmd), nil)
	}
	e := cache.securityCount(countDnfAdvisories(out.Stdout), true, "", out.Source(dnfUpdateinfoCmd))
	return withTruncation(e, out.Truncated)
}

// countDnfAdvisories counts the advisory rows of `dnf updateinfo list
// security`. An advisory id always carries a digit (RHSA-2026:1234,
// RLSA-2026:1234, FEDORA-2026-abc123), which is what separates a row from
// dnf's own chatter ("Last metadata expiration check…", "Updating
// Subscription Management repositories.").
func countDnfAdvisories(data []byte) int {
	n := 0
	for _, line := range splitLines(data) {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.ContainsAny(f[0], "0123456789") {
			n++
		}
	}
	return n
}

// parseDnfCheckUpdate reads the `NAME.ARCH  VERSION  REPO` rows of
// `dnf --cacheonly check-update`. The "Obsoleting Packages" section that can
// follow lists a different relationship and is not a pending upgrade.
func parseDnfCheckUpdate(data []byte) []any {
	recs := []any{}
	for _, line := range splitLines(data) {
		if strings.HasPrefix(line, "Obsoleting Packages") {
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		dot := strings.LastIndexByte(f[0], '.')
		if dot <= 0 {
			continue
		}
		recs = append(recs, map[string]any{
			"name":      f[0][:dot],
			"current":   "",
			"candidate": f[1],
			"origin":    f[2],
		})
	}
	sortUpdateRecords(recs)
	return recs
}

// dnfRebootRequired asks needs-restarting, which is not installed by default
// on the rhel family: its absence is an environment limitation, never a
// finding. Ruling J-31: in a container the command is not run at all.
func dnfRebootRequired(ctx context.Context, a collect.Access, b *collect.Builder) facts.Envelope {
	if e, ok := containerReboot(b); ok {
		return e
	}
	out := a.Run(ctx, needsRestartingCmd)
	src := out.Source(needsRestartingCmd)
	switch {
	case out.Err != nil || out.TimedOut:
		return collect.Unsupported("reboot state unavailable: " + patchCmdReason(out, needsRestartingCmd))
	case out.ExitCode == 0:
		return withTruncation(collect.OK(false, src), out.Truncated)
	case out.ExitCode == 1:
		return withTruncation(collect.OK(true, src), out.Truncated)
	default:
		return collect.Unsupported("reboot state unavailable: " + patchCmdReason(out, needsRestartingCmd))
	}
}

// dnfAutoUpdate is the persisted side of auto_update.enabled on a dnf host:
// dnf-automatic only applies updates when [commands] apply_updates says so.
func dnfAutoUpdate(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFile(dnfAutomaticConf, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.OK(false, &facts.Source{Kind: "file", Path: dnfAutomaticConf})
		}
		e := collect.FromReadError(err, meta)
		e.Reason = dnfAutomaticConf + ": " + e.Reason
		return e
	}
	applies, found := dnfAutomaticApply(data)
	return collect.OKRead(found && applies, &facts.Source{Kind: "file", Path: dnfAutomaticConf}, meta)
}

// dnfAutomaticApply reads apply_updates out of the [commands] section of
// dnf-automatic's configuration; the same key under any other section means
// something else and is ignored.
func dnfAutomaticApply(data []byte) (bool, bool) {
	section := ""
	for _, line := range splitLines(data) {
		l := strings.TrimSpace(line)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]") {
			section = strings.ToLower(strings.Trim(l, "[]"))
			continue
		}
		if section != "commands" {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "apply_updates") {
			return isDnfTruthy(strings.TrimSpace(v)), true
		}
	}
	return false, false
}

func isDnfTruthy(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "1", "on":
		return true
	}
	return false
}

// rpmPackages is the installed inventory on a dnf host. It asks rpm, which
// reads the package database directly — never a daemon (D14).
func rpmPackages(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, rpmQaCmd)
	if !cmdOK(out) {
		return collect.Unsupported("installed package inventory unavailable: " + patchCmdReason(out, rpmQaCmd))
	}
	return withTruncation(collect.OK(parseRpmQa(out.Stdout), out.Source(rpmQaCmd)), out.Truncated)
}

// parseRpmQa reads the tab-separated rows rpmQaFormat asks for. rpm expands
// the \t itself, so the bytes arriving here carry real tabs even though the
// declared format carries the backslash escapes (Ruling J-23).
func parseRpmQa(data []byte) []any {
	recs := []any{}
	for _, line := range splitLines(data) {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 || f[0] == "" {
			continue
		}
		recs = append(recs, map[string]any{"name": f[0], "version": f[1], "arch": f[2]})
	}
	sortPackageRecords(recs)
	return recs
}

// --- shared -------------------------------------------------------------

// autoUpdateRuntimeReason is the runtime side of auto_update.enabled on
// every family. Both sides are always set (H-18); the runtime side would
// mean the state of the unattended-upgrades or dnf-automatic timer, which
// belongs to the services inventory rather than to this collector.
const autoUpdateRuntimeReason = "the unattended-upgrade timer state is not probed in this version"

// containerReboot applies Ruling J-31 before any probe: inside a container
// the reboot flag and needs-restarting both answer for the HOST kernel,
// which this namespace neither owns nor can restart. An empty Container is
// NOT a container — run.go leaves Env zero when the os collector could not
// fill it, and reading "" as "some container" would turn an unknown
// environment into a claim about it.
func containerReboot(b *collect.Builder) (facts.Envelope, bool) {
	kind := b.Header().Env.Container
	if kind == "" || kind == "none" {
		return facts.Envelope{}, false
	}
	return collect.Unsupported("running inside a " + kind + " container; the reboot state belongs to the host kernel, not to this namespace"), true
}

// patchCmdReason is the reason an `unsupported` patch fact carries when a
// command did not succeed (R220, the cronTimers shape). Ruling J-24: a
// Timeout expiry is checked FIRST and its reason names the timeout, so a
// slow host is never mistaken for a host with nothing to report — whatever
// half-written stderr the killed process left behind.
func patchCmdReason(out collect.Output, c collect.Command) string {
	if out.TimedOut {
		return commandLine(c) + " timed out after " + patchTimeout(c).String()
	}
	if s := firstLine(out.Stderr); s != "" {
		return s
	}
	if out.Err != nil {
		return commandLine(c) + ": " + out.Err.Error()
	}
	return commandLine(c) + " exited " + strconv.Itoa(out.ExitCode)
}

// patchTimeout is the deadline a command actually runs under: its own, or
// RunCommand's default when it declares none.
func patchTimeout(c collect.Command) time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

// commandLine renders a command the way --list-actions and the run header
// do, so a reason names exactly what a reviewer approved.
func commandLine(c collect.Command) string {
	return strings.TrimSpace(c.Path + " " + strings.Join(c.Args, " "))
}

// sortPackageRecords orders an inventory by (name, arch): the same host
// renders the same bytes whatever order the database or rpm listed it in.
func sortPackageRecords(recs []any) {
	sort.Slice(recs, func(i, j int) bool {
		ri, rj := recs[i].(map[string]any), recs[j].(map[string]any)
		ni, nj := ri["name"].(string), rj["name"].(string)
		if ni != nj {
			return ni < nj
		}
		return ri["arch"].(string) < rj["arch"].(string)
	})
}

// sortUpdateRecords orders pending updates by (name, candidate).
func sortUpdateRecords(recs []any) {
	sort.Slice(recs, func(i, j int) bool {
		ri, rj := recs[i].(map[string]any), recs[j].(map[string]any)
		ni, nj := ri["name"].(string), rj["name"].(string)
		if ni != nj {
			return ni < nj
		}
		return ri["candidate"].(string) < rj["candidate"].(string)
	})
}
