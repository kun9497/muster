//go:build linux

package collectors

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The pkgverify collector verifies every packaged file against the package
// database (spec I-5): `rpm -Va` or `dpkg --verify`, whichever the family is,
// under --deep as root only. Its output is noisy by construction — every
// documentation file a minimised image never wrote, every touched timestamp —
// so the rows pass a noise filter, and the filter, its inputs and what each
// rule removed are facts of their own (principle 4): a PASS whose filter
// cannot be read back is not a PASS anyone can check.
//
// The exit code is data (principle 2, J-3): rpm exits 1 to say "something
// differs" and dpkg with no arguments always exits 0, so the verdict is read
// from the rows and the code only tells "answered" from "failed".
const (
	dpkgInfoListGlob   = "/var/lib/dpkg/info/*.list"
	dpkgInfoDigestGlob = "/var/lib/dpkg/info/*.md5sums"
	dpkgCfgPath        = "/etc/dpkg/dpkg.cfg"
	dpkgCfgDGlob       = "/etc/dpkg/dpkg.cfg.d/*"

	// verifyMaxOutput is each command's capture cap. The lab's dpkg --verify
	// printed 1199 rows (about 50 KiB); the cap is a limit on muster's
	// memory, and a capture that reaches it makes complete false.
	verifyMaxOutput = 64 << 20

	// verifyRowCap bounds modified and modified_config each (J-16).
	verifyRowCap = 5000
)

// The two verify commands. Their Timeout is the --verify-timeout default; the
// run replaces it with the operator's value, which the guard allows because
// allowedCommand compares Path and Args only.
var (
	rpmVerifyCmd  = collect.Command{Path: "/usr/bin/rpm", Args: []string{"-Va"}, Timeout: 30 * time.Minute, MaxOutput: verifyMaxOutput}
	dpkgVerifyCmd = collect.Command{Path: "/usr/bin/dpkg", Args: []string{"--verify"}, Timeout: 30 * time.Minute, MaxOutput: verifyMaxOutput}
)

// dpkgCfgNameRE is the name rule of dpkg's loadcfgdir (valid_config_filename):
// a dpkg.cfg.d entry is read only when its whole name is letters, digits, `_`
// and `-`, so `excludes.dpkg-old` and `foo.conf` never apply.
var dpkgCfgNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

var pkgverifyCollector = collect.Collector{
	Name: "pkgverify",
	Declare: collect.Declaration{
		Reads: []string{
			dpkgStatusPath, rpmDBDir,
			dpkgInfoListGlob, dpkgInfoDigestGlob,
			dpkgCfgPath, dpkgCfgDGlob,
		},
		Commands: []collect.Command{rpmVerifyCmd, dpkgVerifyCmd},
		// J-7: documentation only. run.go never reads Needs; the collector
		// gates itself on euid() below.
		Needs: "root",
	},
	Run: runPkgverify,
}

// pkgverifyRootReason is the one reason a non-root run carries.
const pkgverifyRootReason = "package verification needs root: an unprivileged rpm -Va marks every file it cannot read as untestable"

func runPkgverify(ctx context.Context, a collect.Access, b *collect.Builder) error {
	vo, ok := b.Verify()
	if !ok {
		return nil // --deep not given, or --no-verify: packages.verify.* stays absent
	}
	if euid() != 0 {
		b.Set("packages.verify.complete", collect.Denied(pkgverifyRootReason))
		return nil
	}

	var tool string
	var cmd collect.Command
	switch {
	case exists(a, dpkgStatusPath):
		tool, cmd = "dpkg", dpkgVerifyCmd
	case pathPresent(a, rpmDBDir):
		tool, cmd = "rpm", rpmVerifyCmd
	default:
		writeVerifyUnknown(b)
		return nil
	}
	if vo.Timeout > 0 {
		cmd.Timeout = vo.Timeout
	}

	out := a.Run(ctx, cmd)
	src := out.Source(cmd)
	// A killed command's capture ends wherever the kill found it, exactly as
	// a capped one does, so both drop their last line.
	cut := out.Truncated || out.TimedOut
	parsed := parseVerifyOutput(out.Stdout, cut)

	var filter verifyFilter
	excludes, excludeErrors := []any{}, []any{} // R50: never nil, on rpm too
	withoutDigests, digestProbe := 0, ""
	if tool == "dpkg" {
		filter, excludes, excludeErrors = dpkgPathFilters(a)
		withoutDigests, digestProbe = dpkgPackagesWithoutDigests(a)
	}
	modified, config, counts := filterVerifyRows(parsed.rows, filter)

	b.Set("packages.verify.complete", verifyComplete(out, cmd, src, len(parsed.rows)))
	b.Set("packages.verify.tool", collect.OK(tool, src))
	b.Set("packages.verify.modified", verifyListEnv(modified, src, cut))
	b.Set("packages.verify.modified_config", verifyListEnv(config, src, cut))
	b.Set("packages.verify.filter", collect.OK(verifyFilterValue(), src))
	b.Set("packages.verify.filtered_counts", collect.OK(verifyCountsValue(counts), src))
	b.Set("packages.verify.stats", collect.OK(map[string]any{
		"lines":                          parsed.lines,
		"exit_code":                      out.ExitCode,
		"duration_ms":                    int(out.Duration / time.Millisecond),
		"truncated":                      out.Truncated,
		"stderr_head":                    headLines(out.Stderr),
		"unparsed_head":                  stringsValue(parsed.unparsed),
		"packages_without_digests":       withoutDigests,
		"packages_without_digests_error": digestProbe,
		"dpkg_path_excludes":             excludes,
		"dpkg_path_excludes_error":       excludeErrors,
	}, src))
	return nil
}

// verifyComplete applies J-3 in its order: a kill first, then a command that
// never started, then the exit code read together with the rows.
func verifyComplete(out collect.Output, cmd collect.Command, src *facts.Source, rows int) facts.Envelope {
	line := commandLine(cmd)
	var e facts.Envelope
	switch {
	case out.TimedOut:
		e = collect.TimeoutEnv(line + " timed out after " + patchTimeout(cmd).String())
	case out.Err != nil:
		e = collect.ErrorEnv(line + ": " + out.Err.Error())
	case out.ExitCode == 0 || out.ExitCode == 1 && rows > 0:
		if out.Truncated {
			e = collect.OK(false, src)
			e.Reason = line + " output reached its " + strconv.Itoa(cmd.MaxOutput>>20) + " MiB cap; the rows past it were not read"
		} else {
			e = collect.OK(true, src)
		}
	case out.ExitCode == 1:
		// rpm on a locked or corrupt database: its complaint on stderr, exit
		// 1 and no row. A host that cannot read its own package database
		// must never read as unmodified.
		reason := line + " exited 1 with no verification row"
		if s := firstLine(out.Stderr); s != "" {
			reason += ": " + s
		}
		e = collect.ErrorEnv(reason)
	default:
		reason := line + " exited " + strconv.Itoa(out.ExitCode)
		if s := firstLine(out.Stderr); s != "" {
			reason += ": " + s
		}
		e = collect.ErrorEnv(reason)
	}
	e.Source = src
	return withTruncation(e, out.Truncated)
}

// verifyListEnv is one of the two row lists: sorted by path, capped at
// verifyRowCap, and truncated when the cap cut it or the capture was cut
// (the silence past either means nothing).
func verifyListEnv(rows []verifyRow, src *facts.Source, cut bool) facts.Envelope {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].path < rows[j].path })
	values := make([]any, 0, len(rows))
	for _, r := range rows {
		values = append(values, map[string]any{
			"path":       r.path,
			"attributes": stringsValue(r.attrs),
			"untested":   r.untested,
			"file_type":  r.fileType(),
			"note":       r.note,
		})
	}
	capped, full := capRows(values, verifyRowCap)
	return withTruncation(collect.OK(capped, src), full || cut)
}

// writeVerifyUnknown is the shape for a host with neither package database:
// complete unsupported, and every other key written empty so none reads as
// missing (a registered key the snapshot lacks is ERROR(missing_fact)).
func writeVerifyUnknown(b *collect.Builder) {
	derived := &facts.Source{Kind: "derived"}
	b.Set("packages.verify.complete", collect.Unsupported("no supported package manager"))
	b.Set("packages.verify.tool", collect.OK("", derived))
	b.Set("packages.verify.modified", collect.OK([]any{}, derived))
	b.Set("packages.verify.modified_config", collect.OK([]any{}, derived))
	b.Set("packages.verify.filter", collect.OK(verifyFilterValue(), derived))
	b.Set("packages.verify.filtered_counts", collect.OK(verifyCountsValue(nil), derived))
	b.Set("packages.verify.stats", collect.OK(map[string]any{
		"lines":                          0,
		"exit_code":                      -1,
		"duration_ms":                    0,
		"truncated":                      false,
		"stderr_head":                    []any{},
		"unparsed_head":                  []any{},
		"packages_without_digests":       0,
		"packages_without_digests_error": "",
		"dpkg_path_excludes":             []any{},
		"dpkg_path_excludes_error":       []any{},
	}, derived))
}

func verifyFilterValue() []any { return stringsValue(verifyFilterNames) }

func verifyCountsValue(counts map[string]int) map[string]any {
	out := make(map[string]any, len(verifyFilterNames))
	for _, n := range verifyFilterNames {
		out[n] = counts[n]
	}
	return out
}

// dpkgPathFilters reads dpkg's path filters in the order dpkg itself loads
// them (lib/dpkg/options.c dpkg_options_load): the dpkg.cfg.d entries whose
// names pass loadcfgdir's rule, in sorted order, then dpkg.cfg. It returns
// the compiled filter, the directives stats.dpkg_path_excludes records, and
// the read failures stats.dpkg_path_excludes_error records. When any file
// that exists could not be read the directives are empty and the filter
// holds none: a partial set of globs is not dpkg's set, so the
// dpkg_excluded rule is then not applied at all. A missing file is not a
// failure, and a link to /dev/null is a mask (K-21).
func dpkgPathFilters(a collect.Access) (verifyFilter, []any, []any) {
	var files []string
	var failures []string
	matches, err := a.Glob(dpkgCfgDGlob)
	if err != nil {
		failures = append(failures, globReadError(dpkgCfgDGlob, err, collect.ErrorEnv(dpkgCfgDGlob+": "+err.Error())).Reason)
	}
	sort.Strings(matches)
	for _, m := range matches {
		if dpkgCfgNameRE.MatchString(path.Base(m)) {
			files = append(files, m)
		}
	}
	files = append(files, dpkgCfgPath)

	var filters []dpkgPathFilter
	for _, p := range files {
		data, meta, err := a.ReadFile(p, readLimit)
		if err != nil {
			if chainReadFailed(a, p, err) {
				failures = append(failures, pathReason(p, collect.FromReadError(err, meta)).Reason)
			}
			continue
		}
		// A read that came back cut at readLimit, or refused as binary (no
		// data and no error), leaves this file's filters unknown: that is a
		// failure like any other, not a file that sets nothing.
		switch {
		case meta.Binary:
			failures = append(failures, p+": binary")
			continue
		case meta.Truncated:
			failures = append(failures, p+": truncated")
			continue
		}
		filters = append(filters, parseDpkgPathExcludes(data)...)
	}
	if len(failures) > 0 {
		return verifyFilter{}, []any{}, stringsValue(failures)
	}

	var f verifyFilter
	recorded := make([]any, 0, len(filters))
	for _, pf := range filters {
		recorded = append(recorded, pf.directive())
		re, err := dpkgGlobRegexp(pf.glob)
		if err != nil {
			// fnmatch answers a malformed pattern with no match; so does
			// the filter, and the directive is still on record.
			continue
		}
		f.pathFilters = append(f.pathFilters, compiledPathFilter{include: pf.include, re: re})
	}
	return f, recorded, []any{}
}

// dpkgPackagesWithoutDigests counts the installed packages dpkg --verify
// silently cannot check: a .list with no .md5sums beside it. When either
// listing fails the count is 0 and the second value says why.
func dpkgPackagesWithoutDigests(a collect.Access) (int, string) {
	lists, err := a.Glob(dpkgInfoListGlob)
	if err != nil {
		return 0, globReadError(dpkgInfoListGlob, err, collect.ErrorEnv(dpkgInfoListGlob+": "+err.Error())).Reason
	}
	digests, err := a.Glob(dpkgInfoDigestGlob)
	if err != nil {
		return 0, globReadError(dpkgInfoDigestGlob, err, collect.ErrorEnv(dpkgInfoDigestGlob+": "+err.Error())).Reason
	}
	have := make(map[string]bool, len(digests))
	for _, d := range digests {
		have[strings.TrimSuffix(path.Base(d), ".md5sums")] = true
	}
	n := 0
	for _, l := range lists {
		if !have[strings.TrimSuffix(path.Base(l), ".list")] {
			n++
		}
	}
	return n, ""
}

// headLines is the first verifyHeadLines non-empty lines of a stream, each
// capped as evidence is (R64).
func headLines(data []byte) []any {
	out := []any{}
	for _, line := range splitLines(data) {
		if len(out) == verifyHeadLines {
			break
		}
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, sourceRaw(s))
		}
	}
	return out
}

// stringsValue boxes a string list for a record field, never nil.
func stringsValue(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}
