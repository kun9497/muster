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

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	etcCrontab    = "/etc/crontab"
	etcAnacrontab = "/etc/anacrontab"
)

// cronConfigGlobs are the fixed drop-in and access globs; cronSpoolGlobs are
// the per-user spools (Rocky /var/spool/cron, Ubuntu /var/spool/cron/crontabs).
var (
	// cronDropIns are the drop-in directories, each with the scope its files
	// carry. /etc/cron.d holds crontab-FORMAT files, tagged "system"; the
	// /etc/cron.{hourly,daily,weekly,monthly} directories hold executable
	// run-parts SCRIPTS (0755), tagged "periodic" so the 0640 mode-subset check
	// excludes them (an executable is never a bit-subset of 0640, and chmod
	// 0640 would make run-parts skip them) — they are judged on ownership and
	// writability instead.
	cronDropIns = []struct{ glob, scope string }{
		{"/etc/cron.d/*", "system"},
		{"/etc/cron.hourly/*", "periodic"},
		{"/etc/cron.daily/*", "periodic"},
		{"/etc/cron.weekly/*", "periodic"},
		{"/etc/cron.monthly/*", "periodic"},
	}
	cronAccessFiles = []string{"/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"}
	// at-spool: /var/spool/cron/atjobs on the Debian family, /var/spool/at on RHEL.
	cronSpoolGlobs = []string{"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/atjobs/*", "/var/spool/at/*"}
	cronDirs       = []string{
		"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
		"/etc/cron.monthly", "/var/spool/cron", "/var/spool/cron/crontabs", "/var/spool/cron/atjobs", "/var/spool/at",
	}
	cronTimersCmd = collect.Command{Path: systemctlPath, Args: []string{"list-unit-files", "--type=timer", "--no-legend", "--no-pager"}}
)

var cronCollector = collect.Collector{
	Name: "cron",
	Declare: collect.Declaration{
		Reads:    cronReads(),
		Commands: []collect.Command{cronTimersCmd},
		Needs:    "root",
	},
	Run: runCron,
}

func cronReads() []string {
	reads := []string{etcCrontab, etcAnacrontab, groupPath}
	reads = append(reads, cronAccessFiles...)
	for _, d := range cronDropIns {
		reads = append(reads, d.glob)
	}
	reads = append(reads, cronSpoolGlobs...)
	reads = append(reads, cronDirs...)
	return reads
}

func runCron(ctx context.Context, a collect.Access, b *collect.Builder) error {
	groups, _, _ := groupNames(a)
	files := []any{}
	// Fixed system config files.
	for _, p := range []string{etcCrontab, etcAnacrontab} {
		if row, ok := cronRow(a, p, "system", "", groups); ok {
			files = append(files, row)
		}
	}
	for _, p := range cronAccessFiles {
		if row, ok := cronRow(a, p, "access", "", groups); ok {
			files = append(files, row)
		}
	}
	// Drop-in globs. Each drop-in directory carries its own scope: /etc/cron.d
	// is crontab-format ("system"); /etc/cron.{hourly,daily,weekly,monthly} are
	// executable run-parts scripts ("periodic"), excluded from the mode check.
	for _, d := range cronDropIns {
		matches, err := a.Glob(d.glob)
		if err != nil {
			b.Set("cron.files", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.dirs", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.timers", cronTimers(ctx, a))
			return nil
		}
		sort.Strings(matches)
		for _, m := range matches {
			if row, ok := cronRow(a, m, d.scope, "", groups); ok {
				files = append(files, row)
			}
		}
	}
	// Per-user spools: the file's basename is the user.
	for _, g := range cronSpoolGlobs {
		matches, err := a.Glob(g)
		if err != nil {
			b.Set("cron.files", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.dirs", collect.FromReadError(err, collect.ReadMeta{}))
			b.Set("cron.timers", cronTimers(ctx, a))
			return nil
		}
		sort.Strings(matches)
		for _, m := range matches {
			if row, ok := cronRow(a, m, "user", path.Base(m), groups); ok {
				files = append(files, row)
			}
		}
	}
	b.Set("cron.files", collect.OK(files, &facts.Source{Kind: "file", Path: "/etc/crontab"}))
	b.Set("cron.dirs", cronDirRows(a, groups))
	b.Set("cron.timers", cronTimers(ctx, a))
	return nil
}

// cronRow stats one cron/at file. ok is false only when the path does not
// exist (ENOENT) — a stat that failed for any other reason still yields a row
// carrying that failure via mode -1 and owner_ok false, so a denied file is a
// finding, not a silent skip. owner_ok is root-owned, or (for a user spool)
// owned by the user the spool names.
func cronRow(a collect.Access, p, scope, user string, groups map[int]string) (map[string]any, bool) {
	meta, err := a.Stat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		if errors.Is(err, collect.ErrSymlink) {
			// A symlinked cron path is not itself a finding (its target is
			// judged where it lives): flag is_symlink and carry no reason, so
			// the reason-guard leaves it alone and it is not judged an anomaly.
			return map[string]any{
				"path": p, "scope": scope, "user": user, "mode": -1, "uid": -1, "gid": -1,
				"group": "", "owner_ok": true, "group_writable": false, "other_writable": false,
				"is_symlink": true,
			}, true
		}
		return map[string]any{
			"path": p, "scope": scope, "user": user, "mode": -1, "uid": -1, "gid": -1,
			"group": "", "owner_ok": false, "group_writable": false, "other_writable": false,
			"reason": readReason(p, err),
		}, true
	}
	if meta.Kind != "regular" {
		// A directory matched by a spool glob (e.g. /var/spool/cron/crontabs
		// caught by /var/spool/cron/*) is not a cron file; cron.dirs covers it.
		return nil, false
	}
	ownerOK := int(meta.UID) == 0
	if scope == "user" && user != "" {
		// A per-user spool file is legitimately owned by root or by any real
		// (non-system) user, whose uid is >= 1000.
		ownerOK = int(meta.UID) == 0 || int(meta.UID) >= 1000
	}
	return map[string]any{
		"path": p, "scope": scope, "user": user,
		"mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
		// group is evidence only — no control judges a cron row's group name, so
		// a truncated/denied /etc/group is not propagated here (unlike U-67's log
		// rows, which do judge group and carry the read error).
		"group":          groups[int(meta.GID)],
		"owner_ok":       ownerOK,
		"group_writable": meta.Mode&0o020 != 0,
		"other_writable": meta.Mode&0o002 != 0,
	}, true
}

func cronDirRows(a collect.Access, groups map[int]string) facts.Envelope {
	rows := []any{}
	for _, d := range cronDirs {
		meta, err := a.Stat(d)
		if err != nil {
			// A dir that is not there is not a finding. A denied dir is NOT
			// surfaced anywhere: filepath.Glob (hostAccess.Glob) swallows a
			// directory-read error and returns an empty match with a nil error,
			// so neither the glob above nor this stat reports it. Fixing that
			// honestly needs a guarded ReadDir, carried forward per R204.
			continue
		}
		rows = append(rows, map[string]any{
			"path": d, "mode": int(meta.Mode), "uid": int(meta.UID), "gid": int(meta.GID),
			// group is evidence only — no control judges a cron dir's group name.
			"group":          groups[int(meta.GID)],
			"group_writable": meta.Mode&0o020 != 0, "other_writable": meta.Mode&0o002 != 0,
		})
	}
	return collect.OK(rows, &facts.Source{Kind: "file", Path: "/etc/cron.d"})
}

// cronTimers is a best-effort systemd timer inventory. A systemctl that could
// not run is an ENVIRONMENT LIMITATION, not a collection error: a container
// booted without PID-1 systemd has no timer inventory to read, and reporting
// that as an error would make the whole run partial. So a failed command
// degrades to unsupported (R220, mirroring the sshd R88 honest-degradation) —
// unsupported ranks as ok in Builder.Worst (R71), so it keeps the run
// complete, while still being distinct from a clean empty list.
func cronTimers(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, cronTimersCmd)
	src := out.Source(cronTimersCmd)
	if out.Err != nil || out.TimedOut || out.ExitCode != 0 {
		// needsRoot is irrelevant here: `systemctl list-unit-files` reads the
		// unit-file inventory as any user, so a failure is never a root-only
		// refusal — despite the collector's Needs: root (which only annotates,
		// and does not gate, the run). Whatever the cause, an inventory this
		// environment cannot produce is unsupported, not an error.
		reason := firstLine(out.Stderr)
		if reason == "" {
			if out.Err != nil {
				reason = out.Err.Error()
			} else {
				reason = "systemctl list-unit-files --type=timer exited " + strconv.Itoa(out.ExitCode)
			}
		}
		return collect.Unsupported("systemd timer inventory unavailable: " + reason)
	}
	rows := []any{}
	for _, line := range splitLines(out.Stdout) {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasSuffix(f[0], ".timer") {
			rows = append(rows, map[string]any{"name": f[0], "state": f[1]})
		}
	}
	return withTruncation(collect.OK(rows, src), out.Truncated)
}
