//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const timedatectlPath = "/usr/bin/timedatectl"

// The two timedatectl invocations are SEPARATE ORACLES (Ruling I-16), never
// one command asked twice:
//
//   - `show -p NTP -p NTPSynchronized` answers time_sync.synchronized and runs
//     on every branch. The repeated-flag form is the safe one: unlike
//     systemctl, timedatectl does not split a comma-separated property list.
//     NTP= is asked for in the same round trip as evidence — nothing parses it
//     — so the declared command a change-control reviewer approves is the one
//     a later stage will keep using.
//   - `show-timesync --all` reads org.freedesktop.timesync1, which only
//     systemd-timesyncd provides. It is DECLARED always but RUN ONLY on the
//     timesyncd branch: on a chrony or ntpd host it exits non-zero, and
//     running it there would put an expected failure in the run header.
var (
	timedatectlShow         = collect.Command{Path: timedatectlPath, Args: []string{"show", "-p", "NTP", "-p", "NTPSynchronized"}}
	timedatectlShowTimesync = collect.Command{Path: timedatectlPath, Args: []string{"show-timesync", "--all"}}
)

// The provider configurations. Ruling I-17: chrony's sources are not only the
// server/pool/peer lines of the main file — a reference clock is a source too,
// and sourcedir/confdir directives name whole directories of them, so the
// stock locations of those (including the DHCP-supplied
// /run/chrony-dhcp/*.sources of Ubuntu 22.04+ and Rocky 9) are declared here.
const (
	timesyncdConf     = "/etc/systemd/timesyncd.conf"
	chronyConfDGlob   = "/etc/chrony/conf.d/*.conf"
	chronySourcesGlob = "/etc/chrony/sources.d/*.sources"
	chronyDHCPGlob    = "/run/chrony-dhcp/*.sources"
)

var (
	chronyMains = []string{"/etc/chrony.conf", "/etc/chrony/chrony.conf"}
	ntpMains    = []string{"/etc/ntp.conf", "/etc/ntpsec/ntp.conf"}
	// Descending precedence, the order mergeDropins wants (Ruling I-23).
	timesyncdDropinDirs = []string{
		"/etc/systemd/timesyncd.conf.d",
		"/run/systemd/timesyncd.conf.d",
		"/usr/local/lib/systemd/timesyncd.conf.d",
		"/usr/lib/systemd/timesyncd.conf.d",
	}
)

func timesyncReads() []string {
	reads := append([]string{}, chronyMains...)
	reads = append(reads, chronyConfDGlob, chronySourcesGlob, chronyDHCPGlob, timesyncdConf)
	for _, d := range timesyncdDropinDirs {
		reads = append(reads, path.Join(d, "*.conf"))
	}
	return append(reads, ntpMains...)
}

var timesyncCollector = collect.Collector{
	Name: "timesync",
	Declare: collect.Declaration{
		Reads:    timesyncReads(),
		Commands: []collect.Command{timedatectlShowTimesync, timedatectlShow},
		Needs:    "none",
	},
	Run: runTimesync,
}

func runTimesync(ctx context.Context, a collect.Access, b *collect.Builder) error {
	b.Set("time_sync.synchronized", timesyncSynchronized(ctx, a))

	s := &timesyncScan{a: a}
	s.run(ctx)
	if s.readErr != nil {
		// C3: a configuration file that exists but cannot be read is the
		// answer for every value it could set — including which provider is
		// configured — never the module's default.
		b.Set("time_sync.provider", *s.readErr)
		b.Set("time_sync.servers", *s.readErr)
		b.Set("time_sync.server_count", *s.readErr)
		return nil
	}
	// R147: a fresh Source pointer per envelope, never one shared.
	src := func() *facts.Source { return &facts.Source{Kind: "derived", Inputs: slices.Clone(s.inputs)} }
	b.Set("time_sync.provider", withTruncation(collect.OK(s.provider, src()), s.truncated))
	if s.absent != "" {
		// The list cannot be known from what this host would let us see. It is
		// absent with the reason, so the control's absent_means: manual turns
		// it into MANUAL rather than a confidently wrong PASS or FAIL.
		b.Set("time_sync.servers", collect.Absent(s.absent))
		b.Set("time_sync.server_count", collect.Absent(s.absent))
		return nil
	}
	// Ruling I-18: with no provider configuration at all the judged leaf is
	// ok:0 and the list is ok:[] — never unset, which would resolve to
	// ERROR(missing_fact) instead of the intended "no active provider" FAIL.
	list := make([]any, 0, len(s.servers))
	for _, name := range s.servers {
		list = append(list, name)
	}
	b.Set("time_sync.servers", withTruncation(collect.OK(list, src()), s.truncated))
	b.Set("time_sync.server_count", withTruncation(collect.OK(len(s.servers), src()), s.truncated))
	return nil
}

// timesyncSynchronized reads NTPSynchronized from `timedatectl show`.
//
// Ruling I-3/R220: timedatectl needs NO privilege — it asks systemd-timedated
// over the system bus, which answers any user — so a failure here is ALWAYS an
// environment limitation (no systemd, no bus, no timedatectl binary), never a
// refusal that being root would lift. This is deliberately NOT the firewall
// collector's euid split, which files a failed ruleset read as denied for a
// non-root run: there is no privilege to name here, so the honest status is
// unsupported. unsupported ranks as ok in Builder.Worst (R71), which is what
// keeps a systemd-less container's run complete.
func timesyncSynchronized(ctx context.Context, a collect.Access) facts.Envelope {
	out := a.Run(ctx, timedatectlShow)
	if out.Err != nil || out.TimedOut || out.ExitCode != 0 {
		return collect.Unsupported("timedatectl unavailable: " + timedatectlReason(out))
	}
	kv := map[string]string{}
	parseDropin(out.Stdout, kv)
	v, ok := kv["NTPSynchronized"]
	if !ok {
		// The command ran but this systemd does not report the property.
		return collect.Unsupported("timedatectl did not report NTPSynchronized")
	}
	return withTruncation(collect.OK(v == "yes", out.Source(timedatectlShow)), out.Truncated)
}

// timedatectlReason is why a timedatectl invocation produced nothing usable.
func timedatectlReason(out collect.Output) string {
	if r := firstLine(out.Stderr); r != "" {
		return r
	}
	switch {
	case out.TimedOut:
		return "timed out"
	case out.Err != nil:
		return out.Err.Error()
	default:
		return "exited " + strconv.Itoa(out.ExitCode)
	}
}

// timesyncScan is one pass over the provider configuration on disk.
type timesyncScan struct {
	a collect.Access

	inputs    []facts.Source
	readErr   *facts.Envelope // the first file that exists but could not be read
	truncated bool

	provider string
	servers  []string
	absent   string // when set, servers/server_count are absent with this reason
}

// run picks the provider and collects its sources. The order is the order a
// host with two of them installed would be judged in: an explicit chrony or
// ntpd configuration outranks the timesyncd file every systemd host ships.
// IR-5: ntpd is asked BEFORE timesyncd, not after, because dpkg keeps
// /etc/systemd/timesyncd.conf as a conffile once the timesyncd package is
// removed — an ntp/ntpsec host carrying that leftover would otherwise be
// judged on the timesyncd branch, where the timesyncd-only oracle fails and
// the server list goes MANUAL.
// Which daemon is RUNNING is services.ntp.* — this is the persisted view.
func (s *timesyncScan) run(ctx context.Context) {
	switch {
	case s.chrony():
		s.provider = "chrony"
	case s.ntpd():
		s.provider = "ntpd"
	case s.timesyncd(ctx):
		s.provider = "timesyncd"
	default:
		s.provider = "none"
	}
	slices.Sort(s.servers)
	s.servers = slices.Compact(s.servers)
}

// fail records the first read error of a file that exists (R148).
func (s *timesyncScan) fail(p string, err error) {
	if s.readErr == nil {
		e := readErrorEnv(p, err)
		s.readErr = &e
	}
}

// read returns a file's contents and whether the path exists at all: a file
// that is there but unreadable answers (nil, true) and records the failure.
func (s *timesyncScan) read(p string) ([]byte, bool) {
	data, meta, err := s.a.ReadFile(p, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		s.fail(p, err)
		return nil, true
	}
	s.truncated = s.truncated || meta.Truncated
	s.inputs = append(s.inputs, facts.Source{Kind: "file", Path: p})
	return data, true
}

func (s *timesyncScan) glob(pattern string) []string {
	matches, err := s.a.Glob(pattern)
	if err != nil {
		s.fail(pattern, err)
		return nil
	}
	slices.Sort(matches)
	return matches
}

// chronyDir is a directory or file of extra sources a chrony configuration
// named: sourcedir, confdir or include (IR-1).
type chronyDir struct {
	directive string // sourcedir | confdir | include
	dir       string
	glob      string
	depth     int // how many directives away from a main file this one is
}

// maxTimesyncIncludeDepth caps how deep a chain of include/sourcedir/confdir
// directives is followed. The seen-set already makes a cycle terminate; the
// cap bounds a legal but absurdly deep chain, and reaching it UNDER-claims —
// the list goes absent — rather than publishing a list that may be short.
const maxTimesyncIncludeDepth = 8

// timesyncInclude is one file an ntp configuration named with includefile.
type timesyncInclude struct {
	path  string
	depth int
}

// chrony reads every chrony configuration file this host has and returns
// whether any existed at all. Ruling I-17: sourcedir/confdir directives are
// followed, breadth-first, so DHCP-supplied and packaged fragments count as
// sources too.
func (s *timesyncScan) chrony() bool {
	found := false
	var queue []chronyDir
	take := func(data []byte, depth int) {
		names, dirs := parseChronySources(data)
		s.servers = append(s.servers, names...)
		for _, d := range dirs {
			d.depth = depth
			queue = append(queue, d)
		}
	}
	for _, p := range chronyMains {
		data, exists := s.read(p)
		if !exists {
			continue
		}
		found = true
		take(data, 1)
	}
	seen := map[string]bool{chronyConfDGlob: true}
	for _, m := range s.glob(chronyConfDGlob) {
		found = true
		if data, _ := s.read(m); data != nil {
			take(data, 1)
		}
	}
	if !found {
		return false
	}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.glob] {
			continue
		}
		seen[d.glob] = true
		if d.depth > maxTimesyncIncludeDepth {
			s.absent = "effective NTP server list unknown: chrony " + d.directive + " " + d.dir +
				" nests deeper than " + strconv.Itoa(maxTimesyncIncludeDepth) + " directives"
			continue
		}
		// Ruling I-10: a directory outside the declaration is RECORDED, never
		// touched — the sshd Include/Banner precedent (R55/R168). Reading it
		// would be a guard violation, which makes the collector error and the
		// whole run incomplete; guessing without it would be an over-claim, so
		// the list goes absent and a human checks that path.
		if !declared(s.a, d.glob) {
			s.absent = "effective NTP server list unknown: chrony " + d.directive + " " + d.dir +
				" is outside the collector's declaration"
			continue
		}
		for _, m := range s.glob(d.glob) {
			if data, _ := s.read(m); data != nil {
				take(data, d.depth+1)
			}
		}
	}
	return true
}

// timesyncd merges the timesyncd.conf drop-in chain and, only here, asks
// timedatectl for the effective list.
func (s *timesyncScan) timesyncd(ctx context.Context) bool {
	values, inputs, err := mergeDropins(s.a, timesyncdConf, timesyncdDropinDirs, "*.conf")
	if err != nil {
		// A file in the chain exists and could not be read: the chain is this
		// host's, so the provider is timesyncd, and C3 answers the rest.
		if s.readErr == nil {
			e := dropinEnvelope(err)
			s.readErr = &e
		}
		return true
	}
	if len(inputs) == 0 {
		return false // no timesyncd configuration on this host
	}
	s.inputs = append(s.inputs, inputs...)
	for _, k := range []string{"NTP", "FallbackNTP"} {
		s.servers = append(s.servers, strings.Fields(values[k])...)
	}
	out := s.a.Run(ctx, timedatectlShowTimesync)
	if out.Err != nil || out.TimedOut || out.ExitCode != 0 {
		// Ruling I-16: only THIS command's failure, and only on this branch,
		// makes the list absent. The shipped timesyncd.conf is entirely
		// commented out, so the files alone cannot know the compiled-in
		// fallback or what networkd handed the daemon — "no servers" would be
		// a fabricated FAIL.
		s.absent = "effective NTP server list unknown: timedatectl unavailable; see " + timesyncdConf
		return true
	}
	s.truncated = s.truncated || out.Truncated
	s.inputs = append(s.inputs, *out.Source(timedatectlShowTimesync))
	kv := map[string]string{}
	parseDropin(out.Stdout, kv)
	// Ruling I-24: the configured list, the fallback list, and the per-link
	// and runtime lists networkd/DHCP supply.
	for _, k := range []string{"ServerName", "SystemNTPServers", "FallbackNTPServers", "LinkNTPServers", "RuntimeNTPServers"} {
		s.servers = append(s.servers, strings.Fields(kv[k])...)
	}
	return true
}

// ntpd reads ntp.conf (and ntpsec's copy) plus the files they pull in with
// includefile, under the same rule as chrony's include (IR-1): a path outside
// the declaration is RECORDED, never read.
func (s *timesyncScan) ntpd() bool {
	found := false
	var queue []timesyncInclude
	for _, p := range ntpMains {
		data, exists := s.read(p)
		if !exists {
			continue
		}
		found = true
		queue = append(queue, s.ntpFile(data, 1)...)
	}
	if !found {
		return false
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		inc := queue[0]
		queue = queue[1:]
		if seen[inc.path] {
			continue
		}
		seen[inc.path] = true
		if inc.depth > maxTimesyncIncludeDepth {
			s.absent = "effective NTP server list unknown: ntp includefile " + inc.path +
				" nests deeper than " + strconv.Itoa(maxTimesyncIncludeDepth) + " directives"
			continue
		}
		// Ruling I-10, as on the chrony branch: reading a file the collector
		// never declared would be a guard violation, and guessing without it
		// would be an over-claim, so the list goes absent and a human checks
		// that path.
		if !declared(s.a, inc.path) {
			s.absent = "effective NTP server list unknown: ntp includefile " + inc.path +
				" is outside the collector's declaration"
			continue
		}
		if data, _ := s.read(inc.path); data != nil {
			queue = append(queue, s.ntpFile(data, inc.depth+1)...)
		}
	}
	return true
}

// ntpFile parses one ntp configuration file: the sources it names, and the
// files it includes, which are returned carrying the given depth.
func (s *timesyncScan) ntpFile(data []byte, depth int) []timesyncInclude {
	var out []timesyncInclude
	for _, raw := range splitLines(data) {
		f := strings.Fields(configComment(raw))
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "server", "pool":
			s.servers = append(s.servers, f[1])
		case "includefile":
			out = append(out, timesyncInclude{path: path.Clean(f[1]), depth: depth})
		}
	}
	return out
}

// parseChronySources reads one chrony configuration or .sources file: the
// server/pool/peer names, the reference clocks, and the source directories it
// names. chrony treats #, %, ; and ! as comment characters.
func parseChronySources(data []byte) (servers []string, dirs []chronyDir) {
	for _, raw := range splitLines(data) {
		f := strings.Fields(configComment(raw))
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "server", "pool", "peer":
			servers = append(servers, f[1])
		case "refclock":
			// A reference clock IS a time source (Ruling I-17). It is recorded
			// as refclock:<driver>:<arg> so two PHC clocks on different
			// devices count as two sources and neither is confused with a
			// network server name.
			id := "refclock:" + f[1]
			if len(f) >= 3 {
				id += ":" + f[2]
			}
			servers = append(servers, id)
		case "sourcedir":
			for _, d := range f[1:] {
				d = path.Clean(d)
				dirs = append(dirs, chronyDir{directive: "sourcedir", dir: d, glob: path.Join(d, "*.sources")})
			}
		case "confdir":
			for _, d := range f[1:] {
				d = path.Clean(d)
				dirs = append(dirs, chronyDir{directive: "confdir", dir: d, glob: path.Join(d, "*.conf")})
			}
		case "include":
			// IR-1: chrony's include names one file or one glob of files, which
			// carry sources exactly as a sourcedir's do. It is followed like any
			// other directive, so an include of a path this collector never
			// declared is recorded rather than read.
			inc := path.Clean(f[1])
			dirs = append(dirs, chronyDir{directive: "include", dir: inc, glob: inc})
		}
	}
	return servers, dirs
}

// configComment strips a chrony/ntp comment and surrounding space. chrony
// accepts #, %, ; and ! as comment characters; ntp.conf accepts # (and, for
// compatibility, the same set).
func configComment(line string) string {
	line = strings.TrimSpace(line)
	if i := strings.IndexAny(line, "#%;!"); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}
