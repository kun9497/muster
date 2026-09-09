//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The FTP configuration files and daemon binaries this collector knows how
// to find. Which daemon is RUNNING is services.ftp.*; these are the
// persisted view.
const (
	vsftpdDebianConf = "/etc/vsftpd.conf"
	vsftpdRhelConf   = "/etc/vsftpd/vsftpd.conf"
	vsftpdConfGlob   = "/etc/vsftpd/*.conf"

	proftpdDebianConf = "/etc/proftpd/proftpd.conf"
	proftpdRhelConf   = "/etc/proftpd.conf"
	proftpdConfGlob   = "/etc/proftpd/*.conf"
	// Wider than the brief's /etc/proftpd/conf.d/*.conf: a directory Include
	// reads every file in the directory (Ruling L-37), and a fragment named
	// without a .conf suffix would otherwise be invisible. The narrower
	// pattern is a subset of this one, so the glob form still matches.
	proftpdConfDGlob = "/etc/proftpd/conf.d/*"

	pureFtpdConf     = "/etc/pure-ftpd/pure-ftpd.conf"
	pureFtpdConfGlob = "/etc/pure-ftpd/conf/*"

	vsftpdBin   = "/usr/sbin/vsftpd"
	proftpdBin  = "/usr/sbin/proftpd"
	pureFtpdBin = "/usr/sbin/pure-ftpd"
)

// The access-control files of the three implementations. Task 1 reads none
// of them — ftp.access_files is the next task's — but the user-list
// candidates are STAT'ed here, because vsftpd's userlist_file default is
// whichever of the two build defaults is on disk.
const (
	vsftpdDebianUserList = "/etc/vsftpd.user_list"
	vsftpdRhelUserList   = "/etc/vsftpd/user_list"
	etcFtpusers          = "/etc/ftpusers"

	// vsftpd's own compiled pam_service_name. Ruling L-21: both packaged
	// builds ship this value and upstream ships "ftp", so both pam.d files
	// are declared; any other name is a path this collector never opened.
	vsftpdDefaultPamService = "vsftpd"
)

// The roles an access-control file plays. The plan names four; pam_allow is
// the fifth (see the ftp.access_files registry description): pam_listfile
// takes sense=allow as readily as sense=deny, and filing such a file as a
// userlist_allow would point a reader at ftp.userlist_file, which is not
// where it came from.
const (
	rolePamDeny       = "pam_deny"
	rolePamAllow      = "pam_allow"
	roleUserlistDeny  = "userlist_deny"
	roleUserlistAllow = "userlist_allow"
	roleFtpusers      = "ftpusers"
)

var (
	// The main configuration file of each implementation, in probe order.
	vsftpdMains  = []string{vsftpdDebianConf, vsftpdRhelConf}
	proftpdMains = []string{proftpdDebianConf, proftpdRhelConf}

	// The access files this collector reads, and the greeting files a
	// vsftpd banner_file may point at. Ruling L-5: a config-supplied path
	// outside these lists is recorded, never opened.
	ftpAccessFiles = []string{
		"/etc/vsftpd/ftpusers", vsftpdRhelUserList, vsftpdDebianUserList,
		"/etc/vsftpd.ftpusers", etcFtpusers,
		pamDir + "/" + vsftpdDefaultPamService, pamDir + "/ftp",
	}
	ftpBannerFiles = []string{"/etc/issue.net", "/etc/vsftpd/banner*"}
)

// ftpConfCandidates is every main configuration file the collector looks
// for, in probe order — the list a reason names when it found none of them.
func ftpConfCandidates() []string {
	c := append([]string(nil), vsftpdMains...)
	c = append(c, proftpdMains...)
	return append(c, pureFtpdConf, pureFtpdConfGlob)
}

func ftpReads() []string {
	reads := []string{
		vsftpdDebianConf, vsftpdRhelConf, vsftpdConfGlob,
		proftpdDebianConf, proftpdRhelConf, proftpdConfGlob, proftpdConfDGlob,
		pureFtpdConf, pureFtpdConfGlob,
		vsftpdBin, proftpdBin, pureFtpdBin,
	}
	reads = append(reads, ftpAccessFiles...)
	return append(reads, ftpBannerFiles...)
}

var ftpCollector = collect.Collector{
	Name: "ftp",
	Declare: collect.Declaration{
		Reads: ftpReads(),
		// Needs: "none" — vsftpd.conf and proftpd.conf are world-readable on
		// both distributions, and one that is not is reported denied through
		// C3 rather than wrapped as a privilege failure (Ruling L-7).
		Needs: "none",
	},
	Run: runFtp,
}

// ftpJudgedKeys are the leaves a control judges. Ruling L-4: they degrade
// TOGETHER — a file that could not be read, a read cut at the cap or a
// construct outside the model makes every one of them carry that story,
// while the evidence leaves (implementation, config_files, parse_complete,
// unmodelled) stay ok and tell the reader what happened.
var ftpJudgedKeys = []string{
	"ftp.local_enabled",
	"ftp.anonymous_enabled",
	"ftp.tls_enforced",
	"ftp.tcp_wrappers",
	"ftp.userlist_enable",
	"ftp.userlist_deny",
	"ftp.userlist_file",
	// The access and greeting leaves degrade with the rest: WHICH files hold
	// the access lists is itself read out of the configuration, so a parse
	// that could not be finished cannot promise the list is complete either.
	"ftp.access_files",
	"ftp.access_file_present",
	"ftp.root_denied",
	"ftp.banner_source",
	"ftp.banner_text",
	"ftp.banner_discloses_version",
}

// vsftpdDefaults are the values vsftpd's own tunables.c compiles in, which
// are what a directive-free file means. Ruling L-25: Debian's man page says
// anonymous_enable "Default: NO", but that patch never reached the code —
// both builds compile YES — so an empty file really does serve anonymous
// logins and this table must not be "corrected" from the man page.
var vsftpdDefaults = map[string]bool{
	"anonymous_enable":       true,
	"local_enable":           false,
	"tcp_wrappers":           false,
	"userlist_enable":        false,
	"userlist_deny":          true,
	"ssl_enable":             false,
	"force_local_logins_ssl": true,
	"force_local_data_ssl":   true,
	"force_anon_logins_ssl":  false,
	"force_anon_data_ssl":    false,
}

// proftpdModelled is every directive this model attributes. A directive
// outside the set is ignored wherever it appears; one INSIDE the set that
// appears inside a section this model does not attribute (Ruling L-4)
// counts as unmodelled instead, so a server whose real settings live in a
// <VirtualHost> is reported as unjudgeable rather than judged by the
// top-level defaults it never uses.
var proftpdModelled = map[string]bool{
	"serverident": true,
	"useftpusers": true,
	"rootlogin":   true,
	"tlsengine":   true,
	"tlsrequired": true,
}

// proftpdOpaqueSections are the sections whose contents belong to another
// server, another build or another module, and are therefore not the
// answer for this host.
var proftpdOpaqueSections = map[string]bool{
	"virtualhost": true,
	"global":      true,
	"ifmodule":    true,
}

// ftpParse accumulates what this host's FTP configuration says. impl is the
// implementation the files and binaries agree on; files is every file whose
// content reached a parse, in read order.
type ftpParse struct {
	a        collect.Access
	impl     string
	mainFile string
	leftover string // a conffile whose daemon binary is not installed

	files     []string
	seen      map[string]bool
	truncated []string

	// readFailure is the first read that failed for a reason other than
	// "not there"; unmodelled lists every construct outside the model, each
	// naming the file and the construct. Either means the judged leaves
	// cannot be answered.
	readFailure *facts.Envelope
	unmodelled  []string

	vsftpd map[string]string // lowercased key -> raw value, last wins
	pro    map[string]string // lowercased directive -> arguments, last wins
	proAno bool              // an <Anonymous> block at an attributed depth
	pure   map[string]string // setting name -> value, last wins
}

// runFtp publishes the ftp keys from configuration files alone: D14 forbids
// invoking the daemon, so nothing here runs a command and no version is
// derived.
//
// C3: a configuration file that EXISTS but cannot be read is the answer for
// every value it could set — never the daemon's compiled default. A host
// with no FTP daemon at all cannot be said to refuse anonymous logins, so
// the judged leaves are absent (→ MANUAL) while the evidence leaves stay ok
// and the run stays complete (Ruling L-7).
func runFtp(_ context.Context, a collect.Access, b *collect.Builder) error {
	p := &ftpParse{
		a:      a,
		seen:   map[string]bool{},
		vsftpd: map[string]string{},
		pro:    map[string]string{},
		pure:   map[string]string{},
	}
	p.detect()
	p.publish(b)
	return nil
}

// detect names the implementation this host's files and binaries agree on
// and parses its configuration. Ruling L-3 (the 2I IR-7 lesson): a
// configuration file counts only when the daemon's binary is installed too
// — dpkg keeps the conffile after `apt remove`, and judging a removed
// package's file is a confidently wrong verdict either way.
func (p *ftpParse) detect() {
	if p.detectVsftpd() || p.detectProftpd() || p.detectPureFtpd() {
		return
	}
	p.impl = "none"
}

func (p *ftpParse) detectVsftpd() bool {
	for _, c := range vsftpdMains {
		data, meta, err := p.a.ReadFile(c, readLimit)
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if !anyPresent(p.a, []string{vsftpdBin}) {
			p.noteLeftover(c, vsftpdBin)
			continue
		}
		p.impl, p.mainFile = "vsftpd", c
		if err != nil {
			p.fail(readErrorEnv(c, err))
		} else {
			p.record(c, meta.Truncated)
			parseVsftpdInto(p.vsftpd, data)
		}
		// Ruling L-24: the glob matches the main file itself, so every OTHER
		// match is a second instance whose settings this model does not
		// attribute to the one it just parsed.
		p.noteExtraInstances()
		return true
	}
	return false
}

// noteExtraInstances records every /etc/vsftpd/*.conf that is not the main
// file. Each is a separate vsftpd instance with its own port and its own
// anonymous setting; judging the main file's answer as the host's would
// miss it entirely.
func (p *ftpParse) noteExtraInstances() {
	matches, err := p.a.Glob(vsftpdConfGlob)
	if err != nil {
		p.fail(collect.Unsupported("glob " + vsftpdConfGlob + ": " + err.Error()))
		return
	}
	sort.Strings(matches)
	for _, m := range matches {
		// The exclusion is the file this run actually PARSED, not a fixed
		// path: on a host carrying both layouts the Debian file wins the
		// probe order, and /etc/vsftpd/vsftpd.conf is then a second
		// instance like any other.
		if m != p.mainFile {
			p.unmodelled = append(p.unmodelled, m+" configures a second vsftpd instance, which this model does not attribute")
		}
	}
}

func (p *ftpParse) detectProftpd() bool {
	for _, c := range proftpdMains {
		data, meta, err := p.a.ReadFile(c, readLimit)
		if err != nil && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if !anyPresent(p.a, []string{proftpdBin}) {
			p.noteLeftover(c, proftpdBin)
			continue
		}
		p.impl, p.mainFile = "proftpd", c
		if err != nil {
			p.fail(readErrorEnv(c, err))
			return true
		}
		p.record(c, meta.Truncated)
		p.parseProftpd(c, data, 0, nil)
		return true
	}
	return false
}

// detectPureFtpd asks the two questions Ruling L-23 settles: the binary,
// then a readable pure-ftpd.conf OR a non-empty /etc/pure-ftpd/conf/*.
// There is no directory stat — the declaration covers neither
// /etc/pure-ftpd nor /etc/pure-ftpd/conf, and a probe outside it is a guard
// violation whatever it would have told us.
func (p *ftpParse) detectPureFtpd() bool {
	data, meta, err := p.a.ReadFile(pureFtpdConf, readLimit)
	confPresent := err == nil || !errors.Is(err, fs.ErrNotExist)
	matches, gerr := p.a.Glob(pureFtpdConfGlob)
	if gerr != nil {
		p.fail(collect.Unsupported("glob " + pureFtpdConfGlob + ": " + gerr.Error()))
		matches = nil
	}
	if !confPresent && len(matches) == 0 {
		return false
	}
	if !anyPresent(p.a, []string{pureFtpdBin}) {
		if confPresent {
			p.noteLeftover(pureFtpdConf, pureFtpdBin)
		} else {
			p.noteLeftover(path.Dir(pureFtpdConfGlob), pureFtpdBin)
		}
		return false
	}
	p.impl = "pure-ftpd"
	if confPresent {
		p.mainFile = pureFtpdConf
		if err != nil {
			p.fail(readErrorEnv(pureFtpdConf, err))
		} else {
			p.record(pureFtpdConf, meta.Truncated)
			parsePureFtpdInto(p.pure, data)
		}
	}
	// The Debian layout keeps one setting per file, named for the setting.
	sort.Strings(matches)
	for _, m := range matches {
		data, meta, err := p.a.ReadFile(m, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || nonRegular(err) {
				continue
			}
			p.fail(readErrorEnv(m, err))
			continue
		}
		p.record(m, meta.Truncated)
		p.pure[path.Base(m)] = firstSettingLine(data)
	}
	return true
}

// parseProftpd walks one proftpd file. Directives are attributed only at a
// depth this model understands; an Include is followed when the declaration
// covers it and recorded when it does not (Ruling L-5).
func (p *ftpParse) parseProftpd(file string, data []byte, depth int, base []*proftpdSection) {
	// Ruling L-39: an included file is inlined AT THE INCLUDE POINT, so it
	// begins at the include site's depth, not at the top level. The header
	// is copied so an append here can never reach into the caller's backing
	// array, while the sections themselves are shared pointers, so a
	// fragment that lands inside a <VirtualHost> marks THAT section noted
	// and the caller sees it.
	stack := append([]*proftpdSection(nil), base...)
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		// proftpd treats a '#' as a comment only where a directive would
		// begin, never mid-line, so a path containing one is not cut.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "</") {
			// Ruling L-40: a closing tag that does not match the section it
			// appears to close is a file proftpd refuses to start on.
			// Popping blindly would re-attribute everything after it to the
			// server — a confident verdict on a configuration that cannot
			// run — so the stack stays as it is and the file is unmodelled.
			// A fragment can never pop a section its includer opened either:
			// that is what base bounds.
			if len(stack) > len(base) && strings.EqualFold(stack[len(stack)-1].name, proftpdClosingName(line)) {
				stack = stack[:len(stack)-1]
				continue
			}
			p.noteUnmodelled(file, line+" does not close the section it appears to, so this file cannot be modelled")
			continue
		}
		if strings.HasPrefix(line, "<") {
			name := proftpdSectionName(line)
			if strings.EqualFold(name, "anonymous") && p.attributes(file, stack, "<Anonymous>") {
				p.proAno = true
			}
			stack = append(stack, &proftpdSection{name: name})
			continue
		}
		fields := strings.Fields(line)
		key := strings.ToLower(fields[0])
		args := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
		if key == "include" {
			p.proftpdInclude(file, args, depth, stack)
			continue
		}
		if !proftpdModelled[key] {
			continue
		}
		if !p.attributes(file, stack, fields[0]) {
			continue
		}
		p.pro[key] = args
	}
	// Ruling L-42, mirroring L-40: a section still open at end of file is
	// the other half of a tag that does not match. proftpd refuses to start
	// on it, so what the file appears to say about the server is not what
	// the server does. Sections are counted against this file's OWN base,
	// so a fragment that closes everything it opened stays complete even
	// when its includer left a section open around it.
	for i := len(base); i < len(stack); i++ {
		if stack[i].noted {
			continue
		}
		stack[i].noted = true
		p.noteUnmodelled(file, "<"+stack[i].name+"> is never closed, so this file cannot be modelled")
	}
}

// proftpdSection is one open section and whether the collector has already
// counted it as unmodelled, so a <VirtualHost> holding four modelled
// directives is ONE construct outside the model, not four.
type proftpdSection struct {
	name  string
	noted bool
}

// attributes reports whether what was read at a depth whose settings are the
// SERVER's own, which Ruling L-35 fixes at the top level and nowhere else:
// TLSRequired inside <Anonymous> covers the anonymous area alone, RootLogin
// inside <Directory> covers that tree alone, and reading either as the
// server-wide answer is the over-claim H-16 forbids — a false PASS for U-54
// on a server that still takes local logins in clear.
//
// The two kinds of section differ only in what they cost. <VirtualHost>,
// <Global> and <IfModule> can REDEFINE server-wide behaviour, so each is
// counted once in unmodelled the first time something modelled turns up
// inside it and the judged leaves go absent. Every other section —
// <Anonymous>, <Directory>, <Limit> and the rest — only narrows the scope
// of what it holds, so it is a neutral container: nothing inside it is
// attributed, and nothing about it makes the file unjudgeable.
func (p *ftpParse) attributes(file string, stack []*proftpdSection, what string) bool {
	for i := len(stack) - 1; i >= 0; i-- {
		if !proftpdOpaqueSections[strings.ToLower(stack[i].name)] {
			continue
		}
		if !stack[i].noted {
			stack[i].noted = true
			p.noteUnmodelled(file, "<"+stack[i].name+"> encloses "+what+
				", which this model does not attribute to the server")
		}
		return false
	}
	return len(stack) == 0
}

// proftpdInclude follows one Include. R55/Ruling L-5: the target is asked
// of the declaration through the guard's own Allowed probe, so an include
// outside it is RECORDED with its path and never touched — muster does not
// read a path a change-control reviewer never approved.
func (p *ftpParse) proftpdInclude(file, target string, depth int, stack []*proftpdSection) {
	target = strings.Trim(strings.TrimSpace(target), `"`)
	if target == "" {
		return
	}
	if depth >= maxIncludeDepth {
		p.fail(collect.ErrorEnv("include nesting deeper than " + strconv.Itoa(maxIncludeDepth) + " levels at " + file))
		return
	}
	pattern, ok := p.includePattern(target)
	if !ok {
		p.noteUnmodelled(file, "Include "+target+" is outside this collector's declaration and was not read")
		return
	}
	targets := []string{pattern}
	if strings.ContainsAny(pattern, "*?[") {
		matches, err := p.a.Glob(pattern)
		if err != nil {
			p.fail(collect.Unsupported("glob " + pattern + ": " + err.Error()))
			return
		}
		sort.Strings(matches)
		targets = matches
	}
	for _, t := range targets {
		if p.seen[path.Clean(t)] {
			continue
		}
		data, meta, err := p.a.ReadFile(t, readLimit)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || nonRegular(err) {
				continue
			}
			// The sshd Include precedent: a fragment that cannot be READ is
			// never silently skipped — it might hold the directive that
			// decides the verdict.
			p.fail(readErrorEnv(t, err))
			continue
		}
		p.record(t, meta.Truncated)
		p.parseProftpd(t, data, depth+1, stack)
	}
}

// includePattern turns one Include target into the pattern the collector
// will actually read, and reports whether the declaration covers it.
//
// Ruling L-37: the stock Debian proftpd.conf includes its fragment
// DIRECTORY — "Include /etc/proftpd/conf.d/" — and proftpd reads every file
// in it, whatever its name. Reading the directory as a literal file would
// fail, and refusing it would make every stock Debian host unjudgeable, so
// a target that is not itself declared is retried as that directory's glob,
// which the declaration does cover. A target neither form covers stays
// undeclared and is recorded rather than read.
func (p *ftpParse) includePattern(target string) (string, bool) {
	dirForm := strings.HasSuffix(target, "/")
	clean := path.Clean(target)
	if !dirForm && declared(p.a, clean) {
		return clean, true
	}
	if glob := clean + "/*"; declared(p.a, glob) {
		return glob, true
	}
	return "", false
}

// nonRegular reports whether a read failed because the path is not a
// regular file: the no-follow read primitive refuses a directory, a symlink
// and every special file, and a glob over a fragment DIRECTORY matches
// whatever is in it — an admin's stash subdirectory included (Ruling
// L-41). Such an entry is skipped, never filed as an error: one error
// envelope flips run.complete and hands CI exit code 2 for something that
// was never configuration.
//
// Ruling L-42: the test is the WHOLE class, not the sentinel the primitive
// raises after a successful open. open(2) never gets far enough to report
// ErrNotRegular for a socket (ENXIO) or for a path whose component stopped
// being a directory between the glob and the read (ENOTDIR), and a device
// node can answer EISDIR; every one of them says the same thing — this
// entry is not a configuration file.
func nonRegular(err error) bool {
	return errors.Is(err, collect.ErrNotRegular) ||
		errors.Is(err, collect.ErrSymlink) ||
		errors.Is(err, unix.EISDIR) ||
		errors.Is(err, unix.ENXIO) ||
		errors.Is(err, unix.ENOTDIR)
}

// record notes a file whose content reached the parse, once however it was
// reached, and whether the read primitive cut it at the cap.
func (p *ftpParse) record(file string, truncated bool) {
	file = path.Clean(file)
	if p.seen[file] {
		return
	}
	p.seen[file] = true
	p.files = append(p.files, file)
	if truncated {
		p.truncated = append(p.truncated, file)
	}
}

// fail records the first read that could not answer. The first is kept
// rather than the worst, so the reason names the file the collector reached
// first in its own fixed order and the same input yields the same reason.
func (p *ftpParse) fail(e facts.Envelope) {
	if p.readFailure == nil {
		p.readFailure = &e
	}
}

func (p *ftpParse) noteUnmodelled(file, what string) {
	p.unmodelled = append(p.unmodelled, file+": "+what)
}

// noteLeftover records a configuration file whose daemon binary is not
// installed. The FIRST one found is kept, so the reason is stable.
func (p *ftpParse) noteLeftover(conf, bin string) {
	if p.leftover == "" {
		p.leftover = conf + " is present but " + bin + " is not: configuration of a removed package"
	}
}

func (p *ftpParse) publish(b *collect.Builder) {
	src := filesSource(p.files)
	cut := len(p.truncated) > 0

	impl := collect.OK(p.impl, p.implSource())
	if p.impl == "none" && p.leftover != "" {
		// Name the file, so a reader can see it is a leftover to purge
		// rather than a configuration anything was judged by (IR-7).
		impl.Reason = "no FTP daemon on this host: " + p.leftover
	}
	b.Set("ftp.implementation", impl)
	b.Set("ftp.config_files", withTruncation(collect.OK(p.sortedFiles(), src), cut))
	b.Set("ftp.parse_complete", collect.OK(p.complete(), src))
	b.Set("ftp.unmodelled", collect.OK(len(p.unmodelled), src))

	if e := p.judged(); e != nil {
		for _, k := range ftpJudgedKeys {
			b.Set(k, *e)
		}
		return
	}
	switch p.impl {
	case "vsftpd":
		p.publishVsftpd(b, src)
	case "proftpd":
		p.publishProftpd(b, src)
	case "pure-ftpd":
		p.publishPureFtpd(b, src)
	}
}

// complete reports whether every file the parse was told to read could be
// read in full. A host with no FTP configuration at all read everything
// there was, so the parse is complete and the judged leaves carry that
// story instead. A construct outside the model is NOT a read failure: it
// counts in unmodelled and leaves this true.
func (p *ftpParse) complete() bool {
	return p.readFailure == nil && len(p.truncated) == 0
}

// judged is the envelope every judged leaf shares when the configuration
// could not be seen or could not be modelled, and nil when it could. A read
// that failed wins over a cap and over an unmodelled construct: it names a
// privilege or an I/O problem, which is the more actionable of the three.
func (p *ftpParse) judged() *facts.Envelope {
	if p.readFailure != nil {
		return p.readFailure
	}
	if len(p.truncated) > 0 {
		e := collect.Absent("the configuration was cut at the read limit in " +
			strings.Join(p.truncated, ", ") + "; what is past the cap cannot be judged")
		return &e
	}
	if len(p.unmodelled) > 0 {
		e := collect.Absent("this configuration uses constructs outside the collector's model: " +
			strings.Join(p.unmodelled, "; "))
		return &e
	}
	if p.impl == "none" {
		reason := "no FTP daemon is installed on this host: none of " +
			strings.Join(ftpConfCandidates(), ", ") + " is present with its daemon binary"
		if p.leftover != "" {
			reason = "no FTP daemon is installed on this host: " + p.leftover
		}
		e := collect.Absent(reason)
		return &e
	}
	return nil
}

func (p *ftpParse) publishVsftpd(b *collect.Builder, src *facts.Source) {
	anonymous := p.vsftpdBool("anonymous_enable")
	tls := p.vsftpdBool("ssl_enable") &&
		p.vsftpdBool("force_local_logins_ssl") && p.vsftpdBool("force_local_data_ssl") &&
		(!anonymous || (p.vsftpdBool("force_anon_logins_ssl") && p.vsftpdBool("force_anon_data_ssl")))
	b.Set("ftp.local_enabled", collect.OK(p.vsftpdBool("local_enable"), src))
	b.Set("ftp.anonymous_enabled", collect.OK(anonymous, src))
	b.Set("ftp.tls_enforced", collect.OK(tls, src))
	b.Set("ftp.tcp_wrappers", collect.OK(p.vsftpdBool("tcp_wrappers"), src))
	b.Set("ftp.userlist_enable", collect.OK(p.vsftpdBool("userlist_enable"), src))
	b.Set("ftp.userlist_deny", collect.OK(p.vsftpdBool("userlist_deny"), src))
	b.Set("ftp.userlist_file", p.userlistFile(src))

	recs, blind := p.vsftpdAccess()
	p.publishAccessFiles(b, src, recs, "this vsftpd configuration names no per-account access list")
	if !p.vsftpdBool("local_enable") {
		e := collect.OK(true, src)
		e.Reason = "local_enable is NO: no local account, root included, may log in"
		b.Set("ftp.root_denied", e)
	} else {
		b.Set("ftp.root_denied", rootDenied(recs, blind, src))
	}
	p.publishVsftpdBanner(b, src)
}

// userlistFile is the explicit userlist_file, or the build default that is
// actually on disk — Debian's flat /etc/vsftpd.user_list and RHEL's
// /etc/vsftpd/user_list are the same tunable with two compiled values, and
// only the file that exists can be the one vsftpd reads. Neither on disk
// means the path is not invented.
func (p *ftpParse) userlistFile(src *facts.Source) facts.Envelope {
	if v, ok := p.vsftpd["userlist_file"]; ok && v != "" {
		if oversized(v) {
			return collect.Absent("userlist_file's value is longer than this collector stores")
		}
		return collect.OK(v, src)
	}
	if c, ok := p.userlistDefault(); ok {
		e := collect.OK(c, &facts.Source{Kind: "file", Path: c})
		e.Reason = "userlist_file is not set; this is the build default that exists on this host"
		return e
	}
	return collect.Absent("userlist_file is not set and neither build default (" +
		vsftpdDebianUserList + ", " + vsftpdRhelUserList + ") exists")
}

// userlistDefault is the build default user list that is on disk, if either
// is; the leaf and the access record must agree on which file that is.
func (p *ftpParse) userlistDefault() (string, bool) {
	for _, c := range p.userListCandidates() {
		if pathPresent(p.a, c) {
			return c, true
		}
	}
	return "", false
}

// userlistPath is the file vsftpd would actually read its user list from -
// the explicit userlist_file, else the build default that exists - as a
// plain path, for the access record that has to stat it.
func (p *ftpParse) userlistPath() (string, bool) {
	if v, ok := p.vsftpd["userlist_file"]; ok && v != "" && !oversized(v) {
		return v, true
	}
	return p.userlistDefault()
}

// userListCandidates orders the two build defaults by the layout the main
// configuration file already proved, so a host that carries both files is
// answered the same way every run.
func (p *ftpParse) userListCandidates() []string {
	if p.mainFile == vsftpdRhelConf {
		return []string{vsftpdRhelUserList, vsftpdDebianUserList}
	}
	return []string{vsftpdDebianUserList, vsftpdRhelUserList}
}

func (p *ftpParse) publishProftpd(b *collect.Builder, src *facts.Source) {
	local := collect.OK(true, src)
	local.Reason = "proftpd authenticates local accounts and has no directive that turns them off wholesale"
	b.Set("ftp.local_enabled", local)
	b.Set("ftp.anonymous_enabled", collect.OK(p.proAno, src))
	b.Set("ftp.tls_enforced", collect.OK(proftpdOn(p.pro["tlsengine"]) && proftpdOn(p.pro["tlsrequired"]), src))
	b.Set("ftp.tcp_wrappers", collect.Absent(
		"proftpd wraps connections through mod_wrap2's directives, which this model does not read"))
	p.setNotAVsftpdConcept(b, "proftpd")

	recs := p.proftpdAccess()
	p.publishAccessFiles(b, src, recs, "UseFtpUsers is off, so proftpd consults no per-account access list")
	if !proftpdOn(p.pro["rootlogin"]) {
		e := collect.OK(true, src)
		e.Reason = "RootLogin is not on, and proftpd's own default is off, so root cannot log in"
		b.Set("ftp.root_denied", e)
	} else {
		b.Set("ftp.root_denied", rootDenied(recs, nil, src))
	}
	p.publishProftpdBanner(b, src)
}

func (p *ftpParse) publishPureFtpd(b *collect.Builder, src *facts.Source) {
	local := collect.OK(true, src)
	local.Reason = "pure-ftpd authenticates local accounts and has no directive that turns them off wholesale"
	b.Set("ftp.local_enabled", local)
	b.Set("ftp.anonymous_enabled", collect.OK(!pureFtpdYes(p.pure["NoAnonymous"]), src))
	// TLS 0 permits cleartext, 1 accepts both, 2 and 3 refuse a cleartext
	// session; only the last two enforce encryption.
	b.Set("ftp.tls_enforced", collect.OK(pureFtpdTLSLevel(p.pure["TLS"]) >= 2, src))
	b.Set("ftp.tcp_wrappers", collect.Absent(
		"pure-ftpd has no tcp_wrappers setting of its own in this model"))
	p.setNotAVsftpdConcept(b, "pure-ftpd")

	p.publishAccessFiles(b, src, nil,
		"pure-ftpd is not configured through a per-account list in this model")
	root := collect.OK(true, src)
	root.Reason = "pure-ftpd refuses every account whose uid is below MinUID, which is at least 1 in every build, so root cannot log in"
	b.Set("ftp.root_denied", root)
	notModelled := collect.Absent("the pure-ftpd greeting is not configurable in this version's model")
	p.setBanner(b, notModelled, notModelled, notModelled)
}

// setNotAVsftpdConcept writes the three user-list leaves for an
// implementation that has no such tunable. They are absent rather than
// false: a false would read as "there is a user list and it lets everyone
// in", which is a different claim from "this daemon has no user list".
func (p *ftpParse) setNotAVsftpdConcept(b *collect.Builder, impl string) {
	reason := "the vsftpd user list is not a " + impl + " setting; its access list is /etc/ftpusers"
	for _, k := range []string{"ftp.userlist_enable", "ftp.userlist_deny", "ftp.userlist_file"} {
		b.Set(k, collect.Absent(reason))
	}
}

// vsftpdBool reads one boolean tunable, falling back to the value vsftpd
// itself compiles in. A value that is neither YES nor NO makes vsftpd
// refuse to start at all, so the compiled default is the honest answer for
// it too.
func (p *ftpParse) vsftpdBool(key string) bool {
	def := vsftpdDefaults[key]
	v, ok := p.vsftpd[key]
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes":
		return true
	case "no":
		return false
	}
	return def
}

func (p *ftpParse) implSource() *facts.Source {
	if p.mainFile != "" {
		return &facts.Source{Kind: "file", Path: p.mainFile}
	}
	if len(p.files) > 0 {
		return filesSource(p.files)
	}
	return &facts.Source{Kind: "derived"}
}

func (p *ftpParse) sortedFiles() []any {
	files := append([]string(nil), p.files...)
	sort.Strings(files)
	out := []any{}
	for _, f := range files {
		out = append(out, f)
	}
	return out
}

// parseVsftpdInto folds one vsftpd file into the settings map. vsftpd's own
// parser takes whole-line '#' comments only, splits at the FIRST '=' and
// lets a later line override an earlier one, so last wins here too. The key
// is folded to lower case; the value keeps its own case.
func parseVsftpdInto(dst map[string]string, data []byte) {
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		dst[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
}

// parsePureFtpdInto folds pure-ftpd's single-file style — one `Name value`
// per line — into the settings map, last wins. The Debian layout's
// one-setting-per-file directory is folded by the caller, which takes the
// name from the file name.
func parsePureFtpdInto(dst map[string]string, data []byte) {
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, _ := strings.Cut(line, " ")
		dst[name] = strings.TrimSpace(value)
	}
}

// firstSettingLine is the value of a Debian /etc/pure-ftpd/conf file: the
// first line that is neither blank nor a comment, which is the whole
// setting.
func firstSettingLine(data []byte) string {
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return line
	}
	return ""
}

// pureFtpdYes reads pure-ftpd's boolean form. An unset setting is the
// daemon's own default, which is "no" for every boolean this model reads.
func pureFtpdYes(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "yes", "on", "true", "1":
		return true
	}
	return false
}

// pureFtpdTLSLevel is the numeric TLS setting; an unset or unparsable value
// is level 0, pure-ftpd's own default (cleartext permitted).
func pureFtpdTLSLevel(v string) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0
	}
	return n
}

// proftpdOn reads proftpd's boolean form, which accepts on/off as well as
// the usual spellings.
func proftpdOn(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "yes", "true", "1":
		return true
	}
	return false
}

// proftpdClosingName is the tag of a section closer, so "</VirtualHost>" is
// "VirtualHost" — the name a matching opener would have carried.
func proftpdClosingName(line string) string {
	return proftpdSectionName("<" + strings.TrimPrefix(line, "</"))
}

// proftpdSectionName is the tag of a section opener, so "<VirtualHost
// ftp.example.org>" is "VirtualHost".
func proftpdSectionName(line string) string {
	name := strings.TrimPrefix(line, "<")
	name = strings.TrimSuffix(name, ">")
	if i := strings.IndexAny(name, " \t>"); i >= 0 {
		name = name[:i]
	}
	return name
}

// ftpProductRe matches a product name in a greeting. A bare version number
// is deliberately NOT a disclosure: "220 3.0.5 ready" tells a scanner
// nothing about which daemon the number belongs to, while any of these
// names hands it the software to look up advisories for.
var ftpProductRe = regexp.MustCompile(`(?i)\b(vsftpd|proftpd|pure-?ftpd|wu-?ftpd)\b`)

// ftpAccessRec is one access-control file as this run found it: the
// permission fields U-56 judges, whether root is named in it, and what the
// stat could say. Ruling L-15: mode, uid and gid are the INTS writePermFacts
// stores, and a record whose stat did not succeed carries -1 in all three —
// never 0, which reads as a root-owned file with no bits set.
type ftpAccessRec struct {
	path string
	role string

	exists     bool
	rootListed bool
	mode       int
	uid        int
	gid        int
	statStatus string // Ruling L-22: ok|absent|denied|error|undeclared
	reason     string

	// blind is set when the file's CONTENT could not be read, so rootListed
	// is not an answer about this file — only about what was seen of it.
	blind bool
}

// record is the row a control reads. R176: every field a clause could filter
// or compare on is present in every row, whatever the stat said; reason is
// the one addition, and only when there is something to say.
func (r *ftpAccessRec) record() map[string]any {
	rec := map[string]any{
		"path":        r.path,
		"role":        r.role,
		"exists":      r.exists,
		"root_listed": r.rootListed,
		"mode":        r.mode,
		"uid":         r.uid,
		"gid":         r.gid,
		"stat_status": r.statStatus,
	}
	if r.reason != "" {
		rec["reason"] = r.reason
	}
	return rec
}

// rootDenial is what one access file says about a root login.
type rootDenial int

const (
	rootUndecided rootDenial = iota // this file refuses nobody named root
	rootRefused                     // this file refuses root
	rootUnknown                     // this file could not be read
)

// says reads one record with its ROLE's semantics. A deny list refuses the
// accounts it names; an allow list refuses every account it does NOT name,
// so the same file read the other way is the opposite verdict. A deny list
// that is not there refuses nobody, which is a definite answer, while an
// allow list that is not there cannot be read as "everyone is allowed".
func (r *ftpAccessRec) says() rootDenial {
	allow := r.role == roleUserlistAllow || r.role == rolePamAllow
	switch {
	case r.blind:
		return rootUnknown
	case !r.exists:
		if allow {
			return rootUnknown
		}
		return rootUndecided
	case allow == r.rootListed:
		return rootUndecided
	}
	return rootRefused
}

// accessRecord stats one access-control file and reads it for a literal root
// line. Ruling L-5: a path the declaration does not cover is recorded and
// never opened. The stat and the read are separate questions — a 0640
// root-owned list is stat-able by anyone and readable by almost nobody — so
// a file whose content is denied still carries the permission fields U-56
// judges, with an honest reason for the content it could not see.
func (p *ftpParse) accessRecord(file, role string) *ftpAccessRec {
	r := &ftpAccessRec{path: path.Clean(file), role: role, mode: -1, uid: -1, gid: -1}
	if !declared(p.a, r.path) {
		r.statStatus, r.blind = "undeclared", true
		r.reason = "outside this collector's declaration: recorded, never opened"
		return r
	}
	meta, err := p.a.Stat(r.path)
	if err != nil {
		e := collect.FromReadError(err, collect.ReadMeta{})
		r.statStatus = string(e.Status)
		r.blind = e.Status != facts.StatusAbsent
		if r.blind {
			r.reason = readReason(r.path, err)
		}
		return r
	}
	r.statStatus, r.exists = "ok", true
	r.mode, r.uid, r.gid = int(meta.Mode), int(meta.UID), int(meta.GID)
	data, rmeta, rerr := p.a.ReadFile(r.path, readLimit)
	switch {
	case rerr != nil:
		r.blind = true
		r.reason = "the file exists but its content could not be read: " + readReason(r.path, rerr)
	case rmeta.Truncated:
		r.blind = true
		r.reason = "the file was cut at the read limit; a name past the cap cannot be seen"
	default:
		r.rootListed = listsRoot(data)
	}
	return r
}

// listsRoot reports whether a user list names root. Each line is one account
// name; a blank line and a '#' comment name nobody.
func listsRoot(data []byte) bool {
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "root" {
			return true
		}
	}
	return false
}

// pamListfile is one pam_listfile.so line: the file it names and whether
// that file is an allow list rather than a deny list.
type pamListfile struct {
	file  string
	allow bool
}

// parsePamListfiles reads every pam_listfile.so line that filters on the
// USER name. The control field is not inspected — a list under auth, account
// or session gates the same login either way — and onerr is a failure policy
// rather than a membership rule, so it is ignored. An @include line pulls in
// a common-* stack, which carries no per-service user list.
func parsePamListfiles(data []byte) []pamListfile {
	var out []pamListfile
	for _, raw := range splitLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		mod := -1
		for i, f := range fields {
			if path.Base(f) == "pam_listfile.so" {
				mod = i
				break
			}
		}
		if mod < 0 {
			continue
		}
		var lf pamListfile
		item, sense := "", ""
		for _, f := range fields[mod+1:] {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "item":
				item = strings.ToLower(v)
			case "sense":
				sense = strings.ToLower(v)
			case "file":
				lf.file = v
			}
		}
		// item=group, item=tty and the rest gate on something other than the
		// account name, so they say nothing about whether root may log in.
		if item != "user" || lf.file == "" {
			continue
		}
		lf.allow = sense == "allow"
		out = append(out, lf)
	}
	return out
}

// vsftpdAccess is every file vsftpd consults to decide WHO may log in, plus
// the sources whose content could not be seen. Ruling L-21: the PAM service
// file is /etc/pam.d/ + the pam_service_name value, whose compiled default is
// vsftpd in both packaged builds; a name the declaration does not cover is
// named in the reason rather than opened.
func (p *ftpParse) vsftpdAccess() (recs []*ftpAccessRec, blind []string) {
	pamFile := p.pamServiceFile()
	if !declared(p.a, pamFile) {
		blind = append(blind, pamFile+" is outside this collector's declaration and was not read, so the lists it names are unknown")
	} else {
		data, meta, err := p.a.ReadFile(pamFile, readLimit)
		switch {
		case err != nil && errors.Is(err, fs.ErrNotExist):
			// Nothing names a list. That is an answer, not a blind spot.
		case err != nil:
			blind = append(blind, pamFile+" could not be read: "+readReason(pamFile, err))
		case meta.Truncated:
			blind = append(blind, pamFile+" was cut at the read limit, so a list named past the cap is unknown")
		default:
			for _, lf := range parsePamListfiles(data) {
				role := rolePamDeny
				if lf.allow {
					role = rolePamAllow
				}
				recs = append(recs, p.accessRecord(lf.file, role))
			}
		}
	}
	if p.vsftpdBool("userlist_enable") {
		role := roleUserlistAllow
		if p.vsftpdBool("userlist_deny") {
			role = roleUserlistDeny
		}
		switch file, ok := p.userlistPath(); {
		case ok:
			recs = append(recs, p.accessRecord(file, role))
		case role == roleUserlistAllow:
			// An allow list decides by ABSENCE, so not knowing which file it
			// is leaves every account's verdict open.
			blind = append(blind, "userlist_enable is on with userlist_deny=NO, but no user list file could be identified")
		}
	}
	return dedupeAccess(recs), blind
}

// pamServiceFile is the pam.d file vsftpd's own pam_service_name names.
func (p *ftpParse) pamServiceFile() string {
	svc := strings.TrimSpace(p.vsftpd["pam_service_name"])
	if svc == "" {
		svc = vsftpdDefaultPamService
	}
	return path.Clean(pamDir + "/" + svc)
}

// proftpdAccess is /etc/ftpusers whenever UseFtpUsers is not explicitly off:
// the directive's own default is on, and that file is the only per-account
// list this model reads for proftpd.
func (p *ftpParse) proftpdAccess() []*ftpAccessRec {
	if proftpdOff(p.pro["useftpusers"]) {
		return nil
	}
	return []*ftpAccessRec{p.accessRecord(etcFtpusers, roleFtpusers)}
}

// dedupeAccess keeps the first record of each path and sorts by path, so the
// same host renders the same bytes however many directives named the file.
func dedupeAccess(recs []*ftpAccessRec) []*ftpAccessRec {
	seen := map[string]bool{}
	out := make([]*ftpAccessRec, 0, len(recs))
	for _, r := range recs {
		if seen[r.path] {
			continue
		}
		seen[r.path] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].path < out[j].path })
	return out
}

// publishAccessFiles writes the record list and the presence bool. emptyWhy
// is the reason the presence leaf carries when this implementation named no
// access list at all — false there means "nothing was found", which is a
// different claim from "a list was found and it is empty".
func (p *ftpParse) publishAccessFiles(b *collect.Builder, src *facts.Source, recs []*ftpAccessRec, emptyWhy string) {
	list := []any{} // R50: never nil
	present := false
	for _, r := range recs {
		list = append(list, r.record())
		if r.exists {
			present = true
		}
	}
	b.Set("ftp.access_files", collect.OK(list, src))
	e := collect.OK(present, src)
	if len(recs) == 0 {
		e.Reason = emptyWhy
	}
	b.Set("ftp.access_file_present", e)
}

// rootDenied answers whether a root login is refused. blind names the
// sources whose content could not be seen: when nothing refuses root and one
// of them is blind, the honest answer is none at all rather than a confident
// false that would PASS U-57 on a host nobody could examine.
func rootDenied(recs []*ftpAccessRec, blind []string, src *facts.Source) facts.Envelope {
	var unknown []string
	for _, r := range recs {
		switch r.says() {
		case rootRefused:
			e := collect.OK(true, src)
			e.Reason = r.path + " (" + r.role + ") refuses a root login"
			return e
		case rootUnknown:
			unknown = append(unknown, r.path)
		}
	}
	unknown = append(unknown, blind...)
	if len(unknown) > 0 {
		return collect.Absent("whether a root login is refused cannot be decided: " +
			strings.Join(unknown, "; "))
	}
	e := collect.OK(false, src)
	e.Reason = "no access list this collector read refuses a root login"
	return e
}

// setBanner writes the three greeting leaves together: what configures the
// greeting, what it says, and whether that names the product.
func (p *ftpParse) setBanner(b *collect.Builder, source, text, discloses facts.Envelope) {
	b.Set("ftp.banner_source", source)
	b.Set("ftp.banner_text", text)
	b.Set("ftp.banner_discloses_version", discloses)
}

// publishVsftpdBanner follows vsftpd's own precedence: ftpd_banner wins over
// banner_file, and neither set means the compiled greeting. That greeting's
// text is NOT invented here — the source says "default", the text is empty
// with a reason naming the product, and the disclosure verdict is true
// because every build's compiled greeting names vsftpd.
func (p *ftpParse) publishVsftpdBanner(b *collect.Builder, src *facts.Source) {
	if v := strings.TrimSpace(p.vsftpd["ftpd_banner"]); v != "" {
		source := collect.OK("ftpd_banner", src)
		if oversized(v) {
			e := collect.Absent("ftpd_banner's value is longer than this collector stores")
			p.setBanner(b, source, e, e)
			return
		}
		p.setBanner(b, source, collect.OK(v, src), collect.OK(ftpProductRe.MatchString(v), src))
		return
	}
	file := strings.TrimSpace(p.vsftpd["banner_file"])
	if file == "" {
		text := collect.OK("", src)
		text.Reason = "neither ftpd_banner nor banner_file is set, so vsftpd serves its compiled greeting; this collector does not invent that text"
		discloses := collect.OK(true, src)
		discloses.Reason = "vsftpd's compiled greeting names the product"
		p.setBanner(b, collect.OK("default", src), text, discloses)
		return
	}
	source := collect.OK("banner_file", src)
	clean := path.Clean(file)
	if !declared(p.a, clean) {
		e := collect.Absent("banner_file " + clean + " is outside this collector's declaration and was not read")
		p.setBanner(b, source, e, e)
		return
	}
	data, meta, err := p.a.ReadFile(clean, readLimit)
	switch {
	case err != nil:
		e := readErrorEnv(clean, err)
		p.setBanner(b, source, e, e)
	case meta.Truncated:
		e := collect.Absent(clean + " was cut at the read limit; what is past the cap cannot be judged")
		p.setBanner(b, source, e, e)
	default:
		text := strings.TrimRight(string(data), "\n")
		if oversized(text) {
			e := collect.Absent(clean + " is longer than this collector stores")
			p.setBanner(b, source, e, e)
			return
		}
		fsrc := &facts.Source{Kind: "file", Path: clean}
		p.setBanner(b, source, collect.OK(text, fsrc), collect.OK(ftpProductRe.MatchString(text), fsrc))
	}
}

// publishProftpdBanner reads ServerIdent, whose argument is on or off and,
// when on, an optional string of the server's own. Unset is proftpd's
// compiled identification, which names the product.
func (p *ftpParse) publishProftpdBanner(b *collect.Builder, src *facts.Source) {
	args := strings.TrimSpace(p.pro["serverident"])
	if args == "" {
		p.setBanner(b, collect.OK("default", src),
			p.compiledIdent(src, "ServerIdent is not set, so proftpd sends its compiled identification; this collector does not invent that text"),
			p.namesTheProduct(src))
		return
	}
	source := collect.OK("serverident", src)
	mode, rest, _ := strings.Cut(args, " ")
	rest = strings.Trim(strings.TrimSpace(rest), `"`)
	switch {
	case proftpdOff(mode):
		text := collect.OK("", src)
		text.Reason = "ServerIdent " + mode + " keeps the product name out of the identification string"
		p.setBanner(b, source, text, collect.OK(false, src))
	case !proftpdOn(mode):
		e := collect.Absent("ServerIdent " + args + " is neither on nor off, and proftpd refuses to start on it")
		p.setBanner(b, source, e, e)
	case rest == "":
		p.setBanner(b, source,
			p.compiledIdent(src, "ServerIdent on carries no string of its own, so proftpd sends its compiled identification"),
			p.namesTheProduct(src))
	case oversized(rest):
		e := collect.Absent("the ServerIdent string is longer than this collector stores")
		p.setBanner(b, source, e, e)
	default:
		p.setBanner(b, source, collect.OK(rest, src), collect.OK(ftpProductRe.MatchString(rest), src))
	}
}

// compiledIdent is the empty text a daemon's own greeting carries, with the
// reason that says why it is empty rather than unknown.
func (p *ftpParse) compiledIdent(src *facts.Source, why string) facts.Envelope {
	e := collect.OK("", src)
	e.Reason = why
	return e
}

func (p *ftpParse) namesTheProduct(src *facts.Source) facts.Envelope {
	e := collect.OK(true, src)
	e.Reason = "proftpd's compiled identification names the product"
	return e
}

// proftpdOff reads proftpd's boolean form for a directive whose OWN default
// is on, so only an explicit off turns it off.
func proftpdOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "off", "no", "false", "0":
		return true
	}
	return false
}
