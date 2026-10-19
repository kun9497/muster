//go:build linux

package collectors

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
)

// The reader parity test (3D-2d §3.10, O-10, O-21, O-28): a review-script body
// that gates on a value read from a file defines its reader as a one-line
// shell function rd_<what>() { LC_ALL=C <command>; }, and the reader must
// agree with the collector's parser over the same bytes, or the body would
// leave a line the check still judges (a block "done" that check still
// FAILs) or rewrite one it does not. The tests here extract the reader from
// the shipped body, run it with sh over each row's file and compare with the
// Go parser the collector calls.

// shippedBody returns the shipped remediation of the control id, failing the
// test when the control or its script is missing.
func shippedBody(t *testing.T, id string) *controls.Remediation {
	t.Helper()
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	c, ok := set.ByID(id)
	if !ok || c.Remediation == nil || strings.TrimSpace(c.Remediation.Script) == "" {
		t.Fatalf("no shipped script for %s", id)
	}
	return c.Remediation
}

var firstSingleQuoted = regexp.MustCompile(`'[^']*'`)

// readerLine returns the one line of r.Script that defines the reader
// function name (O-21: `^\s*<name>\(\) \{.*\}$`), failing the test when there
// is none or more than one, or when the function's command does not start
// with LC_ALL=C (O-47: the locale is the reader's own, not the caller's).
// With inValidate, the function's first single-quoted string (its awk
// program or grep/sed pattern) must appear verbatim in r.Validate, every copy
// run as the reader runs it (`LC_ALL=C <command word> [options] ` right before
// the program): the validate runs in its own subshell and cannot call the
// body's function, so it repeats the program under the same locale.
func readerLine(t *testing.T, r *controls.Remediation, name string, inValidate bool) string {
	t.Helper()
	def := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(name) + `\(\) \{(.*)\}$`)
	var found []string
	var command string
	for _, l := range strings.Split(r.Script, "\n") {
		if m := def.FindStringSubmatch(l); m != nil {
			found = append(found, strings.TrimSpace(l))
			command = strings.TrimSpace(m[1])
		}
	}
	if len(found) != 1 {
		t.Fatalf("the script defines %s() on %d lines, want one:\n%s", name, len(found), r.Script)
	}
	if !strings.HasPrefix(command, "LC_ALL=C ") {
		t.Fatalf("%s's command %q does not start with LC_ALL=C", name, command)
	}
	if inValidate {
		prog := firstSingleQuoted.FindString(command)
		if prog == "" {
			t.Fatalf("%s's command %q carries no single-quoted program", name, command)
		}
		n := strings.Count(r.Validate, prog)
		if n == 0 {
			t.Fatalf("the validate does not repeat %s's program %s verbatim:\n%s", name, prog, r.Validate)
		}
		// The locale is tied to the program: every copy in the validate is
		// run by the reader's own command word and options, immediately
		// preceded by LC_ALL=C (an LC_ALL=C elsewhere on the line is not it).
		lead := command[:strings.Index(command, prog)]
		if got := strings.Count(r.Validate, lead+prog); got != n {
			t.Fatalf("%d of the validate's %d copies of %s's program are not run as %q:\n%s", n-got, n, name, lead, r.Validate)
		}
	}
	return found[0]
}

// runReader writes each of files (keyed by absolute host path) under a fresh
// temporary root, substitutes {root} in call and in every file's content,
// and runs fn and then call with `sh -c` (no -e, no locale forced: the
// reader carries its own LC_ALL=C). It returns stdout without its trailing
// newlines and the exit code; a non-zero exit is data (a reader that
// compares by exit code), never a test failure.
func runReader(t *testing.T, fn, call string, files map[string][]byte) (stdout string, code int) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	root := t.TempDir()
	for p, data := range files {
		if !filepath.IsAbs(p) {
			t.Fatalf("runReader: %q is not an absolute host path", p)
		}
		f := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte(strings.ReplaceAll(string(data), "{root}", root)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sh", "-c", fn+"\n"+strings.ReplaceAll(call, "{root}", root))
	cmd.Dir = root
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("sh: %v", err)
	}
	if errb.Len() > 0 {
		t.Logf("%s: stderr %q", call, errb.String())
	}
	return strings.TrimRight(out.String(), "\n"), code
}

// TestRhostsReaderMatchesTheCollector (§4.5): rd_plus counts the lines of
// /etc/hosts.equiv the body comments out, and that count is the number of
// hostsEquivLines entries the control's clause (`matches "^\+"`) judges, so
// the body leaves no "+" line check still sees and the validate agrees with
// check after it ran.
func TestRhostsReaderMatchesTheCollector(t *testing.T) {
	r := shippedBody(t, "muster.file.rhosts_forbidden")
	fn := readerLine(t, r, "rd_plus", true)
	plus := regexp.MustCompile(`^\+`)
	for _, row := range []struct{ name, file string }{
		{"bare", "+\n"},
		{"indented netgroup", "  +@ops\n"},
		{"comment", "#+x\n"},
		{"indented comment", "  # +x\n"},
		{"host", "host\n"},
		{"tab", "\t+h\n"},
		{"minus", "-host\n+-@ops\n"},
		{"crlf", "+\r\nhost\r\n"},
		{"no final newline", "host\n+host-b"},
		{"empty", ""},
		{"mixed", "+\n  +@ops\nhost-a\n# c\n+host-b\n"},
		{"after the body", "# muster: +\n# muster:   +@ops\nhost-a\n# c\n# muster: +host-b\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			want := 0
			for _, l := range hostsEquivLines([]byte(row.file)) {
				if plus.MatchString(l.(string)) {
					want++
				}
			}
			got, code := runReader(t, fn, "rd_plus {root}/etc/hosts.equiv", map[string][]byte{"/etc/hosts.equiv": []byte(row.file)})
			if code != 0 || got != strconv.Itoa(want) {
				t.Errorf("rd_plus over %q printed %q (exit %d), the collector judges %d \"+\" lines", row.file, got, code, want)
			}
		})
	}
}

// TestVsftpdReadersMatchTheCollector (§4.7, §4.8, O-14, O-28): rd_greeting
// reads the greeting in vsftpd's order and prints `file` where a non-empty
// banner_file sets it (the collector's banner_source is banner_file),
// otherwise `disclose` or `clean` as the collector's
// ftp.banner_discloses_version reads ftpd_banner or the compiled greeting;
// rd_anon prints `yes` or `no` as ftp.anonymous_enabled. The collector only
// reads the paths it declares, so its fake fsAccess keeps the banner file at
// /etc/issue.net, and the shell side gets the same bytes at
// {root}/etc/issue.net, which the row's conf names.
func TestVsftpdReadersMatchTheCollector(t *testing.T) {
	banner := readerLine(t, shippedBody(t, "muster.service.ftp_banner"), "rd_greeting", true)
	anon := readerLine(t, shippedBody(t, "muster.service.ftp_anonymous"), "rd_anon", true)
	const bf = "banner_file={root}/etc/issue.net\n"
	for _, row := range []struct {
		name, conf string
		issue      *string
	}{
		{"PureFTPd ready", "ftpd_banner=PureFTPd ready\n", nil},
		{"myvsftpd", "ftpd_banner=myvsftpd\n", nil},
		{"vsFTPd version", "ftpd_banner=vsFTPd 3.0.5 ready\n", nil},
		{"wu-ftpd", "ftpd_banner=(wu-ftpd)\n", nil},
		{"version number only", "ftpd_banner=Server 3.0.5 ready\n", nil},
		{"upper key", "  FTPD_BANNER = vsFTPd\n", nil},
		{"empty value", "ftpd_banner=\n", nil},
		{"missing key", "listen=YES\n", nil},
		{"commented", "#ftpd_banner=Welcome\n", nil},
		{"clean", "ftpd_banner=Welcome\n", nil},
		{"crlf", "ftpd_banner=Welcome\r\nanonymous_enable=NO\r\n", nil},
		{"last wins", "ftpd_banner=Welcome\nftpd_banner=ProFTPD\n", nil},
		{"clean banner, disclosing file", "ftpd_banner=Welcome\n" + bf, strp("220 vsFTPd 3.0.5\n")},
		{"disclosing banner, clean file", "ftpd_banner=vsFTPd 3.0.5\n" + bf, strp("Authorized use only.\n")},
		{"empty banner file", "ftpd_banner=vsFTPd 3.0.5\n" + bf, strp("")},
		{"empty banner file, clean banner", "ftpd_banner=Welcome\n" + bf, strp("")},
		{"empty banner file alone", bf, strp("")},
		{"newline-only banner file", "ftpd_banner=vsFTPd\n" + bf, strp("\n")},
		{"empty banner_file value", "ftpd_banner=Welcome\nbanner_file=\n", nil},
		{"anonymous FALSE", "anonymous_enable=FALSE\n", nil},
		{"anonymous 0", "anonymous_enable=0\n", nil},
		{"anonymous No spaced", " Anonymous_Enable = No \n", nil},
		{"anonymous YES", "anonymous_enable=YES\n", nil},
		{"anonymous 1", "anonymous_enable=1\n", nil},
		{"anonymous last wins", "anonymous_enable=NO\nanonymous_enable=YES\n", nil},
		{"anonymous commented", "#anonymous_enable=NO\n", nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			a := ftpAccess(nil)
			a.stats[vsftpdBin] = statResult{mode: 0o755, kind: "regular"}
			a.contents = map[string][]byte{vsftpdDebianConf: []byte(strings.ReplaceAll(row.conf, "{root}", ""))}
			files := map[string][]byte{vsftpdDebianConf: []byte(row.conf)}
			if row.issue != nil {
				a.contents["/etc/issue.net"] = []byte(*row.issue)
				files["/etc/issue.net"] = []byte(*row.issue)
			}
			b := buildBegun(t, "ftp", a)
			src, disc, anonEnv := env(t, b, "ftp.banner_source"), env(t, b, "ftp.banner_discloses_version"), env(t, b, "ftp.anonymous_enabled")
			if src.Status != facts.StatusOK || disc.Status != facts.StatusOK || anonEnv.Status != facts.StatusOK {
				t.Fatalf("the collector did not judge the row: source %+v, discloses %+v, anonymous %+v", src, disc, anonEnv)
			}
			want := "clean"
			switch {
			case src.Value == "banner_file":
				want = "file"
			case disc.Value == true:
				want = "disclose"
			}
			if got, code := runReader(t, banner, "rd_greeting {root}/etc/vsftpd.conf", files); code != 0 || got != want {
				t.Errorf("rd_greeting printed %q (exit %d); the collector reads source %v, discloses %v: want %q", got, code, src.Value, disc.Value, want)
			}
			wantAnon := "no"
			if anonEnv.Value == true {
				wantAnon = "yes"
			}
			if got, code := runReader(t, anon, "rd_anon {root}/etc/vsftpd.conf", files); code != 0 || got != wantAnon {
				t.Errorf("rd_anon printed %q (exit %d); the collector reads anonymous_enabled %v", got, code, anonEnv.Value)
			}
		})
	}
}

func strp(s string) *string { return &s }

// TestPostfixAndExportsReadersMatchTheCollector (§4.6, §4.9, O-25, O-26,
// O-28). The readers and why each is or is not repeated in its validate:
//
//	rd_vrfy  inValidate false: a tool call (postconf -h), not a program; the
//	         validate inlines the same `LC_ALL=C postconf -c /etc/postfix -h`
//	rd_nrs   inValidate true: the O-26 ERE, repeated under the same grep
//
// rd_vrfy reads disable_vrfy_command through postconf over the row's main.cf
// (-c names the row's directory, never the host's): where the collector
// reads yes (parsePostfixInto + postfixYes), the body reads yes, case blind.
// The one recorded divergence: the collector folds the parameter name to
// lower case, postconf does not, so Disable_Vrfy_Command = yes reads yes to
// the collector (check PASSes; the row is never planned) and the compiled
// no to postconf. Without postconf on PATH (CI's test job) the postfix rows
// skip, and the TestPostfix* stub tests pin the body alone.
//
// rd_nrs counts the lines of /etc/exports that hold no_root_squash as an
// option token. The comparison is one-sided: wherever parseExportsContent
// reads root_squash false through a no_root_squash option token, rd_nrs
// counts the line, so the swap leaves nothing check still judges. The
// reverse need not hold (a trailing default list applies to no client; the
// swap changes it harmlessly), so each row also names its count.
func TestPostfixAndExportsReadersMatchTheCollector(t *testing.T) {
	t.Run("postfix", func(t *testing.T) {
		r := shippedBody(t, "muster.service.mail_expn_vrfy")
		fn := readerLine(t, r, "rd_vrfy", false)
		if !strings.Contains(r.Validate, "LC_ALL=C postconf -c /etc/postfix -h disable_vrfy_command") {
			t.Fatalf("the validate does not inline rd_vrfy's call:\n%s", r.Validate)
		}
		if _, err := exec.LookPath("postconf"); err != nil {
			t.Skip("no postconf on PATH: the postfix half is pinned by the TestPostfix* stub tests only (O-25)")
		}
		for _, row := range []struct {
			name, conf string
			diverges   bool // the case-folded name: postconf reads its own default
		}{
			{"yes", "disable_vrfy_command = yes\n", false},
			{"YES", "disable_vrfy_command = YES\n", false},
			{"no", "disable_vrfy_command = no\n", false},
			{"continued", "disable_vrfy_command =\n    yes\n", false},
			{"later override", "disable_vrfy_command = yes\ndisable_vrfy_command = no\n", false},
			{"absent", "inet_interfaces = all\n", false},
			{"case-folded name", "Disable_Vrfy_Command = yes\n", true},
		} {
			t.Run(row.name, func(t *testing.T) {
				m := map[string]string{}
				parsePostfixInto(m, []byte(row.conf))
				collector, _ := postfixYes(m["disable_vrfy_command"])
				got, code := runReader(t, fn, "rd_vrfy {root}", map[string][]byte{"/main.cf": []byte(row.conf)})
				body := strings.EqualFold(got, "yes")
				if code != 0 {
					t.Fatalf("rd_vrfy exit %d (printed %q)", code, got)
				}
				if row.diverges {
					if !collector || body || got != "no" {
						t.Errorf("the recorded divergence moved: the collector reads %v, postconf printed %q", collector, got)
					}
					return
				}
				if body != collector {
					t.Errorf("rd_vrfy printed %q; the collector reads disable_vrfy_command as %v", got, collector)
				}
			})
		}
	})
	t.Run("exports", func(t *testing.T) {
		r := shippedBody(t, "muster.service.nfs_export_access")
		fn := readerLine(t, r, "rd_nrs", true)
		for _, row := range []struct {
			name, file string
			n          int // the lines rd_nrs counts
		}{
			{"path and option", "/srv/no_root_squash_area 192.0.2.1(rw,no_root_squash,sync)\n", 1},
			{"alone", "/b 192.0.2.2(no_root_squash)\n", 1},
			{"twice", "/c 192.0.2.3(rw,no_root_squash,no_root_squash)\n", 1},
			{"default list", "/d -no_root_squash 192.0.2.4\n", 1},
			{"comment", "/e 192.0.2.5(rw) # no_root_squash\n", 0},
			{"path only", "/srv/x-no_root_squash 192.0.2.9(rw)\n", 0},
			{"path beside a violation", "/srv/x-no_root_squash 192.0.2.9(rw) 192.0.2.10(no_root_squash)\n", 1},
			{"commented line", "#/g 192.0.2.7(no_root_squash)\n", 0},
			{"parenthesised comment", "/f 192.0.2.6(rw) # (no_root_squash)\n", 0},
			{"tab before the default list", "/t\t-no_root_squash 192.0.2.4\n", 1},
			{"continuation", "/h \\\n\t192.0.2.11(rw,no_root_squash)\n", 1},
			{"seed export", "/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)\n", 1},
			{"accumulated default lists", "/s -no_root_squash 192.0.2.7 -rw 192.0.2.8\n", 1},
			{"two default lists", "/s -no_root_squash -rw 192.0.2.9\n", 1},
			{"trailing default list", "/z 192.0.2.12 -no_root_squash\n", 1},
			{"client override", "/srv -no_root_squash 192.0.2.10(root_squash)\n", 1},
			{"client named so", "/p no_root_squash(rw)\n", 0},
			{"crlf", "/b 192.0.2.2(no_root_squash)\r\n", 1},
			{"after the swap", "/b 192.0.2.2(root_squash)\n/d -root_squash 192.0.2.4\n/c 192.0.2.3(rw,root_squash,root_squash)\n", 0},
			{"empty", "", 0},
			// The token opens the second physical line, so the line-scoped ERE
			// does not count it; the collector splits the joined line at the
			// blank and reads two bare clients, so it reads no false either.
			{"option list across a continuation", "/i 192.0.2.13(rw,\\\nno_root_squash)\n", 0},
		} {
			t.Run(row.name, func(t *testing.T) {
				collectorFalse := false
				for _, rec := range parseExportsContent([]byte(row.file)) {
					if rec.(map[string]any)["root_squash"] == false {
						collectorFalse = true
					}
				}
				got, code := runReader(t, fn, "rd_nrs {root}/etc/exports", map[string][]byte{"/etc/exports": []byte(row.file)})
				if code != 0 || got != strconv.Itoa(row.n) {
					t.Fatalf("rd_nrs printed %q (exit %d), want %d", got, code, row.n)
				}
				if collectorFalse && row.n == 0 {
					t.Errorf("the collector reads root_squash false over %q, and rd_nrs counts no line", row.file)
				}
			})
		}
	})
}
