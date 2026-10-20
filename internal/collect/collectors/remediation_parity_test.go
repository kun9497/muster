//go:build linux

package collectors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/kun9497/muster/internal/collect"
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
	return runReaderWith(t, fn, call, files, nil)
}

// runReaderWith is runReader with setup run over the temporary root after
// the files are written (a FIFO or a symlink a row needs), when not nil.
func runReaderWith(t *testing.T, fn, call string, files map[string][]byte, setup func(root string)) (stdout string, code int) {
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
	if setup != nil {
		setup(root)
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
// reads the greeting in vsftpd's order and prints `file` where banner_file
// names a non-empty regular file that is not a symlink (the collector's
// banner_source is banner_file), otherwise `disclose` or `clean` as the
// collector's ftp.banner_discloses_version reads ftpd_banner or the compiled
// greeting. The reader never opens banner_file (O-82): a FIFO or a symlink
// there is a greeting the collector reads absent (MANUAL, never planned), and
// with no ftpd_banner the reader reads it as the compiled greeting, disclose;
// rd_anon prints `yes` or `no` as ftp.anonymous_enabled. The collector only
// reads the paths it declares, so its fake fsAccess keeps the banner file at
// /etc/issue.net, and the shell side gets the same bytes at
// {root}/etc/issue.net, which the row's conf names.
func TestVsftpdReadersMatchTheCollector(t *testing.T) {
	ftpBanner := shippedBody(t, "muster.service.ftp_banner")
	banner := readerLine(t, ftpBanner, "rd_greeting", true)
	// O-82: the awk program prints the verdict for ftpd_banner and the
	// banner_file value, and the shell alone decides whether that names a
	// greeting file; both validate copies decide it the same way.
	const decide = ` | { read -r g bf; if [ -f "$bf" ] && [ ! -L "$bf" ] && [ -s "$bf" ]; then echo file; else echo "$g"; fi; }`
	if strings.Contains(banner, "getline") || !strings.Contains(banner, `"$1"`+decide) || strings.Count(ftpBanner.Validate, decide) != 2 {
		t.Fatalf("rd_greeting must not open banner_file and its validate copies must decide as it does:\n%s\n%s", banner, ftpBanner.Validate)
	}
	anon := readerLine(t, shippedBody(t, "muster.service.ftp_anonymous"), "rd_anon", true)
	const bf = "banner_file={root}/etc/issue.net\n"
	for _, row := range []struct {
		name, conf string
		issue      *string
		special    string // "fifo" or "symlink": /etc/issue.net is not a regular file
	}{
		{"PureFTPd ready", "ftpd_banner=PureFTPd ready\n", nil, ""},
		{"myvsftpd", "ftpd_banner=myvsftpd\n", nil, ""},
		{"vsFTPd version", "ftpd_banner=vsFTPd 3.0.5 ready\n", nil, ""},
		{"wu-ftpd", "ftpd_banner=(wu-ftpd)\n", nil, ""},
		{"version number only", "ftpd_banner=Server 3.0.5 ready\n", nil, ""},
		{"upper key", "  FTPD_BANNER = vsFTPd\n", nil, ""},
		{"empty value", "ftpd_banner=\n", nil, ""},
		{"missing key", "listen=YES\n", nil, ""},
		{"commented", "#ftpd_banner=Welcome\n", nil, ""},
		{"clean", "ftpd_banner=Welcome\n", nil, ""},
		{"crlf", "ftpd_banner=Welcome\r\nanonymous_enable=NO\r\n", nil, ""},
		{"last wins", "ftpd_banner=Welcome\nftpd_banner=ProFTPD\n", nil, ""},
		{"clean banner, disclosing file", "ftpd_banner=Welcome\n" + bf, strp("220 vsFTPd 3.0.5\n"), ""},
		{"disclosing banner, clean file", "ftpd_banner=vsFTPd 3.0.5\n" + bf, strp("Authorized use only.\n"), ""},
		{"empty banner file", "ftpd_banner=vsFTPd 3.0.5\n" + bf, strp(""), ""},
		{"empty banner file, clean banner", "ftpd_banner=Welcome\n" + bf, strp(""), ""},
		{"empty banner file alone", bf, strp(""), ""},
		{"newline-only banner file", "ftpd_banner=vsFTPd\n" + bf, strp("\n"), ""},
		{"empty banner_file value", "ftpd_banner=Welcome\nbanner_file=\n", nil, ""},
		{"anonymous FALSE", "anonymous_enable=FALSE\n", nil, ""},
		{"anonymous 0", "anonymous_enable=0\n", nil, ""},
		{"anonymous No spaced", " Anonymous_Enable = No \n", nil, ""},
		{"anonymous YES", "anonymous_enable=YES\n", nil, ""},
		{"anonymous 1", "anonymous_enable=1\n", nil, ""},
		{"anonymous last wins", "anonymous_enable=NO\nanonymous_enable=YES\n", nil, ""},
		{"anonymous commented", "#anonymous_enable=NO\n", nil, ""},
		{"FIFO banner file", bf, nil, "fifo"},
		{"symlinked banner file", bf, nil, "symlink"},
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
			var setup func(root string)
			switch row.special {
			case "fifo":
				a.fails["/etc/issue.net"] = fmt.Errorf("%s: %w", "/etc/issue.net", collect.ErrNotRegular)
				setup = func(root string) {
					if err := syscall.Mkfifo(filepath.Join(root, "etc", "issue.net"), 0o644); err != nil {
						t.Fatal(err)
					}
				}
			case "symlink":
				a.fails["/etc/issue.net"] = fmt.Errorf("%s: %w", "/etc/issue.net", collect.ErrSymlink)
				setup = func(root string) {
					target := filepath.Join(root, "banner")
					if err := os.WriteFile(target, []byte("220 vsFTPd 3.0.5\n"), 0o644); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, filepath.Join(root, "etc", "issue.net")); err != nil {
						t.Fatal(err)
					}
				}
			}
			b := buildBegun(t, "ftp", a)
			src, disc, anonEnv := env(t, b, "ftp.banner_source"), env(t, b, "ftp.banner_discloses_version"), env(t, b, "ftp.anonymous_enabled")
			want := "clean"
			if row.special != "" {
				// The collector reads the greeting absent: MANUAL, never
				// planned; the reader, which opens nothing, reads the
				// compiled greeting.
				if src.Status != facts.StatusOK || src.Value != "banner_file" || disc.Status != facts.StatusAbsent || anonEnv.Status != facts.StatusOK {
					t.Fatalf("the collector read the %s banner file as source %+v, discloses %+v, anonymous %+v; want banner_file and absent", row.special, src, disc, anonEnv)
				}
				want = "disclose"
			} else {
				if src.Status != facts.StatusOK || disc.Status != facts.StatusOK || anonEnv.Status != facts.StatusOK {
					t.Fatalf("the collector did not judge the row: source %+v, discloses %+v, anonymous %+v", src, disc, anonEnv)
				}
				switch {
				case src.Value == "banner_file":
					want = "file"
				case disc.Value == true:
					want = "disclose"
				}
			}
			if got, code := runReaderWith(t, banner, "rd_greeting {root}/etc/vsftpd.conf", files, setup); code != 0 || got != want {
				t.Errorf("rd_greeting printed %q (exit %d); the collector reads source %v, discloses %v: want %q", got, code, src.Value, disc.Value, want)
			}
			wantAnon := "no"
			if anonEnv.Value == true {
				wantAnon = "yes"
			}
			if got, code := runReaderWith(t, anon, "rd_anon {root}/etc/vsftpd.conf", files, setup); code != 0 || got != wantAnon {
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
// reverse need not hold (a "-no_root_squash" token right after another list
// is a host name nfs-utils cannot resolve and the collector ignores, O-80; the
// swap changes it harmlessly), so each row also names its count. A trailing
// default list exports the path to the world under it as well (O-79), so the
// collector reads root_squash false there and rd_nrs counts the line.
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
			{"a list after a list, squashed first", "/s -root_squash -no_root_squash 192.0.2.9\n", 1},
			{"a list after a list, squashed second", "/s -no_root_squash -root_squash 192.0.2.9\n", 1},
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

// TestAuditdConfReaderMatchesTheCollector (§4.3, O-17, O-19, O-28): rd_action
// prints the action auditd.conf sets for one key as parseAuditdConf reads it
// (comment lines skipped, the key case blind, the last line wins, the value's
// first space-separated word lower-cased, O-83; "" for a key the file does
// not set), so the body
// rewrites exactly the keys check FAILs on and leaves an `exec <path>`
// action whose first word is in the list. The reader and why it is not
// repeated in the validate:
//
//	rd_action  inValidate false: the validate checks the lists in force over
//	           the keys this run wrote ($MB/disk.keys) in one awk program of
//	           its own, the same reading over every key at once
func TestAuditdConfReaderMatchesTheCollector(t *testing.T) {
	fn := readerLine(t, shippedBody(t, "muster.beyond.audit_disk_actions"), "rd_action", false)
	rows := []struct{ name, conf string }{
		{"spaced upper key", "Space_Left_Action = SYSLOG\n"},
		{"later override", "space_left_action = suspend\nspace_left_action = email\n"},
		{"earlier in the list, later outside", "disk_full_action = halt\ndisk_full_action = SUSPEND\n"},
		{"tab separator", "disk_error_action\t=\tHALT\n"},
		{"tab inside the value", "admin_space_left_action =\texec\t/y\n"},
		{"syslog extra words", "space_left_action = syslog extra words\n"},
		{"tab then a space", "disk_full_action = syslog\t extra\n"},
		{"no spaces", "max_log_file_action=keep_logs\n"},
		{"indented", "   admin_space_left_action = single\n"},
		{"commented", "# space_left_action = ignore\nspace_left_action = rotate\n#space_left_action = suspend\n"},
		{"exec with a path", "space_left_action = exec /usr/local/sbin/x\n"},
		{"EXEC upper", "disk_error_action = EXEC /x\n"},
		{"empty value", "disk_full_action =\n"},
		{"blank value", "disk_full_action =   \n"},
		{"crlf", "space_left_action = SYSLOG\r\nmax_log_file_action = ROTATE\r\n"},
		{"trailing blanks", "space_left_action = syslog   \n"},
		{"no equals", "space_left_action syslog\n"},
		{"another key's suffix", "admin_space_left_action = halt\n"},
		{"a value with an equals sign", "space_left_action = exec /x=y\n"},
		{"missing", "log_file = /var/log/audit/audit.log\n"},
	}
	for _, f := range []string{"auditd.conf.sample", "auditd.conf.exec"} {
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, struct{ name, conf string }{f, string(b)})
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			m := parseAuditdConf([]byte(row.conf))
			for _, k := range []string{"space_left_action", "admin_space_left_action", "disk_full_action", "disk_error_action", "max_log_file_action"} {
				got, code := runReader(t, fn, "rd_action {root}/etc/audit/auditd.conf "+k, map[string][]byte{"/etc/audit/auditd.conf": []byte(row.conf)})
				if code != 0 || got != m[k] {
					t.Errorf("%s: rd_action printed %q (exit %d); parseAuditdConf reads %q", k, got, code, m[k])
				}
			}
		})
	}
}

// TestAuditRulesReadersMatchTheCollector (§4.2, O-3, O-41, O-57): the rules
// bodies read a persisted rules file twice, and the readers compare by exit
// code (0 = present / locked):
//
//	rd_present  inValidate true: the validate repeats it over rules.d. It
//	            exits 0 exactly when parseAuditRules finds a watch or a
//	            syscall rule (auditKind of the getopt-read first option),
//	            so the body writes the floor only where the persisted
//	            clause FAILs and the validate agrees with check after it.
//	rd_lock     inValidate false: a refusal guard the validate never needs.
//	            One-sided: wherever lastEnableValue reads 2 the body reads a
//	            lock; the body also refuses where the collector reads none
//	            (the token later on a line, -e 02 and -e +2, which auditctl
//	            rejects, --loginuid-immutable), the safe direction. Both
//	            bodies carry the same line.
func TestAuditRulesReadersMatchTheCollector(t *testing.T) {
	r := shippedBody(t, "muster.beyond.audit_rules_loaded")
	present := readerLine(t, r, "rd_present", true)
	lock := readerLine(t, r, "rd_lock", false)
	if other := readerLine(t, shippedBody(t, "muster.beyond.auditd_active"), "rd_lock", false); other != lock {
		t.Errorf("the two bodies' rd_lock differ:\n%s\n%s", lock, other)
	}
	rows := []struct {
		name, rules string
		noLock      bool // neither side reads a lock
	}{
		{"glued watch", "-w/etc/passwd -p wa\n", true},
		{"glued syscall", "-aalways,exit -S all\n", true},
		{"spaced watch", "-w /etc/passwd -p wa -k identity\n", true},
		{"indented syscall", "\t  -a always,exit -S execve\n", true},
		{"prepend", "-A exclude,always -F msgtype=CWD\n", true},
		{"commented watch", "# -w /etc/passwd -p wa\n#-a always,exit\n", true},
		{"watch removal", "-W /etc/passwd\n", true},
		{"crlf watch", "-w /etc/passwd -p wa\r\n", true},
		{"glued lock", "-e2\n", false},
		{"two blanks", "-e  2\n", false},
		{"lock with a comment", "-e 2 # c\n", false},
		{"zero-padded", "-e 02\n", false},
		{"signed", "-e +2\n", false},
		{"loginuid lock", "--loginuid-immutable\n", false},
		{"later on the line", "-b 8192 -e 2\n", false},
		{"enable 1", "-e 1\n", true},
		{"enable 0", "-e 0\n", true},
		{"enable 12", "-e 12\n", true},
		{"enable 20", "-e 20\n", true},
		{"backlog", "-b 8192\n", true},
		{"lock then enable", "-e 2\n-e 1\n", false},
	}
	for _, f := range []string{"audit.rules.sample", "audit.rules.d-50-watch.rules", "audit.rules.d-99-finalize.rules"} {
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, struct {
			name, rules string
			noLock      bool
		}{f, string(b), f != "audit.rules.d-99-finalize.rules"})
	}
	const file = "/etc/audit/rules.d/x.rules"
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			rules := parseAuditRules([]byte(row.rules), file)
			n := 0
			for _, x := range rules {
				if x.kind == "watch" || x.kind == "syscall" {
					n++
				}
			}
			files := map[string][]byte{file: []byte(row.rules)}
			if _, code := runReader(t, present, "rd_present {root}"+file, files); (code == 0) != (n > 0) {
				t.Errorf("rd_present exit %d; parseAuditRules finds %d watch or syscall rules", code, n)
			}
			_, code := runReader(t, lock, "rd_lock {root}"+file, files)
			if v, _, found := lastEnableValue(rules); found && v == 2 && code != 0 {
				t.Errorf("lastEnableValue reads the lock and rd_lock exits %d", code)
			}
			if row.noLock && code == 0 {
				t.Errorf("rd_lock reads a lock in %q", row.rules)
			}
			if !row.noLock && code != 0 {
				t.Errorf("rd_lock exit %d over %q, want a lock", code, row.rules)
			}
		})
	}
}

// TestInactivityReadersMatchTheCollector (§4.4, O-38, O-28): the two readers
// of account_inactivity_lock against the collector.
//
//	rd_inactive inValidate true: the validate repeats it over
//	            /etc/default/useradd. It prints the value parseUseraddDefaults
//	            reads (the last column-one INACTIVE= line as C strtol base 0,
//	            digits parsed by hand; -1 for missing, junk or below -1), so
//	            the body rewrites the line exactly where the useradd clauses
//	            FAIL and the validate agrees with check after it.
//	rd_login    inValidate false: the enumeration; the validate reads
//	            inactive.run, the names this run changed. It prints the names
//	            of accounts.login_capable (uid 0 first, then passwd order;
//	            compared sorted, duplicates kept), so the body bounds every
//	            row the field-7 clauses judge and no other.
func TestInactivityReadersMatchTheCollector(t *testing.T) {
	r := shippedBody(t, "muster.beyond.account_inactivity_lock")
	inactive := readerLine(t, r, "rd_inactive", true)
	login := readerLine(t, r, "rd_login", false)

	t.Run("useradd", func(t *testing.T) {
		rows := map[string]string{
			"octal 08":         "INACTIVE=08\n",
			"leading blank":    "INACTIVE= 30\n",
			"leading tab":      "INACTIVE=\t7\n",
			"CR":               "INACTIVE=30\r\n",
			"bare 0x":          "INACTIVE=0x\n",
			"signed bare 0x":   "INACTIVE=+0x\n",
			"junk":             "INACTIVE=abc\n",
			"octal 030":        "INACTIVE=030\n",
			"hex 0x1F":         "INACTIVE=0x1F\n",
			"hex 0X1f":         "INACTIVE=0X1f\n",
			"hex 0x30":         "INACTIVE=0x30\n",
			"below -1":         "INACTIVE=-2\n",
			"-1":               "INACTIVE=-1\n",
			"-0":               "INACTIVE=-0\n",
			"+5":               "INACTIVE=+5\n",
			"zero":             "INACTIVE=0\n",
			"octal 09":         "INACTIVE=09\n",
			"trailing blank":   "INACTIVE=5 \n",
			"digits then junk": "INACTIVE=1a\n",
			"empty value":      "INACTIVE=\n",
			"a later line":     "INACTIVE=10\nGROUP=100\nINACTIVE=20\n",
			"a later bad line": "INACTIVE=07\nINACTIVE=bad\n",
			"indented":         " INACTIVE=5\n",
			"commented":        "# INACTIVE=5\n",
			"no final newline": "INACTIVE=7",
			"empty file":       "",
			"lower case":       "inactive=5\n",
		}
		for _, f := range []string{"useradd.default.35", "useradd.default.el9", "useradd.default.ubuntu"} {
			b, err := os.ReadFile(filepath.Join("testdata", f))
			if err != nil {
				t.Fatal(err)
			}
			rows[f] = string(b)
		}
		names := make([]string, 0, len(rows))
		for n := range rows {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			t.Run(n, func(t *testing.T) {
				want, _ := parseUseraddDefaults([]byte(rows[n]))
				got, code := runReader(t, inactive, "rd_inactive {root}/etc/default/useradd", map[string][]byte{"/etc/default/useradd": []byte(rows[n])})
				if code != 0 || got != strconv.Itoa(want) {
					t.Errorf("rd_inactive %q (exit %d); parseUseraddDefaults reads %d from %q", got, code, want, rows[n])
				}
			})
		}
	})

	t.Run("login", func(t *testing.T) {
		fixture := func(f string) string {
			b, err := os.ReadFile(filepath.Join("testdata", f))
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}
		passwds := map[string]string{
			"inline login": loginPasswd,
			"edges": "root:x:0:0::/root:/bin/bash\r\n" +
				"  #c:x:1:1::/:/bin/sh\n" +
				"#x:x:2000:1::/:/bin/sh\n" +
				"\n   \n" +
				"sp:x: 1500 :1::/:/bin/sh\n" +
				"plus:x:+1:1::/:/bin/sh\n" +
				"plusbig:x:+1001:1::/:/bin/sh\n" +
				"neg:x:-5:1::/:/bin/sh\n" +
				"zerozero:x:00:0::/:/bin/sh\n" +
				"hexuid:x:0x10:1::/:/bin/sh\n" +
				"noshell:x:1600:1::/:\n" +
				"false:x:1700:1::/:/bin/false\n" +
				"nologin:x:1701:1::/:/sbin/nologin\n" +
				"extra:x:1800:1::/:/bin/sh:more\n" +
				":x:1900:1::/:/bin/sh\n" +
				"short:x:2000\n" +
				"padshell:x:2100:1::/: /bin/sh\n" +
				"unlisted:x:2200:1::/:/bin/zsh\n" +
				"sys:x:999:1::/:/bin/sh\n" +
				"edge:x:1000:1::/:/bin/sh\n",
		}
		for _, f := range []string{"passwd", "passwd_2b", "passwd_2b_ghost", "passwd_home", "passwd_home_deep", "passwd_home_nested", "passwd_home_undeclared", "passwd.homes"} {
			passwds[f] = fixture(f)
		}
		shellsSets := map[string]string{
			"shells_2b":   fixture("shells_2b"),
			"shells_home": fixture("shells_home"),
			"EL shape":    loginShellsFile,
			"padded":      "\t/bin/bash \r\n /bin/sh\n#/bin/zsh\n",
		}
		defsSets := map[string]*string{
			"login.defs":         ptr(fixture("login.defs")),
			"login.defs_2b":      ptr(fixture("login.defs_2b")),
			"missing":            nil,
			"500":                ptr("UID_MIN 500\n"),
			"first junk wins":    ptr("UID_MIN abc\nUID_MIN 10\n"),
			"comment, tab, CR":   ptr("#UID_MIN 1\n  UID_MIN\t1500\r\n"),
			"valueless then set": ptr("UID_MIN\nUID_MIN 1001\n"),
			"signed":             ptr("UID_MIN +1001\n"),
			"prefix key":         ptr("UID_MINX 5\nUID_MIN 3\n"),
		}
		for _, pn := range sortedKeys(passwds) {
			for _, sn := range sortedKeys(shellsSets) {
				for _, dn := range sortedKeys(defsSets) {
					t.Run(pn+"/"+sn+"/"+dn, func(t *testing.T) {
						a := &fsAccess{contents: map[string][]byte{
							"/etc/passwd": []byte(passwds[pn]),
							"/etc/shadow": {},
							"/etc/shells": []byte(shellsSets[sn]),
						}}
						files := map[string][]byte{"/etc/passwd": a.contents["/etc/passwd"], "/etc/shells": a.contents["/etc/shells"]}
						defs := "/dev/null"
						if d := defsSets[dn]; d != nil {
							a.contents["/etc/login.defs"] = []byte(*d)
							files["/etc/login.defs"] = []byte(*d)
							defs = "{root}/etc/login.defs"
						}
						var want []string
						for _, row := range okList(t, build(t, "accounts", a), "accounts.login_capable") {
							want = append(want, row.(map[string]any)["name"].(string))
						}
						out, code := runReader(t, login, "rd_login "+defs+" {root}/etc/shells {root}/etc/passwd", files)
						if code != 0 {
							t.Fatalf("rd_login exit %d", code)
						}
						var got []string
						if out != "" {
							got = strings.Split(out, "\n")
						}
						sort.Strings(got)
						sort.Strings(want)
						if strings.Join(got, ",") != strings.Join(want, ",") {
							t.Errorf("rd_login names %v; loginCapable names %v", got, want)
						}
					})
				}
			}
		}
	})
}
