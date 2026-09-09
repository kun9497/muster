//go:build linux

package collectors

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// mailAccess builds the double for the mail collector. Ruling I-20: every
// map a test of this collector reaches into is initialised here — a later
// `a.fails[…] = …`, `a.stats[…] = …` or `a.truncated[…] = …` on a nil map
// panics — and Ruling L-31: `stats` carries `kind: "dir"` for
// /run/systemd/system and `kind: "regular"` for every MTA binary, derived
// from the configuration files the fixture seeds, exactly as loggingAccess
// does.
//
// Ruling L-3: a configuration file names an implementation only when the
// daemon's BINARY is installed too, so a fixture that seeds one seeds the
// other; a test about a conffile left behind by a removed package deletes
// the binary again. The sendmail seed is the /usr/sbin/sendmail-mta
// alternatives symlink rather than sendmail.sendmail, so the anyPresent
// probe of Ruling L-20 is the thing under test.
func mailAccess(files map[string]string) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	stats := map[string]statResult{"/run/systemd/system": {mode: 0o755, kind: "dir"}}
	for p := range files {
		var bin string
		switch p {
		case postfixMainCf:
			bin = postfixBin
		case sendmailCf:
			bin = sendmailMtaBin
		case exim4Conf, eximConf:
			bin = exim4Bin
		default:
			continue
		}
		stats[bin] = statResult{mode: 0o755, kind: "regular"}
	}
	return &fsAccess{
		files:     files,
		cmds:      map[string]cmdResult{},
		fails:     map[string]error{},
		dirs:      map[string]bool{"/run/systemd/system": true},
		stats:     stats,
		truncated: map[string]bool{},
	}
}

// mailPostfixLeaves are the six parameters read out of main.cf; they are
// ABSENT on a host that runs anything else.
var mailPostfixLeaves = []string{
	"mail.postfix.inet_interfaces",
	"mail.postfix.mynetworks",
	"mail.postfix.smtpd_relay_restrictions",
	"mail.postfix.smtpd_recipient_restrictions",
	"mail.postfix.disable_vrfy_command",
	"mail.postfix.authorized_submit_users",
}

// mailJudgedLeaves are the leaves a control judges, as opposed to the
// evidence leaves (implementation, config_files) that stay ok whatever the
// parse found. A read that failed or was cut at the cap makes every one of
// them carry that story.
var mailJudgedLeaves = append(append([]string(nil), mailPostfixLeaves...),
	"mail.sendmail.privacy_options", "mail.expn_vrfy_restricted")

// mailAllLeaves is every key this collector registers. Each is published on
// EVERY path — a host with no MTA included — so a control can never read
// one as missing.
var mailAllLeaves = append([]string{"mail.implementation", "mail.config_files"}, mailJudgedLeaves...)

// mailComplete asserts that every registered key of the collector was
// published, whatever the host turned out to be.
func mailComplete(t *testing.T, b *collect.Builder) {
	t.Helper()
	for _, k := range mailAllLeaves {
		env(t, b, k)
	}
}

// mailString fetches an ok string leaf, reporting the envelope rather than a
// bare mismatch when the collector degraded instead of answering.
func mailString(t *testing.T, b *collect.Builder, key string) string {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v, want an ok string", key, e)
	}
	s, ok := e.Value.(string)
	if !ok {
		t.Fatalf("%s: value %#v is not a string", key, e.Value)
	}
	return s
}

// mailBool fetches an ok bool leaf the same way.
func mailBool(t *testing.T, b *collect.Builder, key string) bool {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v, want an ok bool", key, e)
	}
	v, ok := e.Value.(bool)
	if !ok {
		t.Fatalf("%s: value %#v is not a bool", key, e.Value)
	}
	return v
}

// absentBecause asserts a leaf is absent and that its reason names what the
// reader has to act on.
func absentBecause(t *testing.T, b *collect.Builder, key string, must ...string) {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusAbsent {
		t.Fatalf("%s: %+v, want absent", key, e)
	}
	for _, m := range must {
		if !strings.Contains(e.Reason, m) {
			t.Errorf("%s reason %q must name %q", key, e.Reason, m)
		}
	}
}

// Debian's stock main.cf: inet_interfaces "all", the loopback-only
// mynetworks, and no disable_vrfy_command at all — so the parameter's leaf
// is ABSENT naming postfix's compiled default while expn_vrfy_restricted
// reads false from it.
func TestMailPostfixDebianStock(t *testing.T) {
	a := mailAccess(map[string]string{postfixMainCf: "main.cf.debian"})
	b := buildBegun(t, "mail", a)
	mailComplete(t, b)

	if e := env(t, b, "mail.implementation"); e.Status != facts.StatusOK || e.Value != "postfix" {
		t.Fatalf("implementation %+v, want ok postfix", e)
	}
	if got := stringList(t, b, "mail.config_files"); !slices.Equal(got, []string{postfixMainCf}) {
		t.Errorf("config_files %v, want just the main file", got)
	}
	if got := mailString(t, b, "mail.postfix.inet_interfaces"); got != "all" {
		t.Errorf("inet_interfaces = %q, want all", got)
	}
	if got := mailString(t, b, "mail.postfix.mynetworks"); got != "127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128" {
		t.Errorf("mynetworks = %q, want the stock loopback list", got)
	}
	if got := mailString(t, b, "mail.postfix.smtpd_relay_restrictions"); got != "permit_mynetworks permit_sasl_authenticated defer_unauth_destination" {
		t.Errorf("smtpd_relay_restrictions = %q, want the stock list", got)
	}
	// Every parameter the file does not set is absent with postfix's own
	// compiled default named, never that default published as a value.
	absentBecause(t, b, "mail.postfix.smtpd_recipient_restrictions", "default is empty")
	absentBecause(t, b, "mail.postfix.disable_vrfy_command", "default is no")
	absentBecause(t, b, "mail.postfix.authorized_submit_users", "static:anyone")
	absentBecause(t, b, "mail.sendmail.privacy_options", "postfix")

	if mailBool(t, b, "mail.expn_vrfy_restricted") {
		t.Error("disable_vrfy_command unset is postfix's default no: VRFY is answered")
	}
	if w := b.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}
	// The read guard covers nine paths; only the one that exists is opened.
	// This file names /etc/aliases through alias_maps and alias_database, and
	// neither is followed: a path main.cf mentions is not a path muster reads.
	if !slices.Equal(a.reads, []string{postfixMainCf}) {
		t.Errorf("reads = %v, want only %s", a.reads, postfixMainCf)
	}
}

// A line beginning with whitespace continues the previous value, joined with
// a single space; a later assignment of the same parameter wins; a '#' that
// is not at the start of a line belongs to the value.
//
// The fixture also carries the two cases postconf(5) settles and nothing else
// in the suite reaches: an INDENTED comment between a parameter and its
// continuation (a comment, never part of the value) and a line that is not an
// assignment at all followed by an indented line (which has no parameter left
// to extend). Reading the indented comment as a continuation shows up in
// mynetworks; dropping the "last = \"\"" reset after a non-assignment line
// shows up in inet_interfaces.
func TestMailPostfixContinuationAndLastWins(t *testing.T) {
	b := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.continuation"}))
	mailComplete(t, b)

	for _, c := range []struct{ key, want string }{
		{"mail.postfix.mynetworks", "127.0.0.0/8 198.51.100.0/24 203.0.113.0/24"},
		{"mail.postfix.smtpd_relay_restrictions", "permit_mynetworks, reject_unauth_destination"},
		// Two inet_interfaces lines: the LAST is what postfix uses, and the
		// orphan continuation further down does not extend it.
		{"mail.postfix.inet_interfaces", "loopback-only"},
		{"mail.postfix.smtpd_recipient_restrictions", "check_policy_service unix:private/policy # inline, not a comment"},
	} {
		if got := mailString(t, b, c.key); got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
}

// The other half of the continuation guard: a line beginning with whitespace
// BEFORE any parameter has nothing to extend and must not become a parameter
// of its own. No published leaf can show that — a parameter with an empty
// name is looked up by nobody — so the parse map itself is the assertion.
func TestMailPostfixOrphanContinuationCreatesNoParameter(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "main.cf.continuation"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	got := map[string]string{}
	parsePostfixInto(got, data)
	if v, ok := got[""]; ok {
		t.Errorf("the parse invented a parameter with an empty name = %q", v)
	}
	if got["inet_interfaces"] != "loopback-only" {
		t.Errorf("inet_interfaces = %q, want loopback-only", got["inet_interfaces"])
	}
}

// disable_vrfy_command yes — in any of the spellings postfix accepts —
// restricts VRFY, and postfix implements no EXPN command at all, so that one
// parameter settles the derived leaf. The value is stored verbatim.
func TestMailPostfixVrfyDisabled(t *testing.T) {
	yes := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.vrfy-disabled"}))
	mailComplete(t, yes)
	if got := mailString(t, yes, "mail.postfix.disable_vrfy_command"); got != "YES" {
		t.Errorf("disable_vrfy_command = %q, want the value as written", got)
	}
	if !mailBool(t, yes, "mail.expn_vrfy_restricted") {
		t.Error("disable_vrfy_command = YES must restrict VRFY")
	}
	if got := mailString(t, yes, "mail.postfix.authorized_submit_users"); got != "static:postfix" {
		t.Errorf("authorized_submit_users = %q", got)
	}

	// Ruling LR-8: postfix's mail_conf_bool takes yes or no, case blind, and
	// refuses to start on anything else - "on" included. Reading it as a yes
	// answered VRFY for a host that cannot be running this file at all, so the
	// verdict steps back and names the parameter. The evidence leaf keeps the
	// value as written, which is what tells the operator what to fix.
	on := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.vrfy-on"}))
	absentBecause(t, on, "mail.expn_vrfy_restricted", "disable_vrfy_command", "on")
	if got := mailString(t, on, "mail.postfix.disable_vrfy_command"); got != "on" {
		t.Errorf("disable_vrfy_command = %q, want the value as written", got)
	}
	if w := on.Worst("mail"); w != facts.StatusOK {
		t.Errorf("Worst(mail) = %s, want ok: a file postfix refuses is not a collector error", w)
	}
	// This file sets nothing else, so it is where the unset-parameter branch
	// of smtpd_relay_restrictions is pinned.
	absentBecause(t, on, "mail.postfix.smtpd_relay_restrictions",
		"permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination")

	off := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.relay-open"}))
	if got := mailString(t, off, "mail.postfix.disable_vrfy_command"); got != "no" {
		t.Errorf("disable_vrfy_command = %q, want no", got)
	}
	if mailBool(t, off, "mail.expn_vrfy_restricted") {
		t.Error("disable_vrfy_command = no answers VRFY")
	}
}

// A $name reference is evidence, not a value to resolve: main.cf's own
// expansion depends on parameters this collector does not model, so the
// string is stored exactly as written and the operator reads it.
func TestMailPostfixReferencesAreNotExpanded(t *testing.T) {
	b := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.relay-open"}))
	if got := mailString(t, b, "mail.postfix.smtpd_recipient_restrictions"); got != "$smtpd_relay_restrictions, permit" {
		t.Errorf("smtpd_recipient_restrictions = %q, want the unexpanded reference", got)
	}
	if got := mailString(t, b, "mail.postfix.mynetworks"); got != "0.0.0.0/0" {
		t.Errorf("mynetworks = %q", got)
	}
}

// sendmail: O PrivacyOptions=goaway keeps the literal token AND appends its
// expansion (Ruling L-26), because which flags goaway covers is
// version-dependent; only novrfy and noexpn, present in every version, are
// judged.
func TestMailSendmailPrivacyOptions(t *testing.T) {
	away := buildBegun(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.goaway"}))
	mailComplete(t, away)
	if e := env(t, away, "mail.implementation"); e.Status != facts.StatusOK || e.Value != "sendmail" {
		t.Fatalf("implementation %+v, want ok sendmail", e)
	}
	got := stringList(t, away, "mail.sendmail.privacy_options")
	want := []string{
		"authwarnings", "goaway", "needexpnhelo", "needmailhelo", "needvrfyhelo",
		"nobodyreturn", "noexpn", "noverb", "novrfy",
	}
	if !slices.Equal(got, want) {
		t.Errorf("privacy_options = %v, want %v", got, want)
	}
	if !slices.Contains(got, "goaway") {
		t.Error("the literal goaway token must survive its own expansion")
	}
	if !mailBool(t, away, "mail.expn_vrfy_restricted") {
		t.Error("goaway covers novrfy and noexpn in every version")
	}
	// A sendmail host has no postfix parameters, and saying so is not the
	// same as saying they are empty.
	for _, k := range mailPostfixLeaves {
		absentBecause(t, away, k, "sendmail")
	}
	if w := away.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}

	only := build(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.novrfy-only"}))
	if got := stringList(t, only, "mail.sendmail.privacy_options"); !slices.Equal(got, []string{"authwarnings", "novrfy"}) {
		t.Errorf("privacy_options = %v", got)
	}
	if mailBool(t, only, "mail.expn_vrfy_restricted") {
		t.Error("novrfy alone still answers EXPN")
	}

	// The single-letter option spelling, with whitespace around the list.
	old := build(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.oldform"}))
	if got := stringList(t, old, "mail.sendmail.privacy_options"); !slices.Equal(got, []string{"noexpn", "novrfy"}) {
		t.Errorf("privacy_options = %v, want the OpPrivacyOptions list", got)
	}
	if !mailBool(t, old, "mail.expn_vrfy_restricted") {
		t.Error("noexpn and novrfy together restrict both commands")
	}

	// Ruling L-50: sendmail ORs every PrivacyOptions line into one set, so
	// two lines are a UNION and not a last-one-wins; the separators may be
	// commas or whitespace, and a following indented line continues the value.
	union := build(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.two-lines"}))
	if got := stringList(t, union, "mail.sendmail.privacy_options"); !slices.Equal(got,
		[]string{"authwarnings", "needmailhelo", "noexpn", "novrfy"}) {
		t.Errorf("privacy_options = %v, want the union of both lines", got)
	}
	if !mailBool(t, union, "mail.expn_vrfy_restricted") {
		t.Error("novrfy on one line and noexpn on the next still restrict both")
	}

	// The bare legacy spelling, where the flags follow the option letter.
	legacy := build(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.legacy"}))
	if got := stringList(t, legacy, "mail.sendmail.privacy_options"); !slices.Contains(got, "goaway") {
		t.Errorf("privacy_options = %v, want the Opgoaway flags", got)
	}
	if !mailBool(t, legacy, "mail.expn_vrfy_restricted") {
		t.Error("Opgoaway is goaway, which covers novrfy and noexpn")
	}

	// A line this collector cannot read is not an empty set of flags: both
	// leaves refuse rather than publish a FAIL with an untrue reason.
	bad := buildBegun(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.garbled"}))
	mailComplete(t, bad)
	for _, k := range []string{"mail.sendmail.privacy_options", "mail.expn_vrfy_restricted"} {
		absentBecause(t, bad, k, "confPRIVACY_FLAGS")
	}
	if w := bad.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}

	// A .cf with no PrivacyOptions line at all is an EMPTY list, not an
	// absence: the file was read and it sets nothing.
	none := build(t, "mail", mailAccess(map[string]string{sendmailCf: "sendmail.cf.none"}))
	mailComplete(t, none)
	if got := stringList(t, none, "mail.sendmail.privacy_options"); len(got) != 0 {
		t.Errorf("privacy_options = %v, want an empty list", got)
	}
	if mailBool(t, none, "mail.expn_vrfy_restricted") {
		t.Error("sendmail's compiled default answers both VRFY and EXPN")
	}
}

// exim is named but never parsed: its access control lives in ACLs this
// collector does not model, so the derived leaf is ABSENT rather than a
// guess, and the configuration file is not even opened.
func TestMailEximIsDetectedNotParsed(t *testing.T) {
	a := mailAccess(map[string]string{exim4Conf: "exim4.conf.conf"})
	b := buildBegun(t, "mail", a)
	mailComplete(t, b)

	if e := env(t, b, "mail.implementation"); e.Status != facts.StatusOK || e.Value != "exim" {
		t.Fatalf("implementation %+v, want ok exim", e)
	}
	if got := stringList(t, b, "mail.config_files"); !slices.Equal(got, []string{exim4Conf}) {
		t.Errorf("config_files %v, want the file that named the implementation", got)
	}
	for _, k := range mailPostfixLeaves {
		absentBecause(t, b, k, "exim")
	}
	absentBecause(t, b, "mail.sendmail.privacy_options", "exim")
	absentBecause(t, b, "mail.expn_vrfy_restricted", "ACL")
	if len(a.reads) != 0 {
		t.Errorf("reads = %v, want none: the exim configuration is not parsed", a.reads)
	}
	if w := b.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}
}

// A main.cf without /usr/sbin/postfix is a removed package's leftover, not a
// mail server (Ruling L-3); a host with no MTA at all answers every leaf
// with an absence naming the candidates; an unreadable main.cf is DENIED on
// every value it could have set (C3); a read cut at the cap is not evidence
// for anything past the cap.
func TestMailImplementationAndDegradation(t *testing.T) {
	leftover := mailAccess(map[string]string{postfixMainCf: "main.cf.debian"})
	delete(leftover.stats, postfixBin)
	lb := buildBegun(t, "mail", leftover)
	mailComplete(t, lb)
	e := env(t, lb, "mail.implementation")
	if e.Status != facts.StatusOK || e.Value != "none" {
		t.Fatalf("implementation %+v, want ok none for a conffile with no binary", e)
	}
	if !strings.Contains(e.Reason, postfixMainCf) || !strings.Contains(e.Reason, postfixBin) {
		t.Errorf("implementation reason %q must name the leftover file and the missing binary", e.Reason)
	}
	for _, k := range mailJudgedLeaves {
		absentBecause(t, lb, k, postfixMainCf)
	}

	bare := buildBegun(t, "mail", mailAccess(nil))
	mailComplete(t, bare)
	if e := env(t, bare, "mail.implementation"); e.Status != facts.StatusOK || e.Value != "none" {
		t.Fatalf("implementation %+v, want ok none", e)
	}
	if got := stringList(t, bare, "mail.config_files"); len(got) != 0 {
		t.Errorf("config_files = %v, want an empty list", got)
	}
	for _, k := range mailJudgedLeaves {
		absentBecause(t, bare, k, postfixMainCf, sendmailCf, exim4Conf)
	}
	if w := bare.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok on a host with no MTA`, w)
	}

	denied := mailAccess(map[string]string{postfixMainCf: "main.cf.debian"})
	denied.fails[postfixMainCf] = unix.EACCES
	db := buildBegun(t, "mail", denied)
	mailComplete(t, db)
	if e := env(t, db, "mail.implementation"); e.Status != facts.StatusOK || e.Value != "postfix" {
		t.Fatalf("implementation %+v: an unreadable main.cf is still a postfix host", e)
	}
	for _, k := range mailJudgedLeaves {
		e := env(t, db, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s = %s, want denied", k, e.Status)
		}
		if !strings.Contains(e.Reason, postfixMainCf) {
			t.Errorf("%s reason %q must name the file that could not be read", k, e.Reason)
		}
	}
	// Ruling L-49: the file is THERE and could not be opened, which is not the
	// same finding as "this host has no mail configuration at all".
	cf := env(t, db, "mail.config_files")
	if cf.Status != facts.StatusDenied {
		t.Errorf("config_files %+v, want denied rather than an empty list", cf)
	}
	if !strings.Contains(cf.Reason, postfixMainCf) {
		t.Errorf("config_files reason %q must name the file", cf.Reason)
	}
	if w := db.Worst("mail"); w != facts.StatusDenied {
		t.Errorf(`Worst("mail") = %s, want denied`, w)
	}

	cut := mailAccess(map[string]string{postfixMainCf: "main.cf.debian"})
	cut.truncated[postfixMainCf] = true
	cb := buildBegun(t, "mail", cut)
	mailComplete(t, cb)
	for _, k := range mailJudgedLeaves {
		absentBecause(t, cb, k, postfixMainCf)
	}
	if e := env(t, cb, "mail.config_files"); !e.Truncated {
		t.Errorf("config_files %+v must carry the truncation", e)
	}
}

// Two MTAs installed at once (RHEL installs postfix and sendmail side by
// side under alternatives): the first in the fixed order answers the evidence
// leaves and the other is named in the implementation's reason, but the
// DERIVED verdict is refused — which of the two serves port 25 is decided by
// the enabled unit, not by this collector's probe order, so a hardened
// postfix beside a permissive sendmail must never read PASS (Ruling L-48).
// The second configuration is still never opened.
func TestMailSecondImplementationIsNamedNotJudged(t *testing.T) {
	a := mailAccess(map[string]string{
		postfixMainCf: "main.cf.debian",
		sendmailCf:    "sendmail.cf.goaway",
	})
	b := buildBegun(t, "mail", a)
	mailComplete(t, b)

	e := env(t, b, "mail.implementation")
	if e.Status != facts.StatusOK || e.Value != "postfix" {
		t.Fatalf("implementation %+v, want ok postfix (first in the fixed order)", e)
	}
	if !strings.Contains(e.Reason, "sendmail") || !strings.Contains(e.Reason, sendmailCf) {
		t.Errorf("implementation reason %q must name the other MTA on the host", e.Reason)
	}
	// The sendmail leaf is not answered from a file this host does not run.
	absentBecause(t, b, "mail.sendmail.privacy_options", "postfix")
	// The verdict names BOTH families rather than describing one of them.
	absentBecause(t, b, "mail.expn_vrfy_restricted", "postfix", "sendmail", sendmailCf)
	// The evidence leaves are still the parsed ones.
	if got := mailString(t, b, "mail.postfix.inet_interfaces"); got != "all" {
		t.Errorf("inet_interfaces = %q, want the parsed value", got)
	}
	if w := b.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}
	if !slices.Equal(a.reads, []string{postfixMainCf}) {
		t.Errorf("reads = %v, want only the chosen implementation's file", a.reads)
	}
	if got := stringList(t, b, "mail.config_files"); !slices.Equal(got, []string{postfixMainCf}) {
		t.Errorf("config_files %v", got)
	}
}

// A value longer than this collector stores is refused rather than copied
// into the snapshot (M16): the reason names the limit, never the value.
func TestMailOversizedValueIsNotStored(t *testing.T) {
	b := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.oversized"}))
	mailComplete(t, b)

	e := env(t, b, "mail.postfix.mynetworks")
	if e.Status != facts.StatusAbsent {
		t.Fatalf("mynetworks %+v, want absent for an oversized value", e)
	}
	if strings.Contains(e.Reason, "192.0.2.0") {
		t.Errorf("mynetworks reason %q must not carry the value it refused", e.Reason)
	}
	// The rest of the file is still evidence.
	if got := mailString(t, b, "mail.postfix.inet_interfaces"); got != "all" {
		t.Errorf("inet_interfaces = %q, want all", got)
	}
}

// The M16 cap reaches the DERIVED verdict too. When disable_vrfy_command is
// itself longer than a value this collector stores, the parameter leaf refuses
// it — and the verdict must refuse it as well, because postfixYes() of a value
// nobody looked at is not "the compiled default", it is a guess that reads
// ok:false on a host whose main.cf may well say yes.
func TestMailOversizedVrfyParameterRefusesTheVerdict(t *testing.T) {
	b := build(t, "mail", mailAccess(map[string]string{postfixMainCf: "main.cf.oversized-vrfy"}))
	mailComplete(t, b)

	for _, k := range []string{"mail.postfix.disable_vrfy_command", "mail.expn_vrfy_restricted"} {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s = %+v, want absent for an oversized value", k, e)
		}
		if !strings.Contains(e.Reason, "disable_vrfy_command") {
			t.Errorf("%s reason %q must name the parameter it refused", k, e.Reason)
		}
		if strings.Contains(e.Reason, "yes yes") {
			t.Errorf("%s reason %q must not carry the value it refused", k, e.Reason)
		}
	}
	// The rest of the file is still evidence.
	if got := mailString(t, b, "mail.postfix.inet_interfaces"); got != "all" {
		t.Errorf("inet_interfaces = %q, want all", got)
	}
}

// A leftover conffile is reported even when ANOTHER MTA answered the facts.
// RHEL carries postfix and sendmail side by side, and a third package removed
// with `rpm -e` leaves its configuration behind; the implementation's reason
// has to carry BOTH notes, or the operator is shown the MTA to reconcile and
// never the stale file to purge (IR-7).
func TestMailLeftoverIsNamedBesideASecondMTA(t *testing.T) {
	a := mailAccess(map[string]string{
		postfixMainCf: "main.cf.debian",
		sendmailCf:    "sendmail.cf.goaway",
		exim4Conf:     "exim4.conf.conf",
	})
	// exim's package was removed; its configuration file stayed behind.
	delete(a.stats, exim4Bin)
	b := buildBegun(t, "mail", a)
	mailComplete(t, b)

	e := env(t, b, "mail.implementation")
	if e.Status != facts.StatusOK || e.Value != "postfix" {
		t.Fatalf("implementation %+v, want ok postfix (first in the fixed order)", e)
	}
	for _, want := range []string{"sendmail", sendmailCf, exim4Conf, exim4Bin, "removed package"} {
		if !strings.Contains(e.Reason, want) {
			t.Errorf("implementation reason %q must name %q: the second MTA AND the leftover", e.Reason, want)
		}
	}
	// Neither of the other two files was opened, and the leftover is not
	// evidence for anything: it is a file to delete.
	if !slices.Equal(a.reads, []string{postfixMainCf}) {
		t.Errorf("reads = %v, want only the chosen implementation's file", a.reads)
	}
	if got := stringList(t, b, "mail.config_files"); !slices.Equal(got, []string{postfixMainCf}) {
		t.Errorf("config_files %v, want only the file that was read", got)
	}
	// A second MTA still refuses the derived verdict (Ruling L-48).
	absentBecause(t, b, "mail.expn_vrfy_restricted", "postfix", "sendmail")
	if w := b.Worst("mail"); w != facts.StatusOK {
		t.Errorf(`Worst("mail") = %s, want ok`, w)
	}
}

// Ruling LR-12: the emission set is driven by the REGISTRY, not by a list this
// file keeps in step by hand — a key added to registry.yaml and never
// published would otherwise reach a control as `missing` → ERROR(missing_fact).
func TestMailPublishesEveryRegisteredKeyOnAHostWithNoMta(t *testing.T) {
	b := buildBegun(t, "mail", mailAccess(nil))
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, k := range reg.Keys {
		if k.Collector != "mail" {
			continue
		}
		n++
		if s := env(t, b, k.Key).Status; s != facts.StatusOK && s != facts.StatusAbsent {
			t.Errorf("%s = %s, want ok or absent on a host with no MTA", k.Key, s)
		}
	}
	if n == 0 {
		t.Fatal("the registry declares no mail keys, so this test would pass vacuously")
	}
	if w := b.Worst("mail"); w != facts.StatusOK {
		t.Errorf("Worst(mail) = %s, want ok", w)
	}
}
