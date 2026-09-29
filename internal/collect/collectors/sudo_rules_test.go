package collectors

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// P-2: the sudoers user specifications, aliases and Defaults scopes, read to
// the grammar of sudoers(5). These tests are pure Go and run on every
// platform; the collector's leaves are tested in files_sudo_test.go.

// mainSudoers is /etc/sudoers; the collector's constant has a build tag.
const mainSudoers = "/etc/sudoers"

func sudoSeed(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// ruleText is one rule as a line a failure message can show and a test can
// compare: principal kind negated runas nopasswd [commands] resolved.
func ruleText(r sudoRule) string {
	return fmt.Sprintf("%s %s neg=%t runas=%q nopasswd=%t %q resolved=%t",
		r.Principal, r.Kind, r.Negated, r.Runas, r.NoPasswd, r.Commands, r.Resolved)
}

func rulesText(rules []sudoRule) []string {
	out := []string{}
	for _, r := range rules {
		out = append(out, ruleText(r))
	}
	return out
}

func resolveOne(t *testing.T, data, p string) ([]sudoRule, int) {
	t.Helper()
	return resolveRules([]sudoersFile{parseSudoers([]byte(data), p)})
}

func wantRules(t *testing.T, got []sudoRule, want []string) {
	t.Helper()
	if g := rulesText(got); !reflect.DeepEqual(g, want) {
		t.Errorf("rules\n got %q\nwant %q", g, want)
	}
}

func wantStrings(t *testing.T, what string, got, want []string) {
	t.Helper()
	if got == nil {
		got = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %q, want %q", what, got, want)
	}
}

func TestParseSudoersUbuntuStock(t *testing.T) {
	f := parseSudoers(sudoSeed(t, "sudoers.ubuntu"), mainSudoers)
	rules, unresolved := resolveRules([]sudoersFile{f})
	wantRules(t, rules, []string{
		`root user neg=false runas="(ALL:ALL)" nopasswd=false ["ALL"] resolved=true`,
		`%admin group neg=false runas="(ALL)" nopasswd=false ["ALL"] resolved=true`,
		`%sudo group neg=false runas="(ALL:ALL)" nopasswd=false ["ALL"] resolved=true`,
	})
	for _, r := range rules {
		if r.File != mainSudoers || r.Line == 0 {
			t.Errorf("%s: file %q line %d", ruleText(r), r.File, r.Line)
		}
	}
	if unresolved != 0 {
		t.Errorf("unresolved %d, want 0", unresolved)
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{})
	if authenticateDisabled([]sudoersFile{f}) {
		t.Error("authenticate_disabled true on the stock file")
	}
	// The seven commented "#Defaults:%sudo env_keep" lines are comments.
	for _, d := range f.Defaults {
		if d.Scope != 0 {
			t.Errorf("a scoped Defaults at line %d: %+v", d.Line, d)
		}
	}
	if len(f.Defaults) != 4 {
		t.Errorf("%d Defaults lines, want 4", len(f.Defaults))
	}
}

func TestParseSudoersEL9Stock(t *testing.T) {
	f := parseSudoers(sudoSeed(t, "sudoers.el9"), mainSudoers)
	rules, unresolved := resolveRules([]sudoersFile{f})
	// The commented "# %wheel ALL=(ALL) NOPASSWD: ALL" is not a rule.
	wantRules(t, rules, []string{
		`root user neg=false runas="(ALL)" nopasswd=false ["ALL"] resolved=true`,
		`%wheel group neg=false runas="(ALL)" nopasswd=false ["ALL"] resolved=true`,
	})
	if unresolved != 0 {
		t.Errorf("unresolved %d", unresolved)
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{})
	if authenticateDisabled([]sudoersFile{f}) {
		t.Error("authenticate_disabled true on the stock EL9 file")
	}
	if len(f.Includes) != 1 {
		t.Errorf("includes %v, want the one #includedir line", f.Includes)
	}
}

func TestParseSudoersCloudInit(t *testing.T) {
	p := "/etc/sudoers.d/90-cloud-init-users"
	rules, unresolved := resolveRules([]sudoersFile{parseSudoers(sudoSeed(t, "sudoers_d.90-cloud-init-users"), p)})
	wantRules(t, rules, []string{`ubuntu user neg=false runas="(ALL)" nopasswd=true ["ALL"] resolved=true`})
	if unresolved != 0 || rules[0].File != p || rules[0].Line != 4 {
		t.Errorf("unresolved %d, rule %+v", unresolved, rules[0])
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"ubuntu"})
}

func TestParseSudoersAliases(t *testing.T) {
	f := parseSudoers(sudoSeed(t, "sudoers.aliases"), mainSudoers)
	rules, unresolved := resolveRules([]sudoersFile{f})
	wantRules(t, rules, []string{
		`millert user neg=false runas="" nopasswd=true ["ALL"] resolved=true`,
		`mikef user neg=false runas="" nopasswd=true ["ALL"] resolved=true`,
		`dowdy user neg=false runas="" nopasswd=true ["ALL"] resolved=true`,
		`%opers group neg=false runas="(:adm,oper)" nopasswd=false ["/usr/sbin/"] resolved=true`,
		`bob user neg=false runas="(root,operator)" nopasswd=false ["ALL"] resolved=true`,
		`bob user neg=false runas="(root,operator)" nopasswd=false ["ALL"] resolved=true`,
	})
	if unresolved != 0 {
		t.Errorf("unresolved %d", unresolved)
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"dowdy", "mikef", "millert"})
	// Defaults:FULLTIMERS sets lecture and runchroot, not authenticate.
	if authenticateDisabled([]sudoersFile{f}) {
		t.Error("Defaults:FULLTIMERS !lecture read as !authenticate")
	}
	scopes := ""
	for _, d := range f.Defaults {
		scopes += string(rune(d.Scope)) + d.Target + ";"
	}
	if scopes != ":FULLTIMERS;@SERVERS;!PAGERS;" {
		t.Errorf("Defaults scopes %q", scopes)
	}
	if got := f.Aliases["User_Alias"]["FULLTIMERS"]; !reflect.DeepEqual(got, []string{"millert", "mikef", "dowdy"}) {
		t.Errorf("FULLTIMERS = %q", got)
	}
}

func TestParseSudoersCmndAliasTags(t *testing.T) {
	rules, unresolved := resolveRules([]sudoersFile{parseSudoers(sudoSeed(t, "sudoers.cmndalias"), mainSudoers)})
	// The row records the whole privilege: nopasswd is true because some
	// command of it carries NOPASSWD. nopasswd_all asks the narrower
	// question — does ALL itself carry the tag — and here no ALL is granted.
	wantRules(t, rules, []string{
		`%deploy group neg=false runas="(root)" nopasswd=true ["/usr/bin/systemctl restart nginx" "/usr/bin/systemctl reload nginx" "/usr/bin/journalctl"] resolved=true`,
	})
	if unresolved != 0 {
		t.Errorf("unresolved %d", unresolved)
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{})

	// The ALL of a privilege whose NOPASSWD was overridden before it is not
	// passwordless, although the row is.
	rules, _ = resolveOne(t, "carol ALL = NOPASSWD: /bin/a, PASSWD: ALL\n", mainSudoers)
	wantRules(t, rules, []string{`carol user neg=false runas="" nopasswd=true ["/bin/a" "ALL"] resolved=true`})
	wantStrings(t, "nopasswd_all after PASSWD", nopasswdAll(rules), []string{})
	// ALL reached through a Cmnd_Alias under NOPASSWD is.
	rules, _ = resolveOne(t, "Cmnd_Alias EVERY = ALL\ndave ALL = NOPASSWD: EVERY\n", mainSudoers)
	wantStrings(t, "nopasswd_all through a Cmnd_Alias", nopasswdAll(rules), []string{"dave"})
}

// Review Focus 1: ":" starts a privilege afresh — runas and tags reset.
func TestParseSudoersPrivilegeSeparatorResetsTags(t *testing.T) {
	rules, _ := resolveOne(t, "alice ALL = NOPASSWD: /bin/a : ALL = /bin/b\n", mainSudoers)
	wantRules(t, rules, []string{
		`alice user neg=false runas="" nopasswd=true ["/bin/a"] resolved=true`,
		`alice user neg=false runas="" nopasswd=false ["/bin/b"] resolved=true`,
	})
	rules, _ = resolveOne(t, "alice ALL = (root) NOPASSWD: ALL : ALL = ALL\n", mainSudoers)
	wantRules(t, rules, []string{
		`alice user neg=false runas="(root)" nopasswd=true ["ALL"] resolved=true`,
		`alice user neg=false runas="" nopasswd=false ["ALL"] resolved=true`,
	})
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"alice"})
}

func TestParseSudoersRunasInheritance(t *testing.T) {
	rules, _ := resolveOne(t, "dgb\tboulder = (operator) /bin/ls, (root) /bin/kill, /usr/bin/lprm\n", mainSudoers)
	wantRules(t, rules, []string{
		`dgb user neg=false runas="(operator)" nopasswd=false ["/bin/ls"] resolved=true`,
		`dgb user neg=false runas="(root)" nopasswd=false ["/bin/kill" "/usr/bin/lprm"] resolved=true`,
	})
	// Tags persist too: both commands run without a password.
	rules, _ = resolveOne(t, "ray rushmore = (root) NOPASSWD: /bin/a, /bin/b\n", mainSudoers)
	wantRules(t, rules, []string{`ray user neg=false runas="(root)" nopasswd=true ["/bin/a" "/bin/b"] resolved=true`})
}

func TestParseSudoersNegationKeepsAll(t *testing.T) {
	rules, _ := resolveOne(t, "bob ALL = (ALL:ALL) NOPASSWD: ALL, !/usr/bin/su\n", mainSudoers)
	wantRules(t, rules, []string{`bob user neg=false runas="(ALL:ALL)" nopasswd=true ["ALL" "!/usr/bin/su"] resolved=true`})
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"bob"})
	// A negated ALL grants nothing; root and #0 are never listed; a negated
	// principal is not a grant.
	rules, _ = resolveOne(t, "eve ALL = NOPASSWD: !ALL\nroot ALL = NOPASSWD: ALL\n#0 ALL = NOPASSWD: ALL\nALL, !frank ALL = NOPASSWD: ALL\n", mainSudoers)
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"ALL"})
	if len(rules) != 5 || !rules[4].Negated || rules[4].Principal != "frank" {
		t.Errorf("rules %q", rulesText(rules))
	}
}

func TestParseSudoersPrincipalKinds(t *testing.T) {
	for _, c := range []struct {
		data, principal, kind string
		resolved              bool
		nopasswdAll           []string
	}{
		{"ALL ALL = NOPASSWD: ALL\n", "ALL", "all", true, []string{"ALL"}},
		{"#1000 ALL = ALL\n", "#1000", "uid", true, []string{}},
		{"%#27 ALL = ALL\n", "%#27", "gid", true, []string{}},
		{"+admins ALL = ALL\n", "+admins", "netgroup", false, []string{}},
		{`"%:Domain Admins" ALL = ALL` + "\n", "%:Domain Admins", "nonunix", false, []string{}},
		{`%:Domain\ Admins ALL = ALL` + "\n", "%:Domain Admins", "nonunix", false, []string{}},
		{"%:#1234 ALL = ALL\n", "%:#1234", "nonunix", false, []string{}},
		{"!!alice ALL = ALL\n", "alice", "user", true, []string{}},
		{"#1000 ALL = NOPASSWD: ALL\n", "#1000", "uid", true, []string{"#1000"}},
	} {
		rules, unresolved := resolveOne(t, c.data, mainSudoers)
		if len(rules) != 1 {
			t.Errorf("%q: rules %q", c.data, rulesText(rules))
			continue
		}
		r := rules[0]
		if r.Principal != c.principal || r.Kind != c.kind || r.Resolved != c.resolved || r.Negated {
			t.Errorf("%q: %s", c.data, ruleText(r))
		}
		if want := map[bool]int{true: 0, false: 1}[c.resolved]; unresolved != want {
			t.Errorf("%q: unresolved %d, want %d", c.data, unresolved, want)
		}
		wantStrings(t, c.data+" nopasswd_all", nopasswdAll(rules), c.nopasswdAll)
	}
}

// The logical line is joined before it is classified, so a uid line that
// continues is a rule; a "#" followed by a digit is a uid token even when a
// person meant a comment (sudo's own rule): with an "=" it is a rule that
// fails to parse, without one it is dropped.
func TestParseSudoersUidContinuation(t *testing.T) {
	rules, unresolved := resolveOne(t, "#1000 ALL = \\\n  NOPASSWD: ALL\n", mainSudoers)
	wantRules(t, rules, []string{`#1000 uid neg=false runas="" nopasswd=true ["ALL"] resolved=true`})
	if unresolved != 0 || rules[0].Line != 1 {
		t.Errorf("unresolved %d line %d", unresolved, rules[0].Line)
	}

	rules, unresolved = resolveOne(t, "#1 first rule: a=b\n", mainSudoers)
	wantRules(t, rules, []string{`#1 uid neg=false runas="" nopasswd=false [] resolved=false`})
	if unresolved != 1 {
		t.Errorf("a malformed uid rule: unresolved %d, want 1", unresolved)
	}
	rules, unresolved = resolveOne(t, "#1 first rule\n# 2 is a comment = yes\n#another = one\n", mainSudoers)
	if len(rules) != 0 || unresolved != 0 {
		t.Errorf("comments read as rules: %q (%d)", rulesText(rules), unresolved)
	}
	// A comment that continues swallows the next line; a quoted "#" is text.
	rules, _ = resolveOne(t, "# note \\\nalice ALL = ALL\nbob ALL = /bin/echo \"#x\"\n", mainSudoers)
	wantRules(t, rules, []string{`bob user neg=false runas="" nopasswd=false ["/bin/echo #x"] resolved=true`})
	if rules[0].Line != 3 {
		t.Errorf("line %d, want 3", rules[0].Line)
	}
}

func TestResolveRulesDepthAndCycles(t *testing.T) {
	rules, unresolved := resolveOne(t, "User_Alias A = B\nUser_Alias B = A\nA ALL = NOPASSWD: ALL\n", mainSudoers)
	if unresolved != 1 || len(rules) != 1 || rules[0].Resolved || rules[0].Kind != "alias" {
		t.Errorf("cycle: %q (%d)", rulesText(rules), unresolved)
	}
	if got := unresolvedNames(rules); !reflect.DeepEqual(got, []string{"A"}) {
		t.Errorf("cycle names %q", got)
	}
	rules, unresolved = resolveOne(t, "NOBODY ALL = ALL\n", mainSudoers)
	if unresolved != 1 || rules[0].Principal != "NOBODY" || rules[0].Kind != "alias" || rules[0].Resolved {
		t.Errorf("undefined: %q (%d)", rulesText(rules), unresolved)
	}
	chain := func(n int) string {
		var b strings.Builder
		for i := 1; i < n; i++ {
			fmt.Fprintf(&b, "User_Alias A%d = A%d\n", i, i+1)
		}
		fmt.Fprintf(&b, "User_Alias A%d = zed\nA1 ALL = NOPASSWD: ALL\n", n)
		return b.String()
	}
	rules, unresolved = resolveOne(t, chain(8), mainSudoers)
	if unresolved != 0 || len(rules) != 1 || rules[0].Principal != "zed" {
		t.Errorf("depth 8: %q (%d)", rulesText(rules), unresolved)
	}
	rules, unresolved = resolveOne(t, chain(9), mainSudoers)
	if unresolved != 1 || rules[0].Resolved {
		t.Errorf("depth 9: %q (%d)", rulesText(rules), unresolved)
	}
	// Aliases that multiply each other stop at the expansion budget, and a
	// principal named twice is one row.
	var mult strings.Builder
	for i := 1; i < 8; i++ {
		fmt.Fprintf(&mult, "User_Alias M%d = M%d, M%d, M%d, M%d, M%d, M%d\n", i, i+1, i+1, i+1, i+1, i+1, i+1)
	}
	mult.WriteString("User_Alias M8 = zed\nM1 ALL = NOPASSWD: ALL\n")
	rules, unresolved = resolveOne(t, mult.String(), mainSudoers)
	if unresolved == 0 || len(rules) > 16 {
		t.Errorf("multiplying aliases: %d rules, %d unresolved", len(rules), unresolved)
	}
	rules, unresolved = resolveOne(t, "User_Alias T = zed, zed\nT, zed ALL = ALL\n", mainSudoers)
	if len(rules) != 1 || unresolved != 0 {
		t.Errorf("a principal named twice: %q", rulesText(rules))
	}
	// Past the row budget the last row says the rest was not read.
	var wide strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&wide, "u%d,", i)
	}
	wide.WriteString("v h = /a")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&wide, " : h = /b%d", i)
	}
	rules, unresolved = resolveOne(t, wide.String()+"\n", mainSudoers)
	if len(rules) != sudoRowBudget+1 || unresolved != 1 || rules[len(rules)-1].Resolved {
		t.Errorf("row budget: %d rules, %d unresolved", len(rules), unresolved)
	}
	if got := unresolvedNames(rules); !reflect.DeepEqual(got, []string{"the rules past 65536"}) {
		t.Errorf("row budget names %q", got)
	}
	// An undefined Cmnd_Alias or Runas_Alias leaves the row unresolved: what
	// it grants is unknown.
	rules, unresolved = resolveOne(t, "alice ALL = NOPASSWD: MYSTERY\nbob ALL = (WHO) ALL\n", mainSudoers)
	if unresolved != 2 || rules[0].Resolved || rules[1].Resolved {
		t.Errorf("undefined command/runas alias: %q (%d)", rulesText(rules), unresolved)
	}
	if got := unresolvedNames(rules); !reflect.DeepEqual(got, []string{"MYSTERY", "WHO"}) {
		t.Errorf("names %q", got)
	}
	// Aliases resolve across files, and a negated alias negates its members.
	rules, unresolved = resolveRules([]sudoersFile{
		parseSudoers([]byte("User_Alias ADMINS = %admins, !mallory\n"), mainSudoers),
		parseSudoers([]byte("ADMINS ALL = NOPASSWD: ALL\n"), "/etc/sudoers.d/10"),
	})
	wantRules(t, rules, []string{
		`%admins group neg=false runas="" nopasswd=true ["ALL"] resolved=true`,
		`mallory user neg=true runas="" nopasswd=true ["ALL"] resolved=true`,
	})
	if unresolved != 0 || rules[0].File != "/etc/sudoers.d/10" {
		t.Errorf("cross-file: %d %+v", unresolved, rules[0])
	}
	wantStrings(t, "nopasswd_all", nopasswdAll(rules), []string{"%admins"})
}

func TestAuthenticateDisabledScopes(t *testing.T) {
	for _, c := range []struct {
		data   string
		want   bool
		scoped int
	}{
		{"Defaults !authenticate\n", true, 0},
		{"Defaults\t!authenticate\n", true, 0},
		{"Defaults:alice !authenticate\n", true, 1},
		{"Defaults>root !authenticate\n", true, 1},
		{"Defaults>ALL env_reset, !authenticate\n", true, 1},
		{"Defaults@web !authenticate\n", false, 1},
		{"Defaults!/bin/ls !authenticate\n", false, 1},
		{"Defaults !authenticate\nDefaults authenticate\n", false, 0},
		{"Defaults:alice !authenticate\nDefaults:alice authenticate\n", false, 2},
		{"Defaults authenticate\nDefaults:alice !authenticate\n", true, 1},
		{"Defaults !!authenticate\n", false, 0},
		{"Defaults env_reset\n", false, 0},
		{"# Defaults !authenticate\n", false, 0},
	} {
		f := parseSudoers([]byte(c.data), mainSudoers)
		if got := authenticateDisabled([]sudoersFile{f}); got != c.want {
			t.Errorf("%q: authenticate_disabled %t, want %t", c.data, got, c.want)
		}
		// The scopes this parser records are the ones sudo.defaults.scoped_count
		// counts (TestSudoRuleFacts checks the leaf itself).
		scoped := 0
		for _, d := range f.Defaults {
			if d.Scope != 0 {
				scoped++
			}
		}
		if scoped != c.scoped {
			t.Errorf("%q: scoped_count %d, want %d", c.data, scoped, c.scoped)
		}
	}
	// Later wins across files, in the order given.
	files := []sudoersFile{
		parseSudoers([]byte("Defaults !authenticate\n"), "/etc/sudoers.d/10"),
		parseSudoers([]byte("Defaults authenticate\n"), mainSudoers),
	}
	if authenticateDisabled(files) {
		t.Error("a later file's authenticate did not win")
	}
}
