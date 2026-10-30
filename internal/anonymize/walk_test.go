package anonymize

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func ip4(a, b, c, d byte) string { return netip.AddrFrom4([4]byte{a, b, c, d}).String() }

// testTable is a hand-built table in the spelling Task 5 fills: header rows by
// document path, fact rows by (registry key, value-relative field path), and
// the generic envelope, setting and Source rule sets.
func testTable() Table {
	whitespace := func(rest Class, toks ...Class) *Grammar {
		return &Grammar{Split: SplitWhitespace, Tokens: toks, Rest: rest}
	}
	return Table{
		"schema_version":           {Class: ClassKept},
		"synthetic":                {Class: ClassKept},
		"_expect.*":                {Class: ClassKept},
		"_notes":                   {Class: ClassPlaceholder},
		"run.muster_version":       {Class: ClassKept},
		"run.collected_at":         {Class: ClassKept},
		"run.host.hostname":        {Class: ClassHost},
		"run.host.machine_id_hash": {Class: ClassMachineID},
		"run.host.boot_id":         {Class: ClassBlank},
		"run.host.uptime_s":        {Class: ClassBlank},
		"run.collectors":           {Order: OrderKept},
		"run.collectors[].name":    {Class: ClassKept},
		"run.collectors[].reason":  {Class: ClassPlaceholder},
		"run.partial_failures":     {Order: OrderKept},
		"run.partial_failures[]":   {Class: ClassPlaceholder},

		"envelope.status":    {Class: ClassKept},
		"envelope.value":     {},
		"envelope.source":    {},
		"envelope.truncated": {Class: ClassKept},
		"envelope.reason":    {Class: ClassPlaceholder},
		"setting.runtime":    {},
		"setting.persisted":  {},
		"setting.effective":  {},
		"setting.winner":     {},
		"setting.personas":   {},
		"source.kind":        {Class: ClassKept},
		"source.path":        {Class: ClassPath},
		"source.line":        {Class: ClassKept},
		"source.raw":         {Class: ClassPlaceholder},
		"source.cmd":         {Class: ClassPlaceholder},
		"source.exit_code":   {Class: ClassKept},
		"source.inputs":      {},

		"accounts.users":                 {Order: OrderKept},
		"accounts.users[].name":          {Class: ClassAccount},
		"accounts.users[].uid":           {Class: ClassKept},
		"accounts.users[].home":          {Class: ClassPath, Home: true},
		"accounts.lastlog":               {Order: OrderSorted, Sort: &SortSpec{Keys: []SortKey{{Field: "name"}}}},
		"accounts.lastlog[].name":        {Class: ClassAccount},
		"accounts.lastlog[].host":        {Class: ClassHostOrAddr},
		"accounts.uids":                  {Order: OrderSorted, Sort: &SortSpec{Keys: []SortKey{{Numeric: true}}, Dedup: true}},
		"accounts.uids[]":                {Class: ClassKept},
		"sudo.principals":                {Order: OrderKept},
		"sudo.principals[]":              {Class: ClassAccount},
		"pam.mode":                       {Class: ClassKept},
		"files.etc_hosts_equiv_lines":    {Order: OrderKept},
		"files.etc_hosts_equiv_lines[]":  {Class: ClassGrammar, Grammar: whitespace(ClassPlaceholder, ClassHostOrNetgroup, ClassAccount)},
		"files.etc_securetty_lines":      {Order: OrderKept},
		"files.etc_securetty_lines[]":    {Class: ClassGrammar, Grammar: whitespace(ClassKept, ClassKept)},
		"time_sync.servers":              {Order: OrderKept},
		"time_sync.servers[]":            {Class: ClassHostOrAddr},
		"logging.journal_upload.url":     {Class: ClassURL},
		"ssh.rsa_keys":                   {Order: OrderKept},
		"ssh.rsa_keys[].fingerprint":     {Class: ClassFingerprint},
		"ssh.rsa_keys[].path":            {Class: ClassPath},
		"firewall.raw_dumps":             {Order: OrderKept},
		"firewall.raw_dumps[].content":   {Class: ClassBlank},
		"firewall.raw_dumps[].truncated": {Class: ClassKept},
		"firewall.rules":                 {Order: OrderKept},
		"firewall.rules[].saddr":         {Class: ClassAddress},
		"mounts.points":                  {Order: OrderKept},
		"mounts.points[].target":         {Class: ClassPath},
		"logging.urls":                   {Order: OrderKept},
		"logging.urls[]":                 {Class: ClassURL},
		"walk.world_writable":            {Order: OrderKept},
		"walk.world_writable[].path":     {Class: ClassPath},
		"cron.files":                     {Order: OrderKept},
		"cron.files[].path":              {Class: ClassPath},
		"cron.files[].reason":            {Class: ClassPlaceholder},
		"sshd.banner":                    {Class: ClassPath},
	}
}

func env(v any) map[string]any { return map[string]any{"status": "ok", "value": v} }

func rec(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func list(v ...any) []any { return v }

func testDoc() map[string]any {
	return map[string]any{
		"schema_version": json.Number("1"),
		"synthetic":      true,
		"_expect":        rec("reason_code", "x", "exit_code", json.Number("1")),
		"_notes":         "the alice host, built by hand",
		"run": rec(
			"muster_version", "dev",
			"collected_at", "2026-10-30T00:00:00Z",
			"host", rec("hostname", "github-runner", "machine_id_hash", strings.Repeat("a", 64),
				"boot_id", "0d6f", "uptime_s", json.Number("123")),
			"collectors", list(
				rec("name", "accounts"),
				rec("name", "audit", "reason", ""),
				rec("name", "cron", "reason", "stat /home/alice: permission denied"),
			),
			"partial_failures", list("walk: /home/alice timed out"),
		),
		"facts": map[string]any{
			"accounts": map[string]any{
				"users": env(list(
					rec("name", "runner", "uid", json.Number("1001"), "home", "/home/runner"),
					rec("name", "root", "uid", json.Number("0"), "home", "/root"),
					rec("name", "app", "uid", json.Number("998"), "home", "/srv/app"),
					rec("name", "none", "uid", json.Number("1002"), "home", "/nonexistent"),
					rec("name", "alice", "uid", json.Number("1003"), "home", "/home/alice"),
				)),
				"lastlog": env(list(
					rec("name", "alice", "host", ip4(10, 1, 2, 3)),
					rec("name", "bob", "host", "ws1.corp.example"),
					rec("name", "carol", "host", ":0"),
					rec("name", "dave", "host", ""),
				)),
				"uids": env(list(json.Number("1001"), json.Number("0"), json.Number("998"), json.Number("0"))),
			},
			"sudo": map[string]any{"principals": env(list("%admins", "carol", "root", "ALL"))},
			"pam":  map[string]any{"mode": env("none")},
			"files": map[string]any{
				"etc_hosts_equiv_lines": env(list("+ alice", "alice-host bob", "+@ng -bob", "+", "-", "host  user  extra")),
				"etc_securetty_lines":   env(list("pts/0", "tty1")),
			},
			"time_sync": map[string]any{"servers": env(list(ip4(10, 9, 8, 7), "ntp.corp.example", "pool.ntp.org:123", "bad_name!", "*"))},
			"logging": map[string]any{"journal_upload": map[string]any{
				"url": env("https://alice@logs.corp.example:19532/home/alice/up"),
			}},
			"ssh": map[string]any{"rsa_keys": env(list(rec("fingerprint", "SHA256:abc", "path", "/home/alice/.ssh/authorized_keys")))},
			"firewall": map[string]any{
				"raw_dumps": env(list(rec("content", "table inet filter { }", "truncated", true))),
				"rules":     env(list(rec("saddr", ip4(10, 0, 0, 0)+"/8"), rec("saddr", "not an address"))),
			},
			"mounts": map[string]any{"points": env(list(rec("target", "/var/log"), rec("target", "/tmp"), rec("target", "/home/alice"), rec("target", "/home")))},
			"walk": map[string]any{"world_writable": env(list(
				rec("path", "/srv/app/data"),
				rec("path", "/var/spool/cron/crontabs/carol"),
				rec("path", "/var/log/syslog"),
			))},
			"cron": map[string]any{"files": map[string]any{
				"status": "ok",
				"value":  list(rec("path", "/etc/cron.d/carol", "reason", "stat /etc/cron.d/carol: denied"), rec("path", "/etc/cron.d/x")),
				"reason": "read /home/alice/.cron",
				"source": rec("kind", "derived", "inputs", list(
					rec("kind", "file", "path", "/home/alice/x", "raw", "a line", "inputs", list(rec("kind", "file", "raw", "deeper"))),
					rec("kind", "command", "cmd", "crontab -l -u alice", "exit_code", json.Number("0")),
				)),
				"truncated": true,
			}},
			"sshd": map[string]any{"banner": map[string]any{
				"runtime":   rec("status", "ok", "value", "/home/alice/banner", "source", rec("kind", "command", "raw", "banner /home/alice/banner")),
				"persisted": rec("status", "denied", "reason", "open /etc/ssh/sshd_config.d/alice.conf: denied"),
				"effective": rec("status", "ok", "value", "/home/alice/banner"),
				"winner":    rec("kind", "file", "path", "/home/alice/sshd.conf", "line", json.Number("3"), "raw", "Banner x"),
				"personas": map[string]any{
					"root": rec("status", "ok", "value", "/home/runner/b", "source", rec("kind", "command", "raw", "banner /home/runner/b")),
				},
			}},
		},
	}
}

func get(t *testing.T, tree any, path ...any) any {
	t.Helper()
	cur := tree
	for _, p := range path {
		switch s := p.(type) {
		case string:
			m, ok := cur.(map[string]any)
			if !ok {
				t.Fatalf("%v: not a map at %q", path, s)
			}
			cur, ok = m[s]
			if !ok {
				t.Fatalf("%v: no key %q", path, s)
			}
		case int:
			l, ok := cur.([]any)
			if !ok || s >= len(l) {
				t.Fatalf("%v: not a list or short at %d", path, s)
			}
			cur = l[s]
		}
	}
	return cur
}

func has(tree any, path ...string) bool {
	cur := tree
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = m[p]; !ok {
			return false
		}
	}
	return true
}

func transform(t *testing.T) (map[string]any, Report, *Key) {
	t.Helper()
	k := key7(t)
	out, rep, err := Transform(testDoc(), testTable(), k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	return out, rep, k
}

func TestTransformHeader(t *testing.T) {
	out, rep, k := transform(t)
	if got := get(t, out, "run", "host", "hostname"); got != k.Host("github-runner") {
		t.Errorf("hostname = %v", got)
	}
	if got := get(t, out, "run", "host", "machine_id_hash"); got != k.MachineIDHash(strings.Repeat("a", 64)) {
		t.Errorf("machine_id_hash = %v", got)
	}
	if got := get(t, out, "run", "host", "boot_id"); got != "" {
		t.Errorf("boot_id = %v", got)
	}
	if got := get(t, out, "run", "host", "uptime_s"); got != json.Number("0") {
		t.Errorf("uptime_s = %#v", got)
	}
	if got := get(t, out, "run", "collected_at"); got != "2026-10-30T00:00:00Z" {
		t.Errorf("collected_at = %v", got)
	}
	// placeholder keeps presence: absent stays absent, "" stays "", present is replaced
	if has(get(t, out, "run", "collectors", 0), "reason") {
		t.Error("an absent reason became present")
	}
	if got := get(t, out, "run", "collectors", 1, "reason"); got != "" {
		t.Errorf("empty reason = %v", got)
	}
	if got := get(t, out, "run", "collectors", 2, "reason"); got != Placeholder {
		t.Errorf("reason = %v", got)
	}
	if got := get(t, out, "run", "partial_failures", 0); got != Placeholder {
		t.Errorf("partial_failures = %v", got)
	}
	if got := get(t, out, "_notes"); got != Placeholder {
		t.Errorf("_notes = %v", got)
	}
	if got := get(t, out, "_expect", "reason_code"); got != "x" {
		t.Errorf("_expect kept: %v", got)
	}
	if get(t, out, "synthetic") != true || get(t, out, "schema_version") != json.Number("1") {
		t.Error("synthetic or schema_version changed")
	}
	_ = rep
}

// Account runner and host github-runner map independently, each by its class.
func TestTransformAccountAndHostAreIndependent(t *testing.T) {
	out, _, k := transform(t)
	name := get(t, out, "facts", "accounts", "users", "value", 0, "name")
	host := get(t, out, "run", "host", "hostname")
	if name != k.Account("runner") || host != k.Host("github-runner") {
		t.Fatalf("name %v host %v", name, host)
	}
	if !strings.HasPrefix(name.(string), "u") || !strings.HasPrefix(host.(string), "h") || name == host {
		t.Errorf("classes crossed: %v %v", name, host)
	}
	if got := get(t, out, "facts", "accounts", "users", "value", 1, "name"); got != "root" {
		t.Errorf("root = %v", got)
	}
	// a user called none leaves the enum none alone
	if got := get(t, out, "facts", "accounts", "users", "value", 3, "name"); got != k.Account("none") {
		t.Errorf("user none = %v", got)
	}
	if got := get(t, out, "facts", "pam", "mode", "value"); got != "none" {
		t.Errorf("enum none = %v", got)
	}
}

func TestTransformPaths(t *testing.T) {
	out, _, k := transform(t)
	a := k.Account
	cases := []struct {
		path []any
		want string
	}{
		{[]any{"facts", "accounts", "users", "value", 0, "home"}, "/home/" + a("runner")},
		{[]any{"facts", "accounts", "users", "value", 1, "home"}, "/root"},
		{[]any{"facts", "accounts", "users", "value", 2, "home"}, "/srv/" + a("app")},
		// the home record of app makes /srv/app a home: a prefix rewrite
		{[]any{"facts", "walk", "world_writable", "value", 0, "path"}, "/srv/" + a("app") + "/data"},
		// carol is only a sudo principal: she still counts (first pass)
		{[]any{"facts", "walk", "world_writable", "value", 1, "path"}, "/var/spool/cron/crontabs/" + a("carol")},
		{[]any{"facts", "walk", "world_writable", "value", 2, "path"}, "/var/log/syslog"},
		{[]any{"facts", "cron", "files", "value", 0, "path"}, "/etc/cron.d/" + a("carol")},
		{[]any{"facts", "cron", "files", "value", 1, "path"}, "/etc/cron.d/x"},
		{[]any{"facts", "ssh", "rsa_keys", "value", 0, "path"}, "/home/" + a("alice") + "/.ssh/authorized_keys"},
		{[]any{"facts", "cron", "files", "source", "inputs", 0, "path"}, "/home/" + a("alice") + "/x"},
		{[]any{"facts", "sshd", "banner", "winner", "path"}, "/home/" + a("alice") + "/sshd.conf"},
		{[]any{"facts", "sshd", "banner", "runtime", "value"}, "/home/" + a("alice") + "/banner"},
		{[]any{"facts", "sshd", "banner", "effective", "value"}, "/home/" + a("alice") + "/banner"},
		{[]any{"facts", "sshd", "banner", "personas", "root", "value"}, "/home/" + a("runner") + "/b"},
	}
	for _, c := range cases {
		if got := get(t, out, c.path...); got != c.want {
			t.Errorf("%v = %v, want %v", c.path, got, c.want)
		}
	}
	// mount targets are paths: the control-named ones never change, and a
	// home mounted on its own maps as the home does
	targets := get(t, out, "facts", "mounts", "points", "value").([]any)
	for i, w := range []string{"/var/log", "/tmp", "/home/" + a("alice"), "/home"} {
		if got := targets[i].(map[string]any)["target"]; got != w {
			t.Errorf("mount target %d = %v, want %v", i, got, w)
		}
	}
	if home := get(t, out, "facts", "accounts", "users", "value", 4, "home"); home != targets[2].(map[string]any)["target"] {
		t.Errorf("alice's home %v and her mount target %v differ", home, targets[2])
	}
}

// Without the Home mark the home record builds no home: /srv/app/data stays.
func TestTransformHomesComeFromHomeFields(t *testing.T) {
	tab := testTable()
	r := tab["accounts.users[].home"]
	r.Home = false
	tab["accounts.users[].home"] = r
	out, _, err := Transform(testDoc(), tab, key7(t), "keyed")
	if err != nil {
		t.Fatal(err)
	}
	if got := get(t, out, "facts", "walk", "world_writable", "value", 0, "path"); got != "/srv/app/data" {
		t.Errorf("path = %v", got)
	}
}

func TestTransformReadText(t *testing.T) {
	out, _, k := transform(t)
	a, h := k.Account, k.Host
	lines := get(t, out, "facts", "files", "etc_hosts_equiv_lines", "value").([]any)
	want := []string{
		"+ " + a("alice"),
		h("alice-host") + " " + a("bob"),
		"+@" + a("ng") + " -" + a("bob"),
		"+",
		"-",
		h("host") + "  " + a("user") + "  " + Placeholder,
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("hosts.equiv line %d = %q, want %q", i, lines[i], w)
		}
	}
	plus := regexp.MustCompile(`^\+`)
	for i, in := range testDoc()["facts"].(map[string]any)["files"].(map[string]any)["etc_hosts_equiv_lines"].(map[string]any)["value"].([]any) {
		if plus.MatchString(in.(string)) != plus.MatchString(lines[i].(string)) {
			t.Errorf("^\\+ changed on line %d", i)
		}
	}
	tty := get(t, out, "facts", "files", "etc_securetty_lines", "value").([]any)
	if tty[0] != "pts/0" || tty[1] != "tty1" {
		t.Errorf("securetty = %v", tty)
	}
}

func TestTransformHostOrAddress(t *testing.T) {
	out, _, k := transform(t)
	addr, _ := k.AddrToken(ip4(10, 9, 8, 7))
	want := []string{addr, k.Host("ntp.corp.example"), k.Host("pool.ntp.org") + ":123", Placeholder, "*"}
	got := get(t, out, "facts", "time_sync", "servers", "value").([]any)
	for i, w := range want {
		if got[i] != w {
			t.Errorf("server %d = %v, want %v", i, got[i], w)
		}
	}
	if addr == ip4(10, 9, 8, 7) || !strings.HasPrefix(addr, "10.") {
		t.Errorf("address %v: not mapped inside its range", addr)
	}
	// lastlog hosts: an address, a host, and the X display placeholdered
	ll := get(t, out, "facts", "accounts", "lastlog", "value").([]any)
	byName := map[string]any{}
	for _, r := range ll {
		byName[r.(map[string]any)["name"].(string)] = r.(map[string]any)["host"]
	}
	a10, _ := k.AddrToken(ip4(10, 1, 2, 3))
	for name, w := range map[string]string{"alice": a10, "bob": k.Host("ws1.corp.example"), "carol": Placeholder, "dave": ""} {
		if byName[k.Account(name)] != w {
			t.Errorf("lastlog %s host = %v, want %v", name, byName[k.Account(name)], w)
		}
	}
	rules := get(t, out, "facts", "firewall", "rules", "value").([]any)
	if p, _ := k.AddrToken(ip4(10, 0, 0, 0) + "/8"); rules[0].(map[string]any)["saddr"] != p {
		t.Errorf("saddr = %v", rules[0])
	}
	if rules[1].(map[string]any)["saddr"] != Placeholder {
		t.Errorf("an address field matching no form = %v", rules[1])
	}
}

func TestTransformURLAndFingerprint(t *testing.T) {
	out, _, k := transform(t)
	want := "https://" + k.Account("alice") + "@" + k.Host("logs.corp.example") + ":19532/home/" + k.Account("alice") + "/up"
	if got := get(t, out, "facts", "logging", "journal_upload", "url", "value"); got != want {
		t.Errorf("url = %v, want %v", got, want)
	}
	if got := get(t, out, "facts", "ssh", "rsa_keys", "value", 0, "fingerprint"); got != k.Fingerprint("SHA256:abc") {
		t.Errorf("fingerprint = %v", got)
	}
}

func TestTransformBlank(t *testing.T) {
	out, _, _ := transform(t)
	d := get(t, out, "facts", "firewall", "raw_dumps", "value", 0).(map[string]any)
	if d["content"] != "" || d["truncated"] != true {
		t.Errorf("raw dump = %v", d)
	}
}

func TestTransformSortsBySpecAndKeepsOrder(t *testing.T) {
	out, _, k := transform(t)
	ll := get(t, out, "facts", "accounts", "lastlog", "value").([]any)
	var names []string
	for _, r := range ll {
		names = append(names, r.(map[string]any)["name"].(string))
	}
	if !sort.StringsAreSorted(names) || len(names) != 4 {
		t.Errorf("lastlog not re-sorted by name: %v", names)
	}
	mapped := []string{k.Account("alice"), k.Account("bob"), k.Account("carol"), k.Account("dave")}
	if sort.StringsAreSorted(mapped) {
		t.Fatal("test needs a key under which mapping reorders the names")
	}
	uids := get(t, out, "facts", "accounts", "uids", "value").([]any)
	if !reflect.DeepEqual(uids, []any{json.Number("0"), json.Number("998"), json.Number("1001")}) {
		t.Errorf("numeric dedup sort = %v", uids)
	}
	// an ordered list keeps its order: users runner, root, app, none
	users := get(t, out, "facts", "accounts", "users", "value").([]any)
	if users[1].(map[string]any)["name"] != "root" || users[0].(map[string]any)["name"] != k.Account("runner") {
		t.Errorf("ordered list moved: %v", users)
	}
	sudo := get(t, out, "facts", "sudo", "principals", "value").([]any)
	if !reflect.DeepEqual(sudo, []any{"%" + k.Account("admins"), k.Account("carol"), "root", "ALL"}) {
		t.Errorf("sudo principals = %v", sudo)
	}
}

func TestTransformEnvelopeSettingAndSource(t *testing.T) {
	out, _, _ := transform(t)
	for _, p := range [][]any{
		{"facts", "cron", "files", "reason"},
		{"facts", "cron", "files", "source", "inputs", 0, "raw"},
		{"facts", "cron", "files", "source", "inputs", 0, "inputs", 0, "raw"},
		{"facts", "cron", "files", "source", "inputs", 1, "cmd"},
		{"facts", "cron", "files", "value", 0, "reason"},
		{"facts", "sshd", "banner", "runtime", "source", "raw"},
		{"facts", "sshd", "banner", "persisted", "reason"},
		{"facts", "sshd", "banner", "winner", "raw"},
		{"facts", "sshd", "banner", "personas", "root", "source", "raw"},
	} {
		if got := get(t, out, p...); got != Placeholder {
			t.Errorf("%v = %v", p, got)
		}
	}
	if get(t, out, "facts", "cron", "files", "truncated") != true || get(t, out, "facts", "cron", "files", "status") != "ok" {
		t.Error("envelope status or truncated changed")
	}
	if get(t, out, "facts", "cron", "files", "source", "inputs", 1, "exit_code") != json.Number("0") ||
		get(t, out, "facts", "sshd", "banner", "winner", "line") != json.Number("3") ||
		get(t, out, "facts", "sshd", "banner", "winner", "kind") != "file" {
		t.Error("source kept fields changed")
	}
	if has(get(t, out, "facts", "cron", "files", "value", 1), "reason") {
		t.Error("an absent record reason became present")
	}
}

// Report lists the classes that mapped a value and the placeholdered or
// emptied document paths, sorted, in the AX-10 spelling.
func TestTransformReport(t *testing.T) {
	_, rep, _ := transform(t)
	wantClasses := []string{"account", "address", "fingerprint", "host", "machine_id_hash", "path", "url"}
	if !reflect.DeepEqual(rep.Classes, wantClasses) {
		t.Errorf("classes = %v", rep.Classes)
	}
	wantReplaced := []string{
		"_notes",
		"facts.accounts.lastlog.value[].host",
		"facts.cron.files.reason",
		"facts.cron.files.source.inputs[].cmd",
		"facts.cron.files.source.inputs[].inputs[].raw",
		"facts.cron.files.source.inputs[].raw",
		"facts.cron.files.value[].reason",
		"facts.files.etc_hosts_equiv_lines.value[]",
		"facts.firewall.raw_dumps.value[].content",
		"facts.firewall.rules.value[].saddr",
		"facts.sshd.banner.persisted.reason",
		"facts.sshd.banner.personas.root.source.raw",
		"facts.sshd.banner.runtime.source.raw",
		"facts.sshd.banner.winner.raw",
		"facts.time_sync.servers.value[]",
		"run.collectors[].reason",
		"run.host.boot_id",
		"run.host.uptime_s",
		"run.partial_failures[]",
	}
	if !reflect.DeepEqual(rep.Replaced, wantReplaced) {
		t.Errorf("replaced =\n%s\nwant\n%s", strings.Join(rep.Replaced, "\n"), strings.Join(wantReplaced, "\n"))
	}
}

func TestTransformDoesNotMutateAndIsDeterministic(t *testing.T) {
	in := testDoc()
	before, _ := json.Marshal(in)
	k := key7(t)
	out1, rep1, err := Transform(in, testTable(), k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(in)
	if string(before) != string(after) {
		t.Error("input mutated")
	}
	out2, rep2, err := Transform(testDoc(), testTable(), k, "ephemeral")
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(out1)
	b2, _ := json.Marshal(out2)
	if string(b1) != string(b2) || !reflect.DeepEqual(rep1, rep2) {
		t.Error("not deterministic")
	}
}

func TestTransformRefusesUnclassifiedPaths(t *testing.T) {
	cases := []struct {
		name string
		edit func(d map[string]any)
		path string
	}{
		{"unknown fact key", func(d map[string]any) {
			d["facts"].(map[string]any)["accounts"].(map[string]any)["shadow"] = env("x")
		}, "facts.accounts.shadow"},
		{"unknown collector", func(d map[string]any) { d["facts"].(map[string]any)["zz"] = map[string]any{"k": env(1)} }, "facts.zz"},
		{"unknown record field", func(d map[string]any) {
			get(t, d, "facts", "accounts", "users", "value", 0).(map[string]any)["gecos"] = "Alice"
		}, "facts.accounts.users.value[].gecos"},
		{"record where a scalar is classified", func(d map[string]any) {
			get(t, d, "facts", "ssh", "rsa_keys", "value", 0).(map[string]any)["path"] = rec("x", "y")
		}, "facts.ssh.rsa_keys.value[].path.x"},
		{"unknown envelope field", func(d map[string]any) {
			get(t, d, "facts", "pam", "mode").(map[string]any)["note"] = "x"
		}, "facts.pam.mode.note"},
		{"unknown source field", func(d map[string]any) {
			get(t, d, "facts", "cron", "files", "source").(map[string]any)["host"] = "x"
		}, "facts.cron.files.source.host"},
		{"unknown nested source field", func(d map[string]any) {
			get(t, d, "facts", "cron", "files", "source", "inputs", 0, "inputs", 0).(map[string]any)["zz"] = "x"
		}, "facts.cron.files.source.inputs[].inputs[].zz"},
		{"unknown setting side", func(d map[string]any) {
			get(t, d, "facts", "sshd", "banner").(map[string]any)["future"] = env("x")
		}, "facts.sshd.banner.future"},
		{"unknown persona", func(d map[string]any) {
			get(t, d, "facts", "sshd", "banner", "personas").(map[string]any)["alice"] = env("x")
		}, "facts.sshd.banner.personas.alice"},
		{"unknown run field", func(d map[string]any) { d["run"].(map[string]any)["zzz"] = "x" }, "run.zzz"},
		{"unknown top-level key", func(d map[string]any) { d["accounts"] = "x" }, "accounts"},
		{"a generic set name under facts", func(d map[string]any) {
			d["facts"].(map[string]any)["envelope"] = map[string]any{"reason": env("x")}
		}, "facts.envelope"},
		{"an empty object at an unknown key", func(d map[string]any) { d["facts"].(map[string]any)["zz"] = map[string]any{} }, "facts.zz"},
	}
	for _, c := range cases {
		d := testDoc()
		c.edit(d)
		_, _, err := Transform(d, testTable(), key7(t), "keyed")
		var u *UnclassifiedError
		if !errors.As(err, &u) || u.Path != c.path {
			t.Errorf("%s: err = %v, want unclassified %s", c.name, err, c.path)
		}
	}
}

func TestTransformRefusesBadInput(t *testing.T) {
	k := key7(t)
	if _, _, err := Transform(testDoc(), testTable(), k, "plain"); err == nil {
		t.Error("an unknown mode was accepted")
	}
	d := testDoc()
	d["run"].(map[string]any)["anonymization"] = rec("scheme", "muster-anon-v1")
	if _, _, err := Transform(d, testTable(), k, "keyed"); !errors.Is(err, ErrAlreadyAnonymized) {
		t.Errorf("already anonymised: %v", err)
	}
	tab := testTable()
	tab["files.etc_securetty_lines[]"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: "comma"}}
	if _, _, err := Transform(testDoc(), tab, k, "keyed"); err == nil {
		t.Error("an unknown grammar split was accepted")
	}
}

// The ledger notes an address by its canonical spelling and a URL by its
// parts, so neither a case variant nor a URL differing only in a
// placeholdered part is a collision.
func TestTransformNotesCanonicalInputs(t *testing.T) {
	k := key7(t)
	d := testDoc()
	d["facts"].(map[string]any)["time_sync"].(map[string]any)["servers"] = env(list("FD00::1", "fd00::1", "[FD00::1]:123", "udp:Fd00::1"))
	d["facts"].(map[string]any)["logging"].(map[string]any)["urls"] = env(list(
		"https://logs.example/x?a=1", "https://logs.example/x?b=2", "https://u:p@logs.example/", "https://u:q@logs.example/",
		"https://LOGS.example/", "https://logs.example/", "https://[FD00::1]:1/", "https://[fd00::1]:1/"))
	out, _, err := Transform(d, testTable(), k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	srv := get(t, out, "facts", "time_sync", "servers", "value").([]any)
	if srv[0] != srv[1] {
		t.Errorf("FD00::1 and fd00::1 map apart: %v", srv)
	}
	urls := get(t, out, "facts", "logging", "urls", "value").([]any)
	if urls[0] != urls[1] || urls[4] != urls[5] || urls[6] != urls[7] {
		t.Errorf("urls = %v", urls)
	}
}

func TestTableValidateRefuses(t *testing.T) {
	cases := []struct {
		name string
		edit func(Table)
	}{
		{"unknown class on a string", func(t Table) { t["pam.mode"] = FieldRule{Class: "bogus"} }},
		{"unknown class on a number", func(t Table) { t["accounts.users[].uid"] = FieldRule{Class: "bogus"} }},
		{"grammar without class grammar", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassKept, Grammar: &Grammar{Split: SplitWhitespace, Rest: ClassKept}}
		}},
		{"class grammar without a grammar", func(t Table) { t["pam.mode"] = FieldRule{Class: ClassGrammar} }},
		{"grammar split", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: "semicolon", Rest: ClassKept}}
		}},
		{"grammar value class", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: SplitComma, Rest: ClassKept, Values: map[string]Class{"user": ClassGrammar}}}
		}},
		{"grammar value key", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: SplitComma, Rest: ClassKept, Values: map[string]Class{"a=b": ClassAccount}}}
		}},
		{"grammar token class", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: SplitWhitespace, Tokens: []Class{"bogus"}, Rest: ClassKept}}
		}},
		{"grammar with no rest", func(t Table) {
			t["pam.mode"] = FieldRule{Class: ClassGrammar, Grammar: &Grammar{Split: SplitWhitespace}}
		}},
		{"Home off a path row", func(t Table) { t["accounts.users[].name"] = FieldRule{Class: ClassAccount, Home: true} }},
		{"list with no row", func(t Table) { delete(t, "accounts.users") }},
		{"list with no order", func(t Table) { t["accounts.users"] = FieldRule{} }},
		{"sorted list with no sort", func(t Table) { t["accounts.users"] = FieldRule{Order: OrderSorted} }},
		{"kept list with a sort", func(t Table) {
			t["accounts.users"] = FieldRule{Order: OrderKept, Sort: &SortSpec{Keys: []SortKey{{Field: "name"}}}}
		}},
		{"sort with no key", func(t Table) { t["accounts.users"] = FieldRule{Order: OrderSorted, Sort: &SortSpec{}} }},
		{"order on a non-list row", func(t Table) { t["pam.mode"] = FieldRule{Class: ClassKept, Order: OrderKept} }},
	}
	for _, c := range cases {
		tab := testTable()
		c.edit(tab)
		if err := tab.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
		if _, _, err := Transform(testDoc(), tab, key7(t), "keyed"); err == nil {
			t.Errorf("%s: Transform accepted the table", c.name)
		}
	}
	if err := testTable().Validate(); err != nil {
		t.Errorf("the test table: %v", err)
	}
}

// Two spellings of one file are two inputs and two outputs: the ledger,
// which notes raw paths, stays injective.
func TestTransformTwoSpellingsOfOnePath(t *testing.T) {
	k := key7(t)
	d := testDoc()
	d["facts"].(map[string]any)["walk"].(map[string]any)["world_writable"] = env(list(
		rec("path", "/srv/app/data"), rec("path", "/srv//app/data"),
		rec("path", "/home/alice/x"), rec("path", "/home/alice/./x"), rec("path", "/home/alice/.."),
	))
	out, _, err := Transform(d, testTable(), k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	a := k.Account
	want := []string{"/srv/" + a("app") + "/data", "/srv//" + a("app") + "/data",
		"/home/" + a("alice") + "/x", "/home/" + a("alice") + "/./x", "/home/" + a("alice") + "/.."}
	for i, w := range want {
		if got := get(t, out, "facts", "walk", "world_writable", "value", i, "path"); got != w {
			t.Errorf("path %d = %v, want %v", i, got, w)
		}
	}
}

// A raw machine id in a path is noted in the machine-id class: with the
// header hash empty, the class is still listed because the path mapped one.
func TestTransformNotesAHostIDInAPath(t *testing.T) {
	k := key7(t)
	const id = "0123456789abcdef0123456789abcdef"
	doc := testDoc()
	doc["run"].(map[string]any)["host"].(map[string]any)["machine_id_hash"] = ""
	ww := doc["facts"].(map[string]any)["walk"].(map[string]any)["world_writable"].(map[string]any)
	ww["value"] = append(ww["value"].([]any), rec("path", "/var/log/journal/"+id))
	out, rep, err := Transform(doc, testTable(), k, "keyed")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range get(t, out, "facts", "walk", "world_writable", "value").([]any) {
		if r.(map[string]any)["path"] == "/var/log/journal/"+k.hostID(idLabel, id) {
			found = true
		}
	}
	if !found {
		t.Errorf("the journal path was not mapped")
	}
	if i := sort.SearchStrings(rep.Classes, ClassMachineID); i == len(rep.Classes) || rep.Classes[i] != ClassMachineID {
		t.Errorf("classes = %v, want machine_id_hash listed", rep.Classes)
	}
}
