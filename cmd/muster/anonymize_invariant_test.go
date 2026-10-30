package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kun9497/muster/internal/anonymize"
	"github.com/kun9497/muster/internal/check"
	"github.com/kun9497/muster/internal/controls"
	"github.com/kun9497/muster/internal/facts"
	"github.com/kun9497/muster/internal/profile"
	"github.com/kun9497/muster/internal/report"
)

// invariantKey is the one fixed key every invariant test anonymises with.
func invariantKey(t testing.TB) *anonymize.Key {
	t.Helper()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	k, err := anonymize.NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// invariantCorpus is spec §4's corpus: every control fixture, the whole-host
// readings, the full fixtures, the two example snapshots and the synthetic
// anonymisation fixtures of this package.
func invariantCorpus(t *testing.T) []string {
	t.Helper()
	var files []string
	for _, g := range []string{
		"../../controls/testdata/*/*.json",
		"testdata/full-pass.json",
		"testdata/full-fail.json",
		"../../examples/ubuntu-24.04-vm.json",
		"../../examples/ubuntu-24.04-container.json",
		"testdata/anonymize/*.json",
	} {
		m, err := filepath.Glob(g)
		if err != nil {
			t.Fatal(err)
		}
		if len(m) == 0 {
			t.Fatalf("corpus glob %s finds nothing", g)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	return files
}

// loadCorpusSnapshot loads a corpus file the way the fixture harness does:
// _expect is not part of the snapshot.
func loadCorpusSnapshot(t *testing.T, name string, data []byte) *facts.Snapshot {
	t.Helper()
	var tree map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	delete(tree, "_expect")
	b, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.Load(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return s
}

// anonymizeBytes runs the command's own transform (anonymizeDocument) over a
// document's bytes under key k.
func anonymizeBytes(t *testing.T, name string, data []byte, k *anonymize.Key) []byte {
	t.Helper()
	doc, err := decodeDocument(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	out, err := anonymizeDocument(doc, k, "keyed")
	if err != nil {
		t.Fatalf("%s: anonymize: %v", name, err)
	}
	return out
}

// verdictRow is what AX-12 holds equal per row: never the snapshot digest,
// a subject or evidence text.
type verdictRow struct {
	ID         string
	Status     check.Status
	ReasonCode check.ReasonCode
	Mechanism  int
	Verdicts   string // the observation verdict multiset, as sorted counts
}

type verdicts struct {
	Rows []verdictRow
	Exit int
}

func verdictsOf(results []check.Result) verdicts {
	var v verdicts
	for _, r := range results {
		counts := map[string]int{}
		for _, o := range r.Observations {
			counts[o.Verdict]++
		}
		var ks []string
		for k := range counts {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		var parts []string
		for _, k := range ks {
			parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
		}
		v.Rows = append(v.Rows, verdictRow{r.ID, r.Status, r.ReasonCode, r.Mechanism, strings.Join(parts, ",")})
	}
	v.Exit = report.ExitCode(results, report.ExitOptions{})
	return v
}

// invariantNow is the command clock for the invariant (no waiver file is
// read, so it only has to be fixed).
var invariantNow = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)

// selections resolves every built-in profile once.
func selections(t *testing.T, set *controls.Set) map[string]*Selection {
	t.Helper()
	out := map[string]*Selection{}
	for _, name := range profile.Builtins() {
		sel, err := resolveSelection(name, nil, set, func(string) {})
		if err != nil {
			t.Fatalf("profile %s: %v", name, err)
		}
		out[name] = sel
	}
	if len(out) < 5 {
		t.Fatalf("only %d built-in profiles", len(out))
	}
	return out
}

// evaluate runs check's pipeline (newCheckBlock, no tuning, no waivers).
func evaluate(sel *Selection, snap *facts.Snapshot, reg *facts.Registry) []check.Result {
	results, _ := newCheckBlock(sel, snap, reg, nil, invariantNow, func(string) {})
	return results
}

// diffVerdicts names the first rows that differ.
func diffVerdicts(a, b verdicts) []string {
	var out []string
	if a.Exit != b.Exit {
		out = append(out, fmt.Sprintf("exit code %d -> %d", a.Exit, b.Exit))
	}
	if len(a.Rows) != len(b.Rows) {
		return append(out, fmt.Sprintf("%d rows -> %d rows", len(a.Rows), len(b.Rows)))
	}
	for i := range a.Rows {
		if a.Rows[i] != b.Rows[i] {
			out = append(out, fmt.Sprintf("%+v -> %+v", a.Rows[i], b.Rows[i]))
		}
	}
	return out
}

// AX-12: for every corpus snapshot and every built-in profile, with no
// tuning and no waiver file, the original and the anonymised snapshot give
// equal (id, status, reason_code), the same mechanism, the same observation
// verdict multiset per row and the same exit code.
func TestAnonymisedVerdictsEqualTheOriginals(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sels := selections(t, set)
	names := make([]string, 0, len(sels))
	for n := range sels {
		names = append(names, n)
	}
	sort.Strings(names)
	k := invariantKey(t)
	files := invariantCorpus(t)
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		orig := loadCorpusSnapshot(t, f, data)
		anonData := anonymizeBytes(t, f, data, k)
		anon := loadCorpusSnapshot(t, f, anonData)
		if anon.Run.Anonymization == nil {
			t.Fatalf("%s: the anonymised snapshot is not marked", f)
		}
		for _, n := range names {
			a := verdictsOf(evaluate(sels[n], orig, reg))
			b := verdictsOf(evaluate(sels[n], anon, reg))
			if d := diffVerdicts(a, b); len(d) > 0 {
				t.Errorf("%s under %s: the anonymised verdicts differ:\n  %s", f, n, strings.Join(d, "\n  "))
			}
		}
	}
	t.Logf("corpus %d snapshots x %d profiles (%s)", len(files), len(names), strings.Join(names, ", "))
}

// syntheticWant is what each fixture under testdata/anonymize is built to
// show, judged on the original and on the anonymised snapshot alike: a
// keep-set clause with the preserved name and with a mapped one, a human
// account log at /tmp beside a /var/log mount, nested and shared homes, an
// empty journal-upload URL with an active unit, and the cron.files presence
// pair (WARN is a partial control's failing verdict). A fixture that stopped reaching its control would make the
// invariant vacuous for it; this pins that it does not.
var syntheticWant = map[string]map[string]check.Status{
	"keep-root-only.json":           {"muster.account.root_only_uid_zero": check.PASS},
	"keep-uid0-mapped.json":         {"muster.account.root_only_uid_zero": check.FAIL},
	"keep-ftp-interactive.json":     {"muster.service.ftp_account_shell": check.FAIL},
	"keep-ftp-mapped.json":          {"muster.service.ftp_account_shell": check.PASS},
	"keep-lp-uucp-present.json":     {"muster.account.unnecessary_accounts": check.WARN},
	"keep-lp-mapped.json":           {"muster.account.unnecessary_accounts": check.PASS},
	"keep-admin-root-group.json":    {"muster.account.admin_group_minimal": check.WARN},
	"keep-admin-mapped-group.json":  {"muster.account.admin_group_minimal": check.PASS},
	"keep-audit-adm.json":           {"muster.beyond.audit_log_permissions": check.PASS},
	"keep-audit-mapped.json":        {"muster.beyond.audit_log_permissions": check.FAIL},
	"keep-logdir-syslog.json":       {"muster.file.log_dir_permissions": check.PASS},
	"keep-logdir-mapped.json":       {"muster.file.log_dir_permissions": check.FAIL},
	"log-home-tmp.json":             {"muster.beyond.separate_partitions": check.WARN},
	"homes-nested-shared.json":      {"muster.file.home_dir_permissions": check.FAIL, "muster.file.home_dir_exists": check.PASS},
	"journal-upload-empty-url.json": {"muster.beyond.remote_log_forwarding": check.FAIL},
	"cron-presence.json":            {"muster.account.cron_permissions": check.FAIL},
}

// wantMechanism pins the mechanism a fixture's control must judge by.
var wantMechanism = map[string]map[string]int{
	"journal-upload-empty-url.json": {"muster.beyond.remote_log_forwarding": 3},
}

func TestSyntheticAnonymizeFixturesJudgeAsBuilt(t *testing.T) {
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	sel := selections(t, set)["default"]
	k := invariantKey(t)
	files, _ := filepath.Glob("testdata/anonymize/*.json")
	if len(files) != len(syntheticWant) {
		t.Errorf("testdata/anonymize holds %d fixtures, syntheticWant names %d", len(files), len(syntheticWant))
	}
	for _, f := range files {
		name := filepath.Base(f)
		want, ok := syntheticWant[name]
		if !ok {
			t.Errorf("%s: no expectation in syntheticWant", name)
			continue
		}
		data := mustRead(t, f)
		var meta struct{ Synthetic bool }
		if err := json.Unmarshal(data, &meta); err != nil || !meta.Synthetic {
			t.Errorf("%s: not marked synthetic: true (D02)", name)
		}
		for which, snap := range map[string]*facts.Snapshot{
			"original":   loadCorpusSnapshot(t, f, data),
			"anonymised": loadCorpusSnapshot(t, f, anonymizeBytes(t, f, data, k)),
		} {
			byID := map[string]check.Result{}
			for _, r := range evaluate(sel, snap, reg) {
				byID[r.ID] = r
			}
			for id, st := range want {
				r, ok := byID[id]
				if !ok {
					t.Errorf("%s (%s): %s not evaluated", name, which, id)
					continue
				}
				if r.Status != st {
					t.Errorf("%s (%s): %s is %s (%s: %s), want %s", name, which, id, r.Status, r.ReasonCode, r.Reason, st)
				}
				if m := wantMechanism[name][id]; m != 0 && r.Mechanism != m {
					t.Errorf("%s (%s): %s judged by mechanism %d, want %d", name, which, id, r.Mechanism, m)
				}
			}
		}
	}
}

// anonFacts anonymises a fixture and returns its decoded fact tree.
func anonFacts(t *testing.T, file string) map[string]any {
	t.Helper()
	out := anonymizeBytes(t, file, mustRead(t, file), invariantKey(t))
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc["facts"].(map[string]any)
}

func listAt(t *testing.T, tree map[string]any, key string) []any {
	t.Helper()
	var cur any = tree
	for _, seg := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: no object at %s", key, seg)
		}
		cur = m[seg]
	}
	l, ok := cur.(map[string]any)["value"].([]any)
	if !ok {
		t.Fatalf("%s: value is not a list", key)
	}
	return l
}

// §4 presence: after anonymisation the cron.files row that had a reason
// still has one (placeholdered) and the row that had none still has none.
func TestAnonymisedCronReasonKeepsPresence(t *testing.T) {
	rows := listAt(t, anonFacts(t, "testdata/anonymize/cron-presence.json"), "cron.files")
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2", len(rows))
	}
	byPath := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	if got, ok := byPath["/etc/cron.d/nightly"]["reason"]; !ok || got != anonymize.Placeholder {
		t.Errorf("the denied row's reason is %v (present %v), want %q", got, ok, anonymize.Placeholder)
	}
	if got, ok := byPath["/etc/cron.d/weekly"]["reason"]; ok {
		t.Errorf("the clean row gained a reason %v", got)
	}
}

// AX-6 over nested and shared homes: a nested home is rewritten under its
// parent's mapped home; a shared home whose last component names one of its
// accounts maps by that name; a shared home named after no account, a home
// at /tmp or /var/tmp, and every mount target stay as they were.
func TestAnonymisedHomesNestedSharedAndExempt(t *testing.T) {
	k := invariantKey(t)
	home := map[string]string{}
	for _, r := range listAt(t, anonFacts(t, "testdata/anonymize/homes-nested-shared.json"), "accounts.users") {
		m := r.(map[string]any)
		home[m["name"].(string)] = m["home"].(string)
	}
	a := func(n string) string { return k.Account(n) }
	want := map[string]string{
		a("alice"): "/home/" + a("alice"),
		a("bob"):   "/home/" + a("alice") + "/" + a("bob"),
		a("carol"): "/srv/team",
		a("dave"):  "/srv/team",
		a("erin"):  "/srv/" + a("erin"),
		a("frank"): "/srv/" + a("erin"),
		"root":     "/root",
	}
	for n, h := range want {
		if home[n] != h {
			t.Errorf("home of %s is %q, want %q", n, home[n], h)
		}
	}

	tree := anonFacts(t, "testdata/anonymize/log-home-tmp.json")
	exempt := 0
	for _, r := range listAt(t, tree, "accounts.users") {
		m := r.(map[string]any)
		if n := m["name"].(string); n == a("log") || n == a("var") {
			exempt++
			if n == a("log") && m["home"] != "/tmp" || n == a("var") && m["home"] != "/var/tmp" {
				t.Errorf("an exempt home was rewritten: %v", m)
			}
		}
	}
	if exempt != 2 {
		t.Fatalf("found %d of the log and var accounts, want 2", exempt)
	}
	var targets []string
	for _, r := range listAt(t, tree, "mounts.points") {
		targets = append(targets, r.(map[string]any)["target"].(string))
	}
	if strings.Join(targets, " ") != "/ /boot /home /tmp /var /var/tmp /var/log /var/log/audit /dev/shm" {
		t.Errorf("mount targets changed: %v", targets)
	}
}

// exampleStrings returns every string of the VM example and of its
// anonymisation under the invariant key, and the example's header hash.
func exampleStrings(t *testing.T) (orig, anon []string, header string) {
	t.Helper()
	const ex = "../../examples/ubuntu-24.04-vm.json"
	data := mustRead(t, ex)
	var hdr struct {
		Run struct {
			Host struct {
				MachineIDHash string `json:"machine_id_hash"`
			} `json:"host"`
		} `json:"run"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		t.Fatal(err)
	}
	var walk func(v any, out *[]string)
	walk = func(v any, out *[]string) {
		switch x := v.(type) {
		case map[string]any:
			for _, e := range x {
				walk(e, out)
			}
		case []any:
			for _, e := range x {
				walk(e, out)
			}
		case string:
			*out = append(*out, x)
		}
	}
	strs := func(doc []byte) []string {
		var tree any
		if err := json.Unmarshal(doc, &tree); err != nil {
			t.Fatal(err)
		}
		var out []string
		walk(tree, &out)
		return out
	}
	return strs(data), strs(anonymizeBytes(t, ex, data, invariantKey(t))), hdr.Run.Host.MachineIDHash
}

// AX-6's machine-id positions over the VM example: its journal directory is
// named by the raw machine id, whose sha256 is the header's
// machine_id_hash. After anonymisation no path component hashes to it.
func TestAnonymisedPathsCarryNoMachineID(t *testing.T) {
	orig, anon, header := exampleStrings(t)
	byID := func(ss []string) (n int) {
		for _, s := range ss {
			for _, c := range strings.Split(s, "/") {
				if sum := sha256.Sum256([]byte(c)); c != "" && fmt.Sprintf("%x", sum) == header {
					n++
				}
			}
		}
		return n
	}
	if n := byID(orig); n == 0 {
		t.Fatal("no path component of the example hashes to its machine_id_hash: the test proves nothing")
	}
	if n := byID(anon); n != 0 {
		t.Errorf("%d path components of the anonymised example hash to the original machine_id_hash", n)
	}
}

// The VM example's PrivateTmp directories (/tmp and /var/tmp
// systemd-private-<boot id>-<unit>-<random>) carry the boot id the header
// blanks; none of them is left after anonymisation.
func TestAnonymisedPathsCarryNoBootID(t *testing.T) {
	orig, anon, _ := exampleStrings(t)
	private := regexp.MustCompile(`systemd-private-([0-9a-f]{32})-`)
	boots := map[string]bool{}
	for _, s := range orig {
		for _, m := range private.FindAllStringSubmatch(s, -1) {
			boots[m[1]] = true
		}
	}
	if len(boots) == 0 {
		t.Fatal("the example names no PrivateTmp directory: the test proves nothing")
	}
	n := 0
	for _, s := range anon {
		for b := range boots {
			if strings.Contains(s, b) {
				n++
			}
		}
	}
	if n != 0 {
		t.Errorf("%d strings of the anonymised example carry an original boot id", n)
	}
}

// canarySnap builds, at test time, the synthetic host of §4's canary sweep:
// a document with every registry key present and, in every location the
// table classifies as anything but kept, a unique canary of that location's
// class: account names, DNS labels, addresses in every form §1.1 parses
// (built from octets, never written as literals), host forms, URLs,
// fingerprints, the machine id hash, paths at every AX-6 position (an
// account-named /etc/sudoers.d/ drop-in and an EL /var/spool/mail/ spool
// among them), template unit instances, free text naming the host's own
// short name, a source.raw cut ending in "…", and every non-kept header
// field. Kept locations carry plain values (AX-4's kept row is published by
// design). It is never committed.
type canarySnap struct {
	tb    testing.TB
	t     anonymize.Table
	reg   *facts.Registry
	n     int
	words []string // canary substrings that must never reach an output
	addrs []string // address canaries, matched on address boundaries
	forms map[string]int
	// rows is every table path the generator placed a value at.
	rows      map[string]bool
	kids      map[string][]string
	addrUnder map[string]bool
}

const (
	canaryShort   = "qzshortname"
	canarySudoer  = "qzsudoer"
	canarySpooler = "qzspooler"
	// canaryMachineID is the host's raw machine id: the journal directory
	// and the BLS entries are named by it, and its sha256 is the header's
	// machine_id_hash.
	canaryMachineID = "0c0ffee00c0ffee00c0ffee00c0ffee0"
	// canaryBootID is the boot id systemd's PrivateTmp directories carry.
	canaryBootID = "0b007b007b007b007b007b007b007b00"
)

func newCanarySnap(tb testing.TB) *canarySnap {
	reg, err := facts.LoadRegistry()
	if err != nil {
		tb.Fatal(err)
	}
	return &canarySnap{tb: tb, t: anonymize.Default, reg: reg, forms: map[string]int{}, rows: map[string]bool{}}
}

func (c *canarySnap) next(prefix string) string {
	c.n++
	w := fmt.Sprintf("%s%04d", prefix, c.n)
	c.words = append(c.words, w)
	return w
}

func v4(a, b, c, d int) string {
	return netip.AddrFrom4([4]byte{byte(a), byte(b), byte(c), byte(d)}).String()
}

func v6(words ...uint16) string {
	var b [16]byte
	for i, w := range words {
		b[2*i], b[2*i+1] = byte(w>>8), byte(w)
	}
	return netip.AddrFrom16(b).String()
}

func (c *canarySnap) addr(s string) string {
	c.addrs = append(c.addrs, s)
	return s
}

// addressForms are §1.1's forms; each call builds fresh addresses.
var addressForms = []string{"v4-private", "v4-public", "v4-cidr", "v4-netmask", "v4-port", "v6-port", "transport",
	"v6-zone", "range", "nft-set", "v6-public", "v4-mapped", "v6-ula", "nat64"}

// hostForms are AX-4's host forms of a host-or-address field.
var hostForms = []string{"bare", "dns", "host-port", "transport-host", "syslog", "wildcard", "netgroup"}

func (c *canarySnap) addressForm(form string) string {
	c.forms[form]++
	c.n++
	n := c.n % 250
	m := c.n / 250 % 200
	switch form {
	case "v4-private":
		return c.addr(v4(10, n, m, 9))
	case "v4-public":
		return c.addr(v4(9, n, m, 5))
	case "v4-cidr":
		return c.addr(v4(172, 20+m%10, n, 4)) + "/30"
	case "v4-netmask":
		return c.addr(v4(192, 168, n, m)) + "/" + v4(255, 255, 255, 255)
	case "v4-port":
		return c.addr(v4(100, 64+m%60, n, 3)) + ":514"
	case "v6-port":
		return "[" + c.addr(v6(0xfd12, 0x3456, uint16(c.n), 0, 0, 0, 0, 1)) + "]:53"
	case "transport":
		return "udp:" + c.addr(v4(9, 9, n, 9+m)) + ":123"
	case "v6-zone":
		return c.addr(v6(0xfe80, 0, 0, 0, 0, 0, uint16(c.n), 1)) + "%eth0"
	case "range":
		return c.addr(v4(10, 200, n, 1+m)) + "-" + c.addr(v4(10, 201, n, 9+m))
	case "nft-set":
		return "{ " + c.addr(v4(10, 202, n, 1+m)) + ", " + c.addr(v4(9, 202, n, 2+m)) + " }"
	case "v6-public":
		return c.addr(v6(0x2a01, 0x4f8, uint16(c.n), 0, 0, 0, 0, 5))
	case "v4-mapped":
		return "::ffff:" + c.addr(v4(10, 203, n, 3+m))
	case "v6-ula":
		return c.addr(v6(0xfd00, uint16(c.n), 0, 0, 0, 0, 0, 7))
	case "nat64":
		return "64:ff9b::" + c.addr(v4(9, 204, n, 4+m))
	}
	c.tb.Fatalf("unknown address form %s", form)
	return ""
}

func (c *canarySnap) hostForm(form string) string {
	c.forms[form]++
	switch form {
	case "bare":
		return c.next("qzhost")
	case "dns":
		return c.next("qzhost") + "." + c.next("qzdom") + ".lan"
	case "host-port":
		return c.next("qzhost") + ".lan:514"
	case "transport-host":
		return "tcp:" + c.next("qzhost") + ".lan:601"
	case "syslog":
		return "@@(o)" + c.next("qzhost") + ".lan:514"
	case "wildcard":
		return "*." + c.next("qzhost") + ".lan"
	case "netgroup":
		return "@" + c.next("qznet")
	}
	c.tb.Fatalf("unknown host form %s", form)
	return ""
}

// pathForms are AX-6's positions.
var pathForms = []string{"home", "sudoers.d", "mail-el", "mail", "crontab", "cron-el", "linger", "accountsservice", "cron.d",
	"journal", "bls", "private-tmp"}

func (c *canarySnap) pathForm(i int) string {
	form := pathForms[i%len(pathForms)]
	c.forms["path:"+form]++
	switch form {
	case "home":
		return "/home/" + c.next("qzpath") + "/.profile"
	case "sudoers.d":
		return "/etc/sudoers.d/" + canarySudoer
	case "mail-el":
		return "/var/spool/mail/" + canarySpooler
	case "mail":
		return "/var/mail/" + canarySudoer
	case "crontab":
		return "/var/spool/cron/crontabs/" + canarySpooler
	case "cron-el":
		return "/var/spool/cron/" + canarySudoer
	case "linger":
		return "/var/lib/systemd/linger/" + canarySpooler
	case "accountsservice":
		return "/var/lib/AccountsService/users/" + canarySudoer
	case "cron.d":
		return "/etc/cron.d/" + canarySpooler
	case "journal":
		return "/var/log/journal/" + canaryMachineID
	case "bls":
		return "/boot/loader/entries/" + canaryMachineID + "-6.8.0-45-generic.conf"
	case "private-tmp":
		return "/tmp/systemd-private-" + canaryBootID + "-chrony.service-HqwecO/tmp"
	}
	return ""
}

func (c *canarySnap) text() string {
	return c.next("qztext") + " on " + canaryShort + " said so"
}

// leaf is one value of class cl; i picks the form of a multi-form class.
func (c *canarySnap) leaf(cl anonymize.Class, i int, kept any) any {
	switch cl {
	case anonymize.ClassKept:
		return kept
	case anonymize.ClassAccount:
		return c.next("qzacct")
	case anonymize.ClassHost:
		return c.next("qzhost") + "." + c.next("qzdom") + ".lan"
	case anonymize.ClassAddress:
		return c.addressForm(addressForms[i%len(addressForms)])
	case anonymize.ClassHostOrAddr, anonymize.ClassHostOrNetgroup:
		j := i % (len(addressForms) + len(hostForms))
		if j < len(addressForms) {
			return c.addressForm(addressForms[j])
		}
		return c.hostForm(hostForms[j-len(addressForms)])
	case anonymize.ClassURL:
		return "https://" + c.next("qzacct") + "@" + c.next("qzhost") + "." + c.next("qzdom") + ".lan:8443/home/" +
			c.next("qzpath") + "/up?" + c.next("qzquery") + "#" + c.next("qzfrag")
	case anonymize.ClassFingerprint:
		w := c.next("qzfp")
		fp := "SHA256:" + w + strings.Repeat("A", 43-len(w))
		c.words = append(c.words, fp)
		return fp
	case anonymize.ClassMachineID:
		c.n++
		h := fmt.Sprintf("%056x", c.n) + "c0ffee00"
		c.words = append(c.words, h)
		return h
	case anonymize.ClassPath:
		return c.pathForm(i)
	case anonymize.ClassPlaceholder:
		return c.text()
	case anonymize.ClassBlank:
		return c.next("qzblank")
	case anonymize.ClassUnit:
		return "getty@" + c.next("qzinst") + ".service"
	case anonymize.ClassFSLocations:
		return "/home/" + c.next("qzpath") + "@" + c.next("qzhost") + ".lan"
	}
	c.tb.Fatalf("no canary for class %q", cl)
	return nil
}

func (c *canarySnap) grammar(g *anonymize.Grammar, i int) string {
	if g.Split == anonymize.SplitComma {
		keys := make([]string, 0, len(g.Values))
		for k := range g.Values {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := []string{"rw", "nodev"}
		for j, k := range keys {
			// An option value never holds the separator: the nft set
			// form (it carries ", ") is not an option value.
			f := i + j
			if n := len(addressForms) + len(hostForms); addressForms[f%len(addressForms)] == "nft-set" || f%n < len(addressForms) && addressForms[f%n] == "nft-set" {
				f++
			}
			parts = append(parts, k+"="+fmt.Sprint(c.leaf(g.Values[k], f, "kept")))
		}
		return strings.Join(parts, ",")
	}
	var toks []string
	for j, cl := range append(append([]anonymize.Class{}, g.Tokens...), g.Rest, g.Rest) {
		toks = append(toks, fmt.Sprint(c.leaf(cl, i+j, "pts/0")))
	}
	return strings.Join(toks, " ")
}

// children are the direct field names below table path rp.
func (c *canarySnap) children(rp string) []string {
	if c.kids == nil {
		c.index()
	}
	return c.kids[rp]
}

func (c *canarySnap) holdsAddress(rp string) bool {
	if c.kids == nil {
		c.index()
	}
	return c.addrUnder[rp]
}

// index computes, once, every row's direct children and whether an address
// class lies at or below it.
func (c *canarySnap) index() {
	seen := map[string]map[string]bool{}
	c.addrUnder = map[string]bool{}
	for row, r := range c.t {
		isAddr := r.Class == anonymize.ClassAddress || r.Class == anonymize.ClassHostOrAddr || r.Class == anonymize.ClassHostOrNetgroup
		for i := 0; i <= len(row); i++ {
			if i < len(row) && row[i] != '.' && row[i] != '[' {
				continue
			}
			if isAddr {
				c.addrUnder[row[:i]] = true
			}
			if i < len(row) && row[i] == '.' {
				rest := row[i+1:]
				if j := strings.IndexAny(rest, ".["); j >= 0 {
					rest = rest[:j]
				}
				if seen[row[:i]] == nil {
					seen[row[:i]] = map[string]bool{}
				}
				seen[row[:i]][rest] = true
			}
		}
	}
	c.kids = map[string][]string{}
	for p, m := range seen {
		for k := range m {
			c.kids[p] = append(c.kids[p], k)
		}
		sort.Strings(c.kids[p])
	}
}

// value builds the value at table path rp; kept is the value a kept leaf
// gets; i is the element index (it picks a form).
func (c *canarySnap) value(rp string, i int, kept any) any {
	if _, isList := c.t[rp+"[]"]; isList {
		c.rows[rp] = true
		n := 2
		if c.holdsAddress(rp + "[]") {
			n = len(addressForms) + len(hostForms)
		}
		l := make([]any, n)
		for j := range l {
			l[j] = c.value(rp+"[]", j, kept)
		}
		return l
	}
	if kids := c.children(rp); len(kids) > 0 {
		c.rows[rp] = true
		m := map[string]any{}
		acct := ""
		for _, k := range kids {
			if c.t[rp+"."+k].Home {
				c.rows[rp+"."+k] = true
				continue
			}
			m[k] = c.value(rp+"."+k, i, true)
			if a, ok := m[k].(string); ok && acct == "" && c.t[rp+"."+k].Class == anonymize.ClassAccount {
				acct = a
			}
		}
		// AX-6: a Home field's last component is its record's account.
		for _, k := range kids {
			if c.t[rp+"."+k].Home {
				if acct == "" {
					acct = c.next("qzhome")
				}
				m[k] = "/data/" + acct
			}
		}
		return m
	}
	r, ok := c.t[rp]
	if !ok {
		c.tb.Fatalf("no table row %s", rp)
	}
	c.rows[rp] = true
	switch r.Class {
	case anonymize.ClassGrammar:
		return c.grammar(r.Grammar, i)
	case "":
		return map[string]any{}
	}
	return c.leaf(r.Class, i, kept)
}

func (c *canarySnap) source(depth int) map[string]any {
	s := map[string]any{
		"kind": "file", "path": c.pathForm(c.n), "line": json.Number("3"),
		"raw": c.next("qzraw") + " " + canaryShort + " cut " + c.next("qzcut") + "…",
		"cmd": c.next("qzcmd") + " --host " + canaryShort, "exit_code": json.Number("0"),
	}
	if depth < 2 {
		s["inputs"] = []any{c.source(depth + 1)}
	}
	return s
}

func (c *canarySnap) envelope(key string, kept any) map[string]any {
	return map[string]any{
		"status": "ok", "value": c.value(key, 0, kept), "source": c.source(0),
		"truncated": true, "reason": c.text(),
	}
}

func keptFor(typ string) any {
	switch strings.TrimSuffix(strings.TrimPrefix(typ, "setting<"), ">") {
	case "bool":
		return true
	case "int":
		return json.Number("1")
	default:
		return "none"
	}
}

func (c *canarySnap) document() map[string]any {
	f := map[string]any{}
	for _, e := range c.reg.Keys {
		k := keptFor(e.Type)
		var v any
		if c.reg.IsSetting(e) {
			v = map[string]any{
				"runtime": c.envelope(e.Key, k), "persisted": c.envelope(e.Key, k),
				"effective": c.envelope(e.Key, k), "winner": c.source(0),
				"personas": map[string]any{
					"root": c.envelope(e.Key, k), "user": c.envelope(e.Key, k), "invalid": c.envelope(e.Key, k),
				},
			}
		} else {
			v = c.envelope(e.Key, k)
		}
		segs := strings.Split(e.Key, ".")
		m := f
		for _, s := range segs[:len(segs)-1] {
			sub, ok := m[s].(map[string]any)
			if !ok {
				sub = map[string]any{}
				m[s] = sub
			}
			m = sub
		}
		m[segs[len(segs)-1]] = v
	}
	// The two accounts the name-position paths are named after are account
	// values too, so the first pass maps them (AX-6).
	users := f["accounts"].(map[string]any)["users"].(map[string]any)
	users["value"] = append(users["value"].([]any),
		map[string]any{"name": canarySudoer, "uid": json.Number("1500")},
		map[string]any{"name": canarySpooler, "uid": json.Number("1501")})
	c.words = append(c.words, canarySudoer, canarySpooler, canaryShort, "qzsitedom",
		"/etc/sudoers.d/"+canarySudoer, "/var/spool/mail/"+canarySpooler, "987654321")

	machineID := fmt.Sprintf("%x", sha256.Sum256([]byte(canaryMachineID)))
	c.words = append(c.words, canaryMachineID, machineID, canaryBootID)
	return map[string]any{
		"synthetic":      true,
		"_notes":         []any{c.text()},
		"schema_version": json.Number("1"),
		"run": map[string]any{
			"muster_version": "dev", "commit": "", "controls_version": "", "controls_digest": "",
			"guide_edition": "kisa-unix-2026", "collected_at": "2026-10-29T00:00:00Z",
			"host": map[string]any{
				"hostname": canaryShort + ".qzsitedom.lan", "machine_id_hash": machineID, "kernel": "6.8.0-45-generic",
				"os_release": map[string]any{"id": "ubuntu", "version_id": "24.04", "family": "debian"},
				"boot_id":    c.next("qzboot"), "uptime_s": json.Number("987654321"),
			},
			"euid": json.Number("0"), "capabilities": []any{"cap_dac_read_search"},
			"env": map[string]any{"container": "none", "virt": "kvm", "wsl": false, "chroot": false, "has_systemd": true,
				"sysctl_writable": true, "cloud_init": false},
			"collectors": []any{map[string]any{"name": "accounts", "status": "error", "ms": json.Number("1"),
				"cmd": c.next("qzcmd") + " " + canaryShort, "reason": c.text()}},
			"redaction":        map[string]any{"profile": "default", "include_secrets": false, "redacted_fields": []any{}},
			"deep":             true,
			"complete":         false,
			"partial_failures": []any{c.text()},
		},
		"facts": f,
	}
}

// addrRun is a maximal run of the characters an address literal is made of.
var addrRun = regexp.MustCompile(`[0-9A-Fa-f:.]+`)

// leaks lists the canaries found in out: every word as a substring, every
// address as a whole token (a maximal run of hex digits, colons and dots, or
// one of its colon-separated pieces, a trailing dot dropped), so an IPv4
// literal never matches inside a longer one.
func (c *canarySnap) leaks(out []byte) []string {
	s := string(out)
	var found []string
	for _, w := range c.words {
		if strings.Contains(s, w) {
			found = append(found, w)
		}
	}
	toks := map[string]bool{}
	for _, run := range addrRun.FindAllString(s, -1) {
		toks[run] = true
		toks[strings.TrimRight(run, ".")] = true
		for _, p := range strings.Split(run, ":") {
			toks[p] = true
			toks[strings.TrimRight(p, ".")] = true
		}
	}
	for _, a := range c.addrs {
		if toks[a] {
			found = append(found, a)
		}
	}
	return found
}

// canaryFiles writes the canary snapshot and its anonymisation (through the
// command itself, under the fixed key) and returns the generator and both
// paths.
func canaryFiles(t *testing.T) (*canarySnap, string, string) {
	t.Helper()
	c := newCanarySnap(t)
	doc := c.document()
	body, err := encodeSnapshot(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	orig := filepath.Join(dir, "canary.json")
	if err := os.WriteFile(orig, body, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.bin")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(0xa0 + i)
	}
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	anonPath := filepath.Join(dir, "anon.json")
	if code, _, stderr := anon(t, "--facts", orig, "--key", keyPath, "--out", anonPath); code != exitOK {
		t.Fatalf("anonymize the canary snapshot: exit %d: %s", code, stderr)
	}
	return c, orig, anonPath
}

// outputsOf runs check (json, and the table with every observation) and fix
// --dry-run (json, table) over a snapshot, the way a receiver would.
func outputsOf(t *testing.T, path string) map[string][]byte {
	t.Helper()
	outs := map[string][]byte{}
	for name, args := range map[string][]string{
		"check json":  {"check", "--facts", path, "--format", "json"},
		"check table": {"check", "--facts", path, "--format", "table", "--all", "--color", "never"},
		"plan json":   {"fix", "--dry-run", "--facts", path, "--format", "json"},
		"plan table":  {"fix", "--dry-run", "--facts", path, "--format", "table", "--color", "never"},
	} {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		if out.Len() == 0 {
			t.Fatalf("%s: exit %d, nothing on stdout: %s", name, code, errb.String())
		}
		outs[name] = out.Bytes()
	}
	return outs
}

// §4 canary sweep: none of the canaries reaches the anonymised snapshot,
// nor the check JSON, the check table, the plan JSON or the plan table made
// from it. Every canary is in the original, every non-kept row and every
// form is placed, and the original's reports do carry canaries, so the
// sweep is not vacuous.
func TestCanarySweep(t *testing.T) {
	c, orig, anonPath := canaryFiles(t)
	origBytes := mustRead(t, orig)
	present := map[string]bool{}
	for _, w := range c.leaks(origBytes) {
		present[w] = true
	}
	var absent []string
	for _, w := range append(append([]string{}, c.words...), c.addrs...) {
		if !present[w] {
			absent = append(absent, w)
		}
	}
	if len(absent) > 0 {
		t.Fatalf("%d canaries are not in the original snapshot: %s", len(absent), strings.Join(first(absent, 20), ", "))
	}
	for row, r := range anonymize.Default {
		if r.Class == "" || r.Class == anonymize.ClassKept || strings.HasSuffix(row, ".*") {
			continue
		}
		if !c.rows[row] && !strings.HasPrefix(row, "run.") && !strings.HasPrefix(row, "envelope.") &&
			!strings.HasPrefix(row, "source.") && !strings.HasPrefix(row, "setting.") && !strings.HasPrefix(row, "_") {
			t.Errorf("table row %s (%s) holds no canary", row, r.Class)
		}
	}
	for _, f := range append(append([]string{}, addressForms...), hostForms...) {
		if c.forms[f] == 0 {
			t.Errorf("form %s was never placed", f)
		}
	}
	for _, f := range pathForms {
		if c.forms["path:"+f] == 0 {
			t.Errorf("path form %s was never placed", f)
		}
	}

	anonBytes := mustRead(t, anonPath)
	if l := c.leaks(anonBytes); len(l) > 0 {
		t.Errorf("the anonymised snapshot carries %d canaries: %s", len(l), strings.Join(first(l, 20), ", "))
	}
	origOuts := outputsOf(t, orig)
	for name, out := range outputsOf(t, anonPath) {
		if l := c.leaks(out); len(l) > 0 {
			t.Errorf("the %s of the anonymised snapshot carries %d canaries: %s", name, len(l), strings.Join(first(l, 20), ", "))
		}
		if len(c.leaks(origOuts[name])) == 0 {
			t.Errorf("the %s of the original carries no canary: the sweep over it proves nothing", name)
		}
	}
	t.Logf("%d canary words, %d address canaries, %d rows placed", len(c.words), len(c.addrs), len(c.rows))
}

func first(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}

// addrClass names the §1.1 range an address lies in ("public4"/"public6"
// outside every special range), built from octets.
func addrClass(a netip.Addr) string {
	a = a.WithZone("")
	p4 := func(a, b, c, d byte, bits int) netip.Prefix {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
	}
	p6 := func(hi, next uint16, bits int) netip.Prefix {
		var b [16]byte
		b[0], b[1], b[2], b[3] = byte(hi>>8), byte(hi), byte(next>>8), byte(next)
		return netip.PrefixFrom(netip.AddrFrom16(b), bits)
	}
	ranges := []netip.Prefix{
		p4(0, 0, 0, 0, 8), p4(127, 0, 0, 0, 8), p4(224, 0, 0, 0, 4), p4(240, 0, 0, 0, 4),
		p4(192, 0, 2, 0, 24), p4(198, 51, 100, 0, 24), p4(203, 0, 113, 0, 24),
		p4(10, 0, 0, 0, 8), p4(100, 64, 0, 0, 10), p4(169, 254, 0, 0, 16), p4(172, 16, 0, 0, 12),
		p4(192, 168, 0, 0, 16), p4(198, 18, 0, 0, 15),
		p6(0xff00, 0, 8), p6(0x2001, 0x0db8, 32), p6(0xfc00, 0, 7), p6(0xfe80, 0, 10),
	}
	for _, r := range ranges {
		if r.Contains(a) {
			return r.String()
		}
	}
	if a.Is4() {
		return "public4"
	}
	return "public6"
}

// §4 properties over the canary host: deterministic per key; injective per
// class; every address keeps its class; every host-or-address form is
// mapped by its own rule (none falls through to the placeholder); the output
// passes facts.Load; an anonymised input is refused.
func TestCanaryProperties(t *testing.T) {
	c, orig, anonPath := canaryFiles(t)
	k := invariantKey(t)
	a := mustRead(t, anonPath)
	if !bytes.Equal(a, anonymizeBytes(t, orig, mustRead(t, orig), k)) {
		t.Error("two runs under one key over one input differ")
	}
	loadSnap(t, a)

	seen := map[string]map[string]string{"account": {}, "host": {}, "address": {}}
	inj := func(class, in, out string) {
		if prev, ok := seen[class][out]; ok && prev != in {
			t.Errorf("%s: %q and %q both map to %q", class, prev, in, out)
		}
		seen[class][out] = in
	}
	for _, w := range c.words {
		switch {
		case strings.HasPrefix(w, "qzacct"):
			inj("account", w, k.Account(w))
		case strings.HasPrefix(w, "qzhost"):
			inj("host", w, k.Host(w+".lan"))
		}
	}
	for _, s := range c.addrs {
		in, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("canary %q: %v", s, err)
		}
		out := k.Addr(in)
		inj("address", in.String(), out.String())
		if addrClass(in) != addrClass(out) {
			t.Errorf("%s (%s) maps to %s (%s): the class changed", in, addrClass(in), out, addrClass(out))
		}
	}

	var doc map[string]any
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	f := doc["facts"].(map[string]any)
	for _, key := range []string{"time_sync.servers", "snmp.agent_addresses"} {
		l := listAt(t, f, key)
		if len(l) != len(addressForms)+len(hostForms) {
			t.Errorf("%s: %d elements, want one per form", key, len(l))
		}
		for _, e := range l {
			if e == anonymize.Placeholder {
				t.Errorf("%s: a host-or-address form fell through to the placeholder", key)
			}
		}
	}

	code, stdout, stderr := anon(t, "--facts", anonPath, "--ephemeral", "--out", "-")
	if code != exitError || stdout != "" || !strings.Contains(stderr, "already anonymised") {
		t.Errorf("anonymising the output: exit %d, stdout %d bytes, stderr %q", code, len(stdout), stderr)
	}
}

// exposureDoc is a synthetic host: postgres listens on loopback only and
// sshd on every address, with an open input policy, so exposure.exposed (the
// collector's join) holds tcp/22 alone and exposed_listeners_allowed passes.
func exposureDoc() map[string]any {
	lo := v4(127, 0, 0, 1)
	any4 := v4(0, 0, 0, 0)
	ok := func(v any) map[string]any {
		return map[string]any{"status": "ok", "value": v, "source": map[string]any{"kind": "derived"}}
	}
	return map[string]any{
		"synthetic": true, "schema_version": json.Number("1"), "run": map[string]any{},
		"facts": map[string]any{
			"env": map[string]any{"container": ok("none")},
			"sockets": map[string]any{"listening": ok([]any{
				map[string]any{"proto": "tcp", "addr": lo, "port": json.Number("5432"), "inode": json.Number("11"), "loopback": true},
				map[string]any{"proto": "tcp", "addr": any4, "port": json.Number("22"), "inode": json.Number("12"), "loopback": false},
			})},
			"exposure": map[string]any{"exposed": ok([]any{
				map[string]any{"service": "tcp/22", "proto": "tcp", "family": "v4", "addr": any4, "port": json.Number("22"), "via": "open_policy"},
			})},
		},
	}
}

// deriveExposureAfterMapping is the test-only hook of delete-the-call case 4
// (spec §4): it maps every listening socket's address by m first and then
// re-derives the loopback boolean and exposure.exposed from the mapped
// address, by a copy of the collector's classification (isLoopback: an
// address in 127.0.0.0/8 or ::1; every other listener is exposed under an
// open policy). That is an anonymiser that ran before the join.
func deriveExposureAfterMapping(doc map[string]any, m func(string) string) {
	f := doc["facts"].(map[string]any)
	socks := f["sockets"].(map[string]any)["listening"].(map[string]any)["value"].([]any)
	var exposed []any
	for _, s := range socks {
		row := s.(map[string]any)
		row["addr"] = m(row["addr"].(string))
		a, err := netip.ParseAddr(row["addr"].(string))
		loopback := err == nil && a.IsLoopback()
		row["loopback"] = loopback
		if loopback {
			continue
		}
		exposed = append(exposed, map[string]any{"service": "tcp/" + row["port"].(json.Number).String(), "proto": "tcp",
			"family": "v4", "addr": row["addr"], "port": row["port"], "via": "open_policy"})
	}
	f["exposure"].(map[string]any)["exposed"].(map[string]any)["value"] = exposed
}

func exposureVerdict(t *testing.T, doc map[string]any) check.Status {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	set, err := controls.LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := facts.LoadRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range evaluate(selections(t, set)["default"], loadCorpusSnapshot(t, "exposure", b), reg) {
		if r.ID == "muster.beyond.exposed_listeners_allowed" {
			return r.Status
		}
	}
	t.Fatal("exposed_listeners_allowed not evaluated")
	return ""
}

// Delete-the-call case 4: mapping an address before exposure is derived.
// The hook with the identity map reproduces the collector's PASS; with a
// map that crosses classes (a plain hash into the IPv4 space, which sends
// 127.0.0.1 off loopback) the same derivation exposes postgres and the
// verdict turns FAIL. Transform runs after the join and keeps the derived
// booleans and the list as collected, so its verdict is the original's; and
// its address map keeps class, so even a late derivation over it would
// agree.
func TestAddressMappedBeforeExposureIsDerived(t *testing.T) {
	k := invariantKey(t)
	if got := exposureVerdict(t, exposureDoc()); got != check.PASS {
		t.Fatalf("the original reads %s, want PASS", got)
	}
	ident := exposureDoc()
	deriveExposureAfterMapping(ident, func(s string) string { return s })
	if got := exposureVerdict(t, ident); got != check.PASS {
		t.Fatalf("the hook with the identity map reads %s: it does not copy the collector", got)
	}
	crossClass := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		out := netip.AddrFrom4([4]byte{sum[0], sum[1], sum[2], sum[3]})
		for out.IsLoopback() || out.IsUnspecified() {
			out = out.Next()
		}
		return out.String()
	}
	early := exposureDoc()
	deriveExposureAfterMapping(early, crossClass)
	if got := exposureVerdict(t, early); got != check.FAIL {
		t.Errorf("mapping across classes before the join reads %s, want FAIL (the hook must show the hazard)", got)
	}
	keep := exposureDoc()
	deriveExposureAfterMapping(keep, func(s string) string {
		out, ok := k.AddrToken(s)
		if !ok {
			t.Fatalf("AddrToken(%q) refused", s)
		}
		return out
	})
	if got := exposureVerdict(t, keep); got != check.PASS {
		t.Errorf("a late derivation over the class-keeping map reads %s, want PASS", got)
	}
	b, err := json.Marshal(exposureDoc())
	if err != nil {
		t.Fatal(err)
	}
	var anonDoc map[string]any
	if err := json.Unmarshal(anonymizeBytes(t, "exposure", b, k), &anonDoc); err != nil {
		t.Fatal(err)
	}
	if got := exposureVerdict(t, anonDoc); got != check.PASS {
		t.Errorf("Transform's output reads %s, want the original's PASS", got)
	}
	socks := listAt(t, anonDoc["facts"].(map[string]any), "sockets.listening")
	seen := 0
	for _, s := range socks {
		row := s.(map[string]any)
		if row["port"] == json.Number("5432") || row["port"] == float64(5432) {
			seen++
			if row["loopback"] != true {
				t.Errorf("Transform changed the derived loopback boolean: %v", row)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no listener on port 5432 in the anonymised snapshot")
	}
}
