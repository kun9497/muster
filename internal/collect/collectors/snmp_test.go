//go:build linux

package collectors

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// The host paths the snmp collector declares, spelled here as literals so a
// test asserts against the real path rather than against whatever the
// collector happens to have named its constant.
const (
	testSnmpdConf      = "/etc/snmp/snmpd.conf"
	testSnmpdFragment  = "/etc/snmp/snmpd.conf.d/50-extra.conf"
	testSnmpStateFile  = "/var/lib/snmp/snmpd.conf"
	testSnmpUndeclared = "/opt/vendor/snmpd-extra.conf"
)

// snmpAccess seeds every map fsAccess exposes (files, cmds, fails, dirs,
// stats) so a test may assign into any of them after construction without
// tripping a nil-map panic (the R226/I-20 lesson).
func snmpAccess(files map[string]string, cmds map[string]cmdResult) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	if cmds == nil {
		cmds = map[string]cmdResult{}
	}
	return &fsAccess{
		files: files,
		cmds:  cmds,
		fails: map[string]error{},
		dirs:  map[string]bool{},
		stats: map[string]statResult{},
	}
}

// treeJSON serialises the whole facts tree the builder holds (Ruling J-29).
// No helper renders a Builder, and facts.Envelope carries JSON tags, so
// marshalling b.Tree() is the entire helper — and it is the only way to
// assert that a secret is absent from EVERY envelope, reason, source and
// record field at once rather than from the handful a test remembered to
// look at.
func treeJSON(t *testing.T, b *collect.Builder) []byte {
	t.Helper()
	data, err := json.Marshal(b.Tree())
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	return data
}

// snmpSubtreeJSON serialises only the snmp subtree. A word like "public" may
// legitimately appear elsewhere in a snapshot (a source path, a view name, a
// sensitivity label), so the "a default community string never leaks"
// assertion is scoped to the subtree this collector owns.
func snmpSubtreeJSON(t *testing.T, b *collect.Builder) []byte {
	t.Helper()
	data, err := json.Marshal(b.Tree()["snmp"])
	if err != nil {
		t.Fatalf("marshal snmp subtree: %v", err)
	}
	return data
}

// stringList fetches an ok list<string> fact as a []string, reporting the
// offending element rather than panicking on a type assertion.
func stringList(t *testing.T, b *collect.Builder, key string) []string {
	t.Helper()
	out := []string{}
	for i, v := range okList(t, b, key) {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s[%d] = %#v, not a string", key, i, v)
		}
		out = append(out, s)
	}
	return out
}

// snmpRecord fetches one list<record> element as a map, failing the test rather
// than panicking when the collector produced something else.
func snmpRecord(t *testing.T, list []any, i int) map[string]any {
	t.Helper()
	if i >= len(list) {
		t.Fatalf("record %d out of range in %v", i, list)
	}
	m, ok := list[i].(map[string]any)
	if !ok {
		t.Fatalf("element %d = %#v, not a record", i, list[i])
	}
	return m
}

// rocommunity/rwcommunity are redacted to {ref, kind, is_default, length,
// source_restricted}: ref is an opaque ordinal in FILE order (never a hash —
// a hash of a short string is trivially reversible), and the string itself
// reaches no envelope, reason, source or record field anywhere in the
// snapshot (Ruling J-7).
func TestSnmpCommunitiesAreRedacted(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{testSnmpdConf: "snmpd.conf.v2c-public"}, nil))
	recs := okList(t, b, "snmp.communities")
	if len(recs) != 2 {
		t.Fatalf("communities %v, want 2 records", recs)
	}

	// c1 — "rocommunity public": the well-known default, no source.
	ro := snmpRecord(t, recs, 0)
	if ro["ref"] != "c1" || ro["kind"] != "ro" || ro["is_default"] != true ||
		ro["length"] != 6 || ro["source_restricted"] != false {
		t.Errorf("communities[0] = %v, want {ref c1, kind ro, is_default true, length 6, source_restricted false}", ro)
	}
	// c2 — "rwcommunity <13 runes> 192.0.2.0/24": not a default, restricted.
	rw := snmpRecord(t, recs, 1)
	if rw["ref"] != "c2" || rw["kind"] != "rw" || rw["is_default"] != false ||
		rw["length"] != 13 || rw["source_restricted"] != true {
		t.Errorf("communities[1] = %v, want {ref c2, kind rw, is_default false, length 13, source_restricted true}", rw)
	}
	// The record carries the five fields and NOTHING else — no "value", no
	// "raw", no digest.
	for _, r := range []map[string]any{ro, rw} {
		if len(r) != 5 {
			t.Errorf("community record %v carries %d fields, want exactly the five redacted ones", r, len(r))
		}
	}

	// The strings themselves are nowhere in the serialised snapshot.
	if bytes.Contains(treeJSON(t, b), []byte("s3cr3tLongOne")) {
		t.Error("community string leaked into the snapshot")
	}
	if bytes.Contains(snmpSubtreeJSON(t, b), []byte("public")) {
		t.Error("the default community string leaked into the snmp subtree")
	}

	// A community directive enables the two community-based versions.
	if v := stringList(t, b, "snmp.versions_enabled"); !slices.Equal(v, []string{"v1", "v2c"}) {
		t.Errorf("versions_enabled %v, want [v1 v2c]", v)
	}
	if a := stringList(t, b, "snmp.agent_addresses"); !slices.Equal(a, []string{"udp:161", "udp6:[::1]:161"}) {
		t.Errorf("agent_addresses %v, want both comma-separated specs", a)
	}
	if e := env(t, b, "snmp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v, want ok true", e)
	}
	if got := b.Worst("snmp"); got != facts.StatusOK {
		t.Errorf(`Worst("snmp") = %s, want ok`, got)
	}
}

// com2sec's fields are positional and easy to transpose: the SOURCE is the
// middle field and the COMMUNITY is the LAST one. Getting them the wrong way
// round would publish the community as an access-rule source (a leak) and
// judge the source's length as the community's strength.
func TestSnmpCom2secSourceAndCommunity(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{testSnmpdConf: "snmpd.conf.com2sec"}, nil))

	recs := okList(t, b, "snmp.communities")
	if len(recs) != 1 {
		t.Fatalf("communities %v, want 1 record", recs)
	}
	c := snmpRecord(t, recs, 0)
	// 17 runes is the community (the last field); the source is 198.51.100.0/24,
	// whose length (15) would be the answer if the two were transposed.
	if c["ref"] != "c1" || c["kind"] != "ro" || c["is_default"] != false ||
		c["length"] != 17 || c["source_restricted"] != true {
		t.Errorf("community %v, want {ref c1, kind ro, is_default false, length 17, source_restricted true}", c)
	}

	rules := okList(t, b, "snmp.access_rules")
	if len(rules) != 4 {
		t.Fatalf("access_rules %v, want the com2sec, group, view and access lines in file order", rules)
	}
	c2s := snmpRecord(t, rules, 0)
	if c2s["kind"] != "com2sec" || c2s["name"] != "readonlySec" || c2s["source"] != "198.51.100.0/24" {
		t.Errorf("access_rules[0] = %v, want the com2sec rule with source 198.51.100.0/24", c2s)
	}
	if snmpRecord(t, rules, 1)["kind"] != "group" || snmpRecord(t, rules, 2)["kind"] != "view" ||
		snmpRecord(t, rules, 3)["kind"] != "access" {
		t.Errorf("access_rules kinds %v, want com2sec, group, view, access in file order", rules)
	}

	// The community reaches no field of any record — not the access rule's
	// source, not anywhere else in the snapshot.
	if bytes.Contains(treeJSON(t, b), []byte("c0mmun1tyOnlyHere")) {
		t.Error("the com2sec community string leaked into the snapshot")
	}

	// A com2sec is only a v2c enablement because a group names the v2c model
	// for its security name.
	if v := stringList(t, b, "snmp.versions_enabled"); !slices.Equal(v, []string{"v2c"}) {
		t.Errorf("versions_enabled %v, want [v2c] (the group names the v2c model)", v)
	}
}

// A v3-only host: createUser lives in the root-only persistent state file
// and rouser in snmpd.conf, so both files have to be parsed to see the whole
// user set. No community directive anywhere means no v1/v2c and an empty
// communities list — never a missing one.
func TestSnmpV3OnlyFromStateFile(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{
		testSnmpdConf:     "snmpd.conf.v3-only",
		testSnmpStateFile: "var-lib-snmpd.conf.v3",
	}, nil))

	if v := stringList(t, b, "snmp.versions_enabled"); !slices.Equal(v, []string{"v3"}) {
		t.Errorf("versions_enabled %v, want [v3]", v)
	}
	if recs := okList(t, b, "snmp.communities"); len(recs) != 0 {
		t.Errorf("communities %v, want empty", recs)
	}

	users := okList(t, b, "snmp.v3_users")
	if len(users) != 2 {
		t.Fatalf("v3_users %v, want the state file's createUser and snmpd.conf's rouser", users)
	}
	// Sorted by name: "aStateOnlyUser" before "confOnlyUser".
	state := snmpRecord(t, users, 0)
	if state["name"] != "aStateOnlyUser" || state["auth_proto"] != "SHA-512" ||
		state["priv_proto"] != "AES-256" || state["level"] != "priv" {
		t.Errorf("v3_users[0] = %v, want the createUser record with its protocols and level", state)
	}
	conf := snmpRecord(t, users, 1)
	if conf["name"] != "confOnlyUser" || conf["level"] != "priv" ||
		conf["auth_proto"] != "" || conf["priv_proto"] != "" {
		t.Errorf("v3_users[1] = %v, want the rouser record with no key material", conf)
	}
	for _, u := range []map[string]any{state, conf} {
		if len(u) != 4 {
			t.Errorf("v3_users record %v carries %d fields, want exactly {name, auth_proto, priv_proto, level}", u, len(u))
		}
	}

	// The passphrases in the state file are key material and never leave it.
	for _, secret := range []string{"authPhraseAlphaOne", "privPhraseBetaTwo"} {
		if bytes.Contains(treeJSON(t, b), []byte(secret)) {
			t.Errorf("v3 key material %q leaked into the snapshot", secret)
		}
	}
	if files := stringList(t, b, "snmp.config_files"); !slices.Equal(files, []string{testSnmpdConf, testSnmpStateFile}) {
		t.Errorf("config_files %v, want both files sorted", files)
	}
}

// includeDir is expanded IN PLACE: the fragment it names is parsed where the
// directive appears, before the rest of the file. The fragment's community is
// therefore c1 and snmpd.conf's own is c2 — the reverse of what the
// declared-glob sweep alone would produce.
func TestSnmpFollowsDeclaredIncludes(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{
		testSnmpdConf:     "snmpd.conf.includes",
		testSnmpdFragment: "snmpd.conf.d_50-extra.conf",
	}, nil))

	recs := okList(t, b, "snmp.communities")
	if len(recs) != 2 {
		t.Fatalf("communities %v, want 2 records", recs)
	}
	frag := snmpRecord(t, recs, 0)
	if frag["ref"] != "c1" || frag["kind"] != "rw" || frag["length"] != 18 || frag["source_restricted"] != true {
		t.Errorf("communities[0] = %v, want the includeDir fragment's rw community first (expanded in place)", frag)
	}
	main := snmpRecord(t, recs, 1)
	if main["ref"] != "c2" || main["kind"] != "ro" || main["is_default"] != true {
		t.Errorf("communities[1] = %v, want snmpd.conf's own default community second", main)
	}

	// The fragment is parsed exactly once even though the declared glob would
	// also have found it.
	if files := stringList(t, b, "snmp.config_files"); !slices.Equal(files, []string{testSnmpdConf, testSnmpdFragment}) {
		t.Errorf("config_files %v, want each file exactly once, sorted", files)
	}
	if e := env(t, b, "snmp.parse_complete"); e.Value != true {
		t.Errorf("parse_complete %+v, want ok true", e)
	}
}

// An includeFile outside the collector's declaration is RECORDED, never
// touched (R55/R75). The configuration was not seen in full, so the judged
// lists are absent — the honest "needs review" — rather than a confident
// answer built from the part that was readable.
func TestSnmpUnreadableIncludeMakesJudgedListsAbsent(t *testing.T) {
	a := snmpAccess(map[string]string{testSnmpdConf: "snmpd.conf.include-undeclared"}, nil)
	b := buildBegun(t, "snmp", a)

	for _, k := range []string{"snmp.versions_enabled", "snmp.communities", "snmp.v3_users"} {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s %+v, want absent", k, e)
		}
		if !strings.Contains(e.Reason, testSnmpUndeclared) {
			t.Errorf("%s reason %q, want it to name %s", k, e.Reason, testSnmpUndeclared)
		}
	}
	if e := env(t, b, "snmp.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete %+v, want ok false", e)
	}
	if files := stringList(t, b, "snmp.config_files"); !slices.Equal(files, []string{testSnmpdConf}) {
		t.Errorf("config_files %v, want only the file that was read", files)
	}
	if slices.Contains(a.reads, testSnmpUndeclared) {
		t.Errorf("an undeclared include must never be read: reads = %v", a.reads)
	}
	// Not seeing part of the configuration is not an environment failure.
	if got := b.Worst("snmp"); got != facts.StatusOK {
		t.Errorf(`Worst("snmp") = %s, want ok`, got)
	}
}

// The persistent state file is root-only. Read as a non-root user it is
// denied, and C3 makes that read's status the answer for every value the file
// could have set — an honest ERROR, never a silent "this host has no v3".
func TestSnmpNonRootStateFileIsDenied(t *testing.T) {
	a := snmpAccess(map[string]string{testSnmpdConf: "snmpd.conf.v2c-public"}, nil)
	a.fails[testSnmpStateFile] = os.ErrPermission
	b := buildBegun(t, "snmp", a)

	for _, k := range []string{"snmp.versions_enabled", "snmp.communities", "snmp.v3_users"} {
		e := env(t, b, k)
		if e.Status != facts.StatusDenied {
			t.Errorf("%s %+v, want denied", k, e)
		}
		if !strings.Contains(e.Reason, testSnmpStateFile) {
			t.Errorf("%s reason %q, want it to name %s", k, e.Reason, testSnmpStateFile)
		}
	}
	if e := env(t, b, "snmp.parse_complete"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("parse_complete %+v, want ok false", e)
	}
	// The evidence gathered from the readable file stays ok.
	if e := env(t, b, "snmp.agent_addresses"); e.Status != facts.StatusOK {
		t.Errorf("agent_addresses %+v, want ok", e)
	}
	if got := b.Worst("snmp"); got != facts.StatusDenied {
		t.Errorf(`Worst("snmp") = %s, want denied (an honest ERROR, not a silent pass)`, got)
	}
	// Even a denied run may not leak: nothing that was readable carries a
	// community string.
	if bytes.Contains(treeJSON(t, b), []byte("s3cr3tLongOne")) {
		t.Error("community string leaked into a denied snapshot")
	}
}

// As root, a state file that is simply not there means nothing was ever
// persisted: v3_users is a definite empty list, not an error and not missing.
func TestSnmpMissingStateFileIsEmpty(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(map[string]string{testSnmpdConf: "snmpd.conf.v2c-public"}, nil))

	e := env(t, b, "snmp.v3_users")
	if e.Status != facts.StatusOK {
		t.Fatalf("v3_users %+v, want ok", e)
	}
	if users := okList(t, b, "snmp.v3_users"); len(users) != 0 {
		t.Errorf("v3_users %v, want empty", users)
	}
	if v := stringList(t, b, "snmp.versions_enabled"); slices.Contains(v, "v3") {
		t.Errorf("versions_enabled %v, want no v3 when no user is configured", v)
	}
	if got := b.Worst("snmp"); got != facts.StatusOK {
		t.Errorf(`Worst("snmp") = %s, want ok`, got)
	}
}

// No snmpd configuration at all: the judged lists are absent (naming the
// paths that were looked for) so a control reads MANUAL rather than
// "v1 is not enabled", the evidence leaves are ok, every registered key is
// set, and the run stays complete.
func TestSnmpNoConfigIsAbsentNotMissing(t *testing.T) {
	b := buildBegun(t, "snmp", snmpAccess(nil, nil))

	for _, k := range []string{"snmp.versions_enabled", "snmp.communities", "snmp.v3_users"} {
		e := env(t, b, k)
		if e.Status != facts.StatusAbsent {
			t.Errorf("%s %+v, want absent", k, e)
		}
		if !strings.Contains(e.Reason, testSnmpdConf) {
			t.Errorf("%s reason %q, want it to name the paths that were looked for", k, e.Reason)
		}
	}
	if files := stringList(t, b, "snmp.config_files"); len(files) != 0 {
		t.Errorf("config_files %v, want empty", files)
	}
	if rules := okList(t, b, "snmp.access_rules"); len(rules) != 0 {
		t.Errorf("access_rules %v, want empty", rules)
	}
	if addrs := okList(t, b, "snmp.agent_addresses"); len(addrs) != 0 {
		t.Errorf("agent_addresses %v, want empty", addrs)
	}
	if e := env(t, b, "snmp.parse_complete"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("parse_complete %+v, want ok true (there was nothing to fail to read)", e)
	}
	if got := b.Worst("snmp"); got != facts.StatusOK {
		t.Errorf(`Worst("snmp") = %s, want ok (a host that does not run snmpd is not a failure)`, got)
	}
}
