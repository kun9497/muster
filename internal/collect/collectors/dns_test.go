//go:build linux

package collectors

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// Host paths the fixtures are served from. The main configuration files have
// named constants in dns.go; the include targets and the os-release files are
// spelled here, because a test that names the same literal the declaration
// names is what proves the declaration covers it.
const (
	bindOptionsFragment  = "/etc/bind/named.conf.options"
	bindLocalFragment    = "/etc/bind/named.conf.local"
	bindDefaultZones     = "/etc/bind/named.conf.default-zones"
	namedOpenInclude     = "/etc/named/open.conf"
	namedLoopA           = "/etc/named/loop-a.conf"
	namedLoopB           = "/etc/named/loop-b.conf"
	rhelCryptoPolicy     = "/etc/crypto-policies/back-ends/bind.config"
	rhel1912Zones        = "/etc/named.rfc1912.zones"
	rhelRootKey          = "/etc/named.root.key"
	namedCustomInclude   = "/etc/named/custom.conf"
	namedTransferInclude = "/etc/named/transfer.conf"
	undeclaredInclude    = "/srv/x.conf"
	namedFanA            = "/etc/named/fan-a.conf"
	namedFanB            = "/etc/named/fan-b.conf"
)

// dnsAccess builds the double for the dns collector. Ruling I-20: every map a
// test of this collector reaches into is initialised here — a later
// `a.fails[…] = …`, `a.stats[…] = …` or `a.truncated[…] = …` on a nil map
// panics — and Ruling L-31: `stats` carries `kind: "dir"` for
// /run/systemd/system and `kind: "regular"` for every daemon binary, derived
// from the configuration files the fixture seeds, exactly as loggingAccess
// does.
//
// Ruling L-3: a configuration file names an implementation only when the
// daemon's BINARY is installed too, so a fixture that seeds one seeds the
// other; a test about a conffile left behind by a removed package deletes the
// binary again.
func dnsAccess(files map[string]string) *fsAccess {
	if files == nil {
		files = map[string]string{}
	}
	stats := map[string]statResult{"/run/systemd/system": {mode: 0o755, kind: "dir"}}
	for p := range files {
		var bin string
		switch p {
		case bindDebianConf, bindRhelConf, bindChrootConf:
			bin = namedBin
		case unboundConf:
			bin = unboundBin
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

// dnsJudgedLeaves are the leaves a control judges, as opposed to the evidence
// leaves (implementation, config_files, parse_complete, unmodelled) that stay
// ok whatever the parse found. Ruling L-4: a read that failed, a read cut at
// the cap or a construct outside the model makes every one of them absent.
var dnsJudgedLeaves = []string{
	"dns.options.allow_transfer",
	"dns.options.allow_update",
	"dns.zones",
}

// dnsAllLeaves is every key this collector registers. Each is published on
// EVERY path — a host with no DNS server included — so a control can never
// read one as missing.
var dnsAllLeaves = append([]string{
	"dns.implementation", "dns.config_files", "dns.parse_complete", "dns.unmodelled",
}, dnsJudgedLeaves...)

// dnsComplete asserts that every registered key of the collector was
// published, whatever the host turned out to be.
func dnsComplete(t *testing.T, b *collect.Builder) {
	t.Helper()
	for _, k := range dnsAllLeaves {
		env(t, b, k)
	}
}

func dnsString(t *testing.T, b *collect.Builder, key string) string {
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

func dnsBool(t *testing.T, b *collect.Builder, key string) bool {
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

func dnsInt(t *testing.T, b *collect.Builder, key string) int {
	t.Helper()
	e := env(t, b, key)
	if e.Status != facts.StatusOK {
		t.Fatalf("%s: %+v, want an ok int", key, e)
	}
	v, ok := e.Value.(int)
	if !ok {
		t.Fatalf("%s: value %#v is not an int", key, e.Value)
	}
	return v
}

// dnsZoneNames is dns.zones reduced to the zone names, in the order the leaf
// carries them — the list is sorted by name, so the order is part of the
// contract.
func dnsZoneNames(t *testing.T, b *collect.Builder) []string {
	t.Helper()
	var out []string
	for i, v := range okList(t, b, "dns.zones") {
		rec, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("dns.zones[%d] = %#v, not a record", i, v)
		}
		name, _ := rec["name"].(string)
		out = append(out, name)
	}
	return out
}

// dnsZoneRec is one zone record by name.
func dnsZoneRec(t *testing.T, b *collect.Builder, name string) map[string]any {
	t.Helper()
	for _, v := range okList(t, b, "dns.zones") {
		rec, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if rec["name"] == name {
			return rec
		}
	}
	t.Fatalf("dns.zones carries no zone %q", name)
	return nil
}

// recField asserts one record field equals want; a field the record does not
// carry at all is reported as such rather than as a nil mismatch.
func recField(t *testing.T, rec map[string]any, field string, want any) {
	t.Helper()
	got, ok := rec[field]
	if !ok {
		t.Errorf("zone %v carries no %s field", rec["name"], field)
		return
	}
	if got != want {
		t.Errorf("zone %v: %s = %#v, want %#v", rec["name"], field, got, want)
	}
}

// recAbsent asserts a record field is NOT there — how a record says "this
// question has no answer", since a record field carries no envelope of its
// own.
func recAbsent(t *testing.T, rec map[string]any, field string) {
	t.Helper()
	if got, ok := rec[field]; ok {
		t.Errorf("zone %v: %s = %#v, want the field to be absent", rec["name"], field, got)
	}
}

// Ruling L-56: the STOCK Debian/Ubuntu chain — named.conf includes
// named.conf.options (which sets no allow-transfer), the empty local fragment,
// and named.conf.default-zones with the root hint and the four RFC 1912
// localhost zones. Nothing sets allow-transfer anywhere, so on an Ubuntu 22.04
// build (BIND 9.18) every one of those four master zones inherits the compiled
// default any and is NOT restricted — the package default, reported honestly.
func TestDnsBindDebianChain(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindDebianConf:      "named.conf.debian",
		bindOptionsFragment: "named.conf.options",
		bindLocalFragment:   "named.conf.local",
		bindDefaultZones:    "named.conf.default-zones",
		etcOSRelease:        "os-release.ubuntu2204",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "bind" {
		t.Fatalf("implementation %+v, want ok bind", e)
	}
	want := []string{bindDebianConf, bindDefaultZones, bindLocalFragment, bindOptionsFragment}
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, want) {
		t.Errorf("config_files %v, want %v", got, want)
	}
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("every file of the chain was read in full")
	}
	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0", n)
	}
	absentBecause(t, b, "dns.options.allow_transfer", "9.16/9.18", "ubuntu 22.04", "defaults to any")
	absentBecause(t, b, "dns.options.allow_update", "none in every version")

	wantZones := []string{".", "0.in-addr.arpa", "127.in-addr.arpa", "255.in-addr.arpa", "localhost"}
	if got := dnsZoneNames(t, b); !slices.Equal(got, wantZones) {
		t.Fatalf("zones %v, want %v", got, wantZones)
	}
	root := dnsZoneRec(t, b, ".")
	recField(t, root, "type", "hint")
	recField(t, root, "file", "/usr/share/dns/root.hints")

	for _, name := range []string{"0.in-addr.arpa", "127.in-addr.arpa", "255.in-addr.arpa", "localhost"} {
		z := dnsZoneRec(t, b, name)
		recField(t, z, "type", "master")
		// Nothing sets a list at either level, so the build default decides.
		recField(t, z, "transfer_restricted", false)
		recAbsent(t, z, "allow_transfer")
		// An unset allow-update is none in every version.
		recField(t, z, "update_restricted", true)
		recAbsent(t, z, "allow_update")
	}
	recField(t, dnsZoneRec(t, b, "localhost"), "file", "/etc/bind/db.local")

	if w := b.Worst("dns"); w != facts.StatusOK {
		t.Errorf(`Worst("dns") = %s, want ok`, w)
	}
}

// A zone that sets no list of its own inherits the options level's refusal —
// the shape a hardened Debian host is in once an operator adds
// "allow-transfer { none; };" to named.conf.options.
func TestDnsZoneInheritsOptionsRefusal(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.inherit-none",
		etcOSRelease: "os-release.ubuntu2204",
	}))
	dnsComplete(t, b)

	if got := dnsString(t, b, "dns.options.allow_transfer"); got != "none" {
		t.Errorf("options.allow_transfer = %q, want none", got)
	}
	z := dnsZoneRec(t, b, "example.org")
	recField(t, z, "allow_transfer", "none")
	recField(t, z, "transfer_restricted", true)
	recField(t, z, "update_restricted", true)
	recAbsent(t, z, "allow_update")
}

// RHEL 9's stock chain: the crypto-policy fragment is included INSIDE
// options {} and the zone file and the root key at the top level. All three
// are declared, all three are tokenised in place, and nothing in them is
// outside the model (Ruling L-18).
func TestDnsBindRhelChain(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf:     "named.conf.rhel",
		rhelCryptoPolicy: "bind.config.rhel",
		rhel1912Zones:    "named.rfc1912.zones",
		rhelRootKey:      "named.root.key",
		etcOSRelease:     "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("every file of the RHEL chain was read in full")
	}
	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0: %+v", n, env(t, b, "dns.zones"))
	}
	want := []string{rhelCryptoPolicy, bindRhelConf, rhel1912Zones, rhelRootKey}
	slices.Sort(want)
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, want) {
		t.Errorf("config_files %v, want %v", got, want)
	}
	// The whole chain's zones, sorted by name.
	wantZones := []string{".", "0.in-addr.arpa", "1.0.0.127.in-addr.arpa", "localhost"}
	if got := dnsZoneNames(t, b); !slices.Equal(got, wantZones) {
		t.Fatalf("zones %v, want %v", got, wantZones)
	}
	root := dnsZoneRec(t, b, ".")
	recField(t, root, "type", "hint")
	recField(t, root, "file", "named.ca")

	// The stock chain sets no allow-transfer anywhere, so the build decides:
	// RHEL 9 ships BIND 9.16, whose default is any.
	absentBecause(t, b, "dns.options.allow_transfer", "9.16/9.18", "rhel 9.4", "defaults to any")
	local := dnsZoneRec(t, b, "localhost")
	recField(t, local, "transfer_restricted", false)
	recField(t, local, "allow_update", "none")
	recField(t, local, "update_restricted", true)
	recAbsent(t, local, "allow_transfer")

	if w := b.Worst("dns"); w != facts.StatusOK {
		t.Errorf(`Worst("dns") = %s, want ok`, w)
	}
}

// An include that sits INSIDE options {} belongs to options: its statements
// are the enclosing block's, not a configuration of their own. A fragment
// holding a bare allow-transfer means nothing at the top level, so this is
// what tells an in-place inlining from one that opens a fresh context.
func TestDnsIncludeInsideOptionsBelongsToOptions(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf:         "named.conf.split-options",
		namedTransferInclude: "named.conf.transfer",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	if got := dnsString(t, b, "dns.options.allow_transfer"); got != "192.0.2.0/24" {
		t.Errorf("options.allow_transfer = %q, want the fragment's list", got)
	}
	recField(t, dnsZoneRec(t, b, "example.org"), "transfer_restricted", true)
	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0", n)
	}
}

// Nothing in the file sets allow-transfer, and the host is RHEL 9.4, whose
// BIND 9.16 transfers to anyone by default: the zone is NOT restricted, and
// saying so needs the build, not the file.
func TestDnsBindDefaultTransferIsOpen(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
		etcOSRelease: "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	absentBecause(t, b, "dns.options.allow_transfer", "9.16/9.18", "rhel 9.4", "defaults to any")
	z := dnsZoneRec(t, b, "example.org")
	recField(t, z, "transfer_restricted", false)
	// An unset allow-update is none in EVERY version, so that half needs no
	// build at all.
	recField(t, z, "update_restricted", true)
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("the file was read in full")
	}
}

// The unset default follows the build (Ruling L-16). Ubuntu 22.04 ships BIND
// 9.18, whose default is any; a distribution this table does not know could be
// 9.20 or later, where the default is none, so the verdict is REFUSED rather
// than guessed — the field is absent and the control reads MANUAL.
func TestDnsUnsetTransferDefaultFollowsTheBuild(t *testing.T) {
	ubuntu := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
		etcOSRelease: "os-release.ubuntu2204",
	}))
	dnsComplete(t, ubuntu)
	recField(t, dnsZoneRec(t, ubuntu, "example.org"), "transfer_restricted", false)
	absentBecause(t, ubuntu, "dns.options.allow_transfer", "ubuntu 22.04", "defaults to any")

	unknown := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
		etcOSRelease: "os-release.unknown",
	}))
	dnsComplete(t, unknown)
	absentBecause(t, unknown, "dns.options.allow_transfer",
		"any before 9.20, none from 9.20")

	// A host with no os-release readable at all is the same unknown build.
	none := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
	}))
	dnsComplete(t, none)
	absentBecause(t, none, "dns.options.allow_transfer",
		"any before 9.20, none from 9.20")
}

// Ruling L-53: a primary zone whose transfer default cannot be determined —
// nothing sets allow-transfer at either level AND the build is unknown — makes
// the WHOLE dns.zones leaf absent, naming the zone. A record cannot carry an
// "unknown" bool, and a control that reads a field a record does not have is
// an internal ERROR rather than the MANUAL Ruling L-16 asks for. The absence
// is published at the leaf, NOT through the shared degradation envelope, so
// dns.options.allow_update — knowable here, none in every version — and the
// evidence leaves keep answering.
func TestDnsZonesAbsentWhenAPrimaryTransferDefaultIsUnknown(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
		etcOSRelease: "os-release.unknown",
	}))
	dnsComplete(t, b)

	absentBecause(t, b, "dns.zones", "example.org", "any before 9.20, none from 9.20")
	absentBecause(t, b, "dns.options.allow_update", "none in every version")
	// The evidence leaves are unaffected: nothing failed to be read or parsed.
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("an undeterminable default is not a read failure")
	}
	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0: an undeterminable default is not an unmodelled construct", n)
	}
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, []string{bindRhelConf}) {
		t.Errorf("config_files %v, want the main file", got)
	}
	if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "bind" {
		t.Errorf("implementation %+v, want ok bind", e)
	}
	if w := b.Worst("dns"); w != facts.StatusOK {
		t.Errorf(`Worst("dns") = %s, want ok`, w)
	}

	// No PRIMARY zone needs the default here, so the list still answers.
	secondary := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.secondary",
		etcOSRelease: "os-release.unknown",
	}))
	dnsComplete(t, secondary)
	if got := dnsZoneNames(t, secondary); !slices.Equal(got, []string{"example.org"}) {
		t.Fatalf("zones %v, want the secondary zone listed", got)
	}
	recField(t, dnsZoneRec(t, secondary, "example.org"), "type", "slave")
	recField(t, dnsZoneRec(t, secondary, "example.org"), "update_restricted", true)
	// The residual of Ruling L-53, pinned so it cannot drift into a guess: a
	// SECONDARY zone on an unknown build has no honest transfer bool either -
	// its build default is exactly as unknown - and the leaf-level absence
	// covers only primary and master. The field is therefore left OFF this
	// record. Nothing reads it: U-50's `where` filters to primary and master
	// before its `require` looks at the field, and a require on a field a
	// record lacks is an internal ERROR rather than a MANUAL.
	recAbsent(t, dnsZoneRec(t, secondary, "example.org"), "transfer_restricted")
}

// Ruling L-54: the include guard is per CHAIN, not per run. The same declared
// fragment included from two different zones is two different meanings — L-18
// gives its statements to the enclosing block — and named reads it twice, so
// dropping the second inclusion would report the second zone as restricted
// while the running server transfers it to anyone.
func TestDnsSameFragmentIncludedTwice(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf:     "named.conf.twice",
		namedOpenInclude: "named.conf.open",
		etcOSRelease:     "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0", n)
	}
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("both inclusions were read in full")
	}
	// The options level refuses transfers; BOTH zones override it through the
	// same fragment.
	for _, name := range []string{"example.org", "example.net"} {
		z := dnsZoneRec(t, b, name)
		recField(t, z, "allow_transfer", "any")
		recField(t, z, "transfer_restricted", false)
	}
	// The file list still names it once, however many times it was reached.
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, []string{bindRhelConf, namedOpenInclude}) {
		t.Errorf("config_files %v, want each file once", got)
	}
}

// The other half of Ruling L-54: a cycle still terminates. loop-a includes
// loop-b, which includes loop-a again — the second one is already open in this
// chain, so it is refused and counted rather than followed.
func TestDnsIncludeCycleTerminates(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.cycle",
		namedLoopA:   "named.conf.loop-a",
		namedLoopB:   "named.conf.loop-b",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 1 {
		t.Errorf("unmodelled = %d, want 1 for the cycle", n)
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, b, k, namedLoopA, "cycle")
	}
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("every file of the cycle was read; the loop is not a read failure")
	}
}

// A zone-level allow-transfer overrides a wide-open options level; an explicit
// allow-update { any; } is not restricted; an update-policy restricts by
// itself, whatever allow-update says.
func TestDnsZoneLevelOverridesAndUpdatePolicy(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.zone-override",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	if got := dnsString(t, b, "dns.options.allow_transfer"); got != "any" {
		t.Errorf("options.allow_transfer = %q, want any", got)
	}
	if got := dnsString(t, b, "dns.options.allow_update"); got != "none" {
		t.Errorf("options.allow_update = %q, want none", got)
	}
	// Sorted by name, so example.net comes first.
	if got := dnsZoneNames(t, b); !slices.Equal(got, []string{"example.net", "example.org"}) {
		t.Fatalf("zones %v, want them sorted by name", got)
	}

	org := dnsZoneRec(t, b, "example.org")
	recField(t, org, "allow_transfer", "192.0.2.0/24")
	recField(t, org, "transfer_restricted", true)
	recField(t, org, "allow_update", "any")
	recField(t, org, "update_restricted", false)

	// example.net sets neither list, so both are the options level's: the
	// open transfer list is inherited, while update-policy settles updates.
	net := dnsZoneRec(t, b, "example.net")
	recField(t, net, "allow_transfer", "any")
	recField(t, net, "transfer_restricted", false)
	recField(t, net, "update_restricted", true)
}

// An ACL name is resolved through the chain wherever it is defined — the
// definition here sits BELOW the reference, so the resolution is a second pass
// over the parsed file. A name nothing defines is a construct outside the
// model: the zones list is refused rather than judged on half a list.
func TestDnsAclResolution(t *testing.T) {
	defined := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.acl",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, defined)
	if n := dnsInt(t, defined, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0", n)
	}
	if got := dnsString(t, defined, "dns.options.allow_transfer"); got != "xfer" {
		t.Errorf("options.allow_transfer = %q, want the ACL name as written", got)
	}
	recField(t, dnsZoneRec(t, defined, "example.org"), "transfer_restricted", true)

	undefined := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.acl-undefined",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, undefined)
	if n := dnsInt(t, undefined, "dns.unmodelled"); n != 1 {
		t.Errorf("unmodelled = %d, want 1 for the undefined ACL name", n)
	}
	// The evidence leaves still answer; only the judged ones step back.
	if !dnsBool(t, undefined, "dns.parse_complete") {
		t.Error("the file was read in full; an undefined ACL is not a read failure")
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, undefined, k, "partners")
	}
}

// A view splits the server into per-client configurations this collector does
// not model, so every judged leaf steps back while the evidence leaves say
// exactly what was found.
func TestDnsViewIsUnmodelled(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.view",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 1 {
		t.Errorf("unmodelled = %d, want 1", n)
	}
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("a view is not a read failure: the file was read in full")
	}
	if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "bind" {
		t.Errorf("implementation %+v, want ok bind", e)
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, b, k, "view")
	}
	if w := b.Worst("dns"); w != facts.StatusOK {
		t.Errorf(`Worst("dns") = %s, want ok`, w)
	}
}

// An include the declaration covers is read; one outside it is RECORDED with
// its path and never opened, at any depth — the undeclared one here sits
// inside options {}. A file the configuration named and muster did not read
// leaves the parse incomplete as well as unmodelled.
func TestDnsIncludeGuard(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf:       "named.conf.include-undeclared",
		namedCustomInclude: "named.conf.custom",
		etcOSRelease:       "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	want := []string{bindRhelConf, namedCustomInclude}
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, want) {
		t.Errorf("config_files %v, want %v", got, want)
	}
	if slices.Contains(a.reads, undeclaredInclude) {
		t.Errorf("the collector opened %s, which its declaration does not cover", undeclaredInclude)
	}
	if n := dnsInt(t, b, "dns.unmodelled"); n != 1 {
		t.Errorf("unmodelled = %d, want 1", n)
	}
	if dnsBool(t, b, "dns.parse_complete") {
		t.Error("a file the configuration named and muster did not read leaves the parse incomplete")
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, b, k, undeclaredInclude)
	}
}

// All three comment syntaxes, a block comment carrying braces and a
// semicolon, a brace INSIDE a quoted string, and a key reference — which
// restricts a transfer to the peer holding that TSIG key.
func TestDnsTokenizerEdges(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.key",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0: %+v", n, env(t, b, "dns.zones"))
	}
	if got := dnsString(t, b, "dns.options.allow_transfer"); got != "key tsig" {
		t.Errorf("options.allow_transfer = %q, want the key reference", got)
	}
	z := dnsZoneRec(t, b, "example.org")
	recField(t, z, "transfer_restricted", true)
	// The brace belongs to the string, so the file name survives whole and
	// the zone block did not end early.
	recField(t, z, "file", "/var/named/example.org{1}.zone")
	recField(t, z, "allow_update", "none")
	recField(t, z, "update_restricted", true)
}

// Ruling L-17: a zone's file is a path the configuration NAMES, not one the
// collector reads. It is recorded verbatim and never opened, so a zone file
// outside the declaration — where every real one lives — leaves the parse
// complete and nothing unmodelled.
func TestDnsZoneFileIsRecordedNotRead(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf: "named.conf.open-transfer",
		etcOSRelease: "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	zoneFile := "/var/named/example.org.zone"
	recField(t, dnsZoneRec(t, b, "example.org"), "file", zoneFile)
	if slices.Contains(a.reads, zoneFile) {
		t.Errorf("the collector opened the zone file %s", zoneFile)
	}
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("a named-but-unread zone file does not make the parse incomplete")
	}
	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0", n)
	}
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, []string{bindRhelConf}) {
		t.Errorf("config_files %v, want just the main file", got)
	}
}

// The three states that are not "a BIND configuration this collector read":
// unbound, a conffile whose daemon was removed, and a main file that exists
// and cannot be opened.
func TestDnsImplementationAndDegradation(t *testing.T) {
	t.Run("unbound", func(t *testing.T) {
		a := dnsAccess(map[string]string{unboundConf: "unbound.conf"})
		b := buildBegun(t, "dns", a)
		dnsComplete(t, b)

		if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "unbound" {
			t.Fatalf("implementation %+v, want ok unbound", e)
		}
		if len(a.reads) != 0 {
			t.Errorf("unbound.conf is evidence, not a file to parse; reads = %v", a.reads)
		}
		if got := okList(t, b, "dns.zones"); len(got) != 0 {
			t.Errorf("zones = %v, want the empty list", got)
		}
		absentBecause(t, b, "dns.options.allow_transfer", "unbound")
		absentBecause(t, b, "dns.options.allow_update", "unbound")
		if !dnsBool(t, b, "dns.parse_complete") {
			t.Error("there was nothing this collector failed to read")
		}
	})

	t.Run("no server", func(t *testing.T) {
		b := buildBegun(t, "dns", dnsAccess(nil))
		dnsComplete(t, b)

		if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "none" {
			t.Fatalf("implementation %+v, want ok none", e)
		}
		if got := stringList(t, b, "dns.config_files"); len(got) != 0 {
			t.Errorf("config_files = %v, want the empty list", got)
		}
		if !dnsBool(t, b, "dns.parse_complete") {
			t.Error("a host with no DNS configuration read everything there was")
		}
		if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
			t.Errorf("unmodelled = %d, want 0", n)
		}
		for _, k := range dnsJudgedLeaves {
			absentBecause(t, b, k, bindRhelConf)
		}
		if w := b.Worst("dns"); w != facts.StatusOK {
			t.Errorf(`Worst("dns") = %s, want ok`, w)
		}
	})

	t.Run("leftover conffile", func(t *testing.T) {
		a := dnsAccess(map[string]string{bindDebianConf: "named.conf.debian"})
		delete(a.stats, namedBin) // the package was removed; the conffile stayed
		b := buildBegun(t, "dns", a)
		dnsComplete(t, b)

		e := env(t, b, "dns.implementation")
		if e.Status != facts.StatusOK || e.Value != "none" {
			t.Fatalf("implementation %+v, want ok none", e)
		}
		// IR-7: name the file, so a reader sees a leftover to purge rather
		// than a configuration something was judged by.
		for _, want := range []string{bindDebianConf, namedBin} {
			if !strings.Contains(e.Reason, want) {
				t.Errorf("implementation reason %q must name %q", e.Reason, want)
			}
		}
		// A leftover conffile is never opened.
		if len(a.reads) != 0 {
			t.Errorf("reads = %v, want none", a.reads)
		}
	})

	t.Run("denied main file", func(t *testing.T) {
		a := dnsAccess(map[string]string{bindRhelConf: "named.conf.open-transfer"})
		a.fails[bindRhelConf] = unix.EACCES
		b := buildBegun(t, "dns", a)
		dnsComplete(t, b)

		// C3: the file exists, so this is still a bind host, and the read's
		// own status is the answer for every value the file could have set.
		if e := env(t, b, "dns.implementation"); e.Status != facts.StatusOK || e.Value != "bind" {
			t.Fatalf("implementation %+v, want ok bind", e)
		}
		for _, k := range append([]string{"dns.config_files"}, dnsJudgedLeaves...) {
			e := env(t, b, k)
			if e.Status != facts.StatusDenied {
				t.Errorf("%s: %+v, want denied", k, e)
			}
			if !strings.Contains(e.Reason, bindRhelConf) {
				t.Errorf("%s reason %q must name the file", k, e.Reason)
			}
		}
		if dnsBool(t, b, "dns.parse_complete") {
			t.Error("a file that could not be read leaves the parse incomplete")
		}
	})

	t.Run("truncated", func(t *testing.T) {
		a := dnsAccess(map[string]string{
			bindRhelConf: "named.conf.open-transfer",
			etcOSRelease: "os-release.rhel9",
		})
		a.truncated[bindRhelConf] = true
		b := buildBegun(t, "dns", a)
		dnsComplete(t, b)

		if dnsBool(t, b, "dns.parse_complete") {
			t.Error("a read cut at the cap is not a complete parse")
		}
		if !env(t, b, "dns.config_files").Truncated {
			t.Error("config_files must carry the truncation flag")
		}
		for _, k := range dnsJudgedLeaves {
			absentBecause(t, b, k, "read limit")
		}
	})

	t.Run("unreadable include", func(t *testing.T) {
		a := dnsAccess(map[string]string{
			bindDebianConf:      "named.conf.debian",
			bindOptionsFragment: "named.conf.options",
		})
		// The local fragment is named by the chain and is not there.
		b := buildBegun(t, "dns", a)
		dnsComplete(t, b)

		if dnsBool(t, b, "dns.parse_complete") {
			t.Error("an include that could not be read leaves the parse incomplete")
		}
		for _, k := range dnsJudgedLeaves {
			absentBecause(t, b, k, bindLocalFragment)
		}
		// The main file WAS read, so the file list is still evidence.
		if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, []string{bindDebianConf, bindOptionsFragment}) {
			t.Errorf("config_files %v, want the two files that were read", got)
		}
	})
}

// A nested address match list is a construct this model does not resolve, so
// the judged leaves step back rather than report a verdict drawn from the
// elements it did understand.
func TestDnsNestedListIsUnmodelled(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.nested",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 1 {
		t.Errorf("unmodelled = %d, want 1", n)
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, b, k, "nested")
	}
}

// M16: a rendered list longer than the value cap is not a value — the reason
// names the limit and never the list. The verdict is still drawn from the
// parsed elements, because those were understood.
func TestDnsOversizedListIsRefused(t *testing.T) {
	b := buildBegun(t, "dns", dnsAccess(map[string]string{
		bindRhelConf: "named.conf.oversized",
		etcOSRelease: "os-release.rhel9",
	}))
	dnsComplete(t, b)

	absentBecause(t, b, "dns.options.allow_transfer", oversizedReason)
	z := dnsZoneRec(t, b, "example.org")
	recAbsent(t, z, "allow_transfer")
	recField(t, z, "transfer_restricted", true)
}

// Ruling L-58: the per-CHAIN include guard bounds one path through the
// configuration, not the work of a run. L-18/L-54 let the same fragment be
// inlined once per path that reaches it, so a file that includes the next one
// twice DOUBLES the token stream at every level and the seven levels the depth
// cap allows are 2^7 re-reads of the deepest fragment. A run-wide cap on the
// number of fragments inlined bounds that; a configuration that reaches it is
// a construct outside the model — unmodelled, with the judged leaves absent
// naming the cap — rather than a verdict drawn from the part that fit.
func TestDnsIncludeExpansionIsCapped(t *testing.T) {
	a := dnsAccess(map[string]string{
		bindRhelConf: "named.conf.fanout",
		namedFanA:    "named.conf.fan-a",
		namedFanB:    "named.conf.fan-b",
		etcOSRelease: "os-release.rhel9",
	})
	b := buildBegun(t, "dns", a)
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n == 0 {
		t.Error("unmodelled = 0: the expansions the cap refused must be counted")
	}
	for _, k := range dnsJudgedLeaves {
		absentBecause(t, b, k, strconv.Itoa(maxIncludeExpansions), "include")
	}
	// The point of the cap is the work it does NOT do: every inlined fragment
	// is a file this collector opened, and without the cap this chain opens
	// the deepest one 256 times over.
	if n := len(a.reads); n > maxIncludeExpansions+2 {
		t.Errorf("reads = %d, want at most the cap plus named.conf and os-release", n)
	}
	// A cap is not a read that failed: every file that was opened was read in
	// full, so parse_complete carries no claim about privileges or I/O.
	if !dnsBool(t, b, "dns.parse_complete") {
		t.Error("the cap is a construct outside the model, not a read failure")
	}
	// The main file and both fragments answered, so they are still the
	// evidence for what WAS read.
	if got := stringList(t, b, "dns.config_files"); !slices.Equal(got, []string{bindRhelConf, namedFanA, namedFanB}) {
		t.Errorf("config_files %v, want each file that was read, once", got)
	}
}

// Ruling L-59: the cap bounds a pathological fan-out, and a nameserver that
// keeps ONE include per zone is not one. A hundred zone fragments, each
// inlined exactly once, is an ordinary configuration on a host that serves a
// hundred zones, and it must reach a verdict rather than a manual review.
func TestDnsOneIncludePerZoneIsNotCapped(t *testing.T) {
	files := map[string]string{
		bindRhelConf: "named.conf.many-zones",
		etcOSRelease: "os-release.rhel9",
	}
	for i := 1; i <= 100; i++ {
		files[fmt.Sprintf("/etc/named/zone-%03d.conf", i)] = "named.conf.zone-include"
	}
	b := buildBegun(t, "dns", dnsAccess(files))
	dnsComplete(t, b)

	if n := dnsInt(t, b, "dns.unmodelled"); n != 0 {
		t.Errorf("unmodelled = %d, want 0: one include per zone is not a construct outside the model", n)
	}
	// The verdict leaves the configuration really does set must ANSWER. An
	// unset allow-update is none in every version and is absent for its own
	// reason, so what this test forbids is any leaf stepping back because of
	// the cap.
	for _, k := range dnsJudgedLeaves {
		if r := env(t, b, k).Reason; strings.Contains(r, "expansion") || strings.Contains(r, "inlined") {
			t.Errorf("%s stepped back for the cap: %s", k, r)
		}
	}
	for _, k := range []string{"dns.options.allow_transfer", "dns.zones"} {
		if s := env(t, b, k).Status; s != facts.StatusOK {
			t.Errorf("%s = %s (%s), want ok: a hundred single inclusions must still reach a verdict",
				k, s, env(t, b, k).Reason)
		}
	}
}
