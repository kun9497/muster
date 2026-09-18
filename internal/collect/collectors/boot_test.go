//go:build linux

package collectors

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// bootSeeds is the boot chain of a host that has a grub.cfg naming no
// superuser, one ordinary /etc/grub.d fragment and an /etc/group to take the
// group name from. A test overrides exactly the entry it is about, so every
// other leaf still has an answer and a failure names its own cause.
func bootSeeds() map[string]string {
	return map[string]string{
		groupPath:              "group",
		grubCfgEL:              "grub.cfg.comments",
		"/etc/grub.d/10_linux": "grub.d-10_linux.sample",
	}
}

// bootStats gives the seeded grub.cfg the shape writePermFacts reports: the
// 0600 root-owned file a hardened host has. fsAccess prefers an explicit
// stats entry over the files map, so a path may be stat-able and unreadable
// independently.
func bootStats(p string) map[string]statResult {
	return map[string]statResult{p: {mode: 0o600, uid: 0, gid: 0, kind: "regular"}}
}

// The firmware leaf is the presence of /sys/firmware/efi and nothing else:
// the directory exists only when the kernel booted through EFI, and the path
// is the evidence either way.
func TestBootFirmware(t *testing.T) {
	a := &fsAccess{files: bootSeeds(), dirs: map[string]bool{efiDir: true}}
	e := env(t, build(t, "boot", a), "boot.firmware")
	if e.Status != facts.StatusOK || e.Value != "uefi" {
		t.Errorf("with %s present, boot.firmware = %+v, want ok uefi", efiDir, e)
	}
	want := facts.Source{Kind: "sys", Path: efiDir}
	if !sameSource(e.Source, &want) {
		t.Errorf("boot.firmware source %+v, want %+v", e.Source, want)
	}

	a = &fsAccess{files: bootSeeds()}
	e = env(t, build(t, "boot", a), "boot.firmware")
	if e.Status != facts.StatusOK || e.Value != "bios" {
		t.Errorf("with %s absent, boot.firmware = %+v, want ok bios", efiDir, e)
	}
	if !sameSource(e.Source, &want) {
		t.Errorf("boot.firmware source %+v, want %+v: the absence of that path is the evidence", e.Source, want)
	}
}

// Secure Boot is one byte of one efivarfs file, behind the four-byte
// attribute word every efivar carries. A file too short to hold both is not
// an efivar and is an error, never a guessed "off"; a host with no efivarfs
// and no variable — every BIOS host, and a UEFI host booted without it — is
// absent with the path named, which is what lets control 10 say "manual"
// rather than "Secure Boot is off".
func TestBootSecureBoot(t *testing.T) {
	seed := func(fixture string) facts.Envelope {
		t.Helper()
		files := bootSeeds()
		files[secureBootPath] = fixture
		a := &fsAccess{files: files, dirs: map[string]bool{efiDir: true}}
		return env(t, build(t, "boot", a), "boot.secure_boot")
	}

	if e := seed("SecureBoot.sample"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("06 00 00 00 01 -> %+v, want ok true", e)
	} else {
		want := facts.Source{Kind: "sys", Path: secureBootPath}
		if !sameSource(e.Source, &want) {
			t.Errorf("boot.secure_boot source %+v, want %+v", e.Source, want)
		}
	}
	if e := seed("SecureBoot.off"); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("06 00 00 00 00 -> %+v, want ok false", e)
	}
	if e := seed("SecureBoot.short"); e.Status != facts.StatusError {
		t.Errorf("three bytes -> %+v, want error: that file cannot hold an attribute word and a value", e)
	} else if !strings.Contains(e.Reason, secureBootPath) {
		t.Errorf("the short-file reason %q does not name %s", e.Reason, secureBootPath)
	}

	// A BIOS host: no /sys/firmware/efi at all.
	bios := env(t, build(t, "boot", &fsAccess{files: bootSeeds()}), "boot.secure_boot")
	if bios.Status != facts.StatusAbsent || !strings.Contains(bios.Reason, secureBootPath) {
		t.Errorf("on a BIOS host boot.secure_boot = %+v, want absent naming %s", bios, secureBootPath)
	}

	// UEFI, but efivarfs is not mounted or the variable is not exported.
	uefi := env(t, build(t, "boot", &fsAccess{files: bootSeeds(), dirs: map[string]bool{efiDir: true}}), "boot.secure_boot")
	if uefi.Status != facts.StatusAbsent || !strings.Contains(uefi.Reason, secureBootPath) {
		t.Errorf("with no efivars, boot.secure_boot = %+v, want absent naming %s", uefi, secureBootPath)
	}
}

// The candidate list is fixed and ordered, and a candidate that cannot be
// stat'd ENDS the search: EL ships /boot/grub2 as 0700, so an unprivileged
// run is refused there, and falling through to the next candidate would
// report "no bootloader configuration" — NOT_APPLICABLE — for a host that
// has one (B-10).
func TestBootGrubCfgCandidatesAndDenied(t *testing.T) {
	// Only /boot/grub2/grub.cfg exists: it is the path, and the nine
	// permission leaves are the ones writePermFacts writes for it.
	a := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	b := build(t, "boot", a)
	if e := env(t, b, "boot.grub_cfg.path"); e.Status != facts.StatusOK || e.Value != grubCfgEL {
		t.Errorf("boot.grub_cfg.path = %+v, want ok %s", e, grubCfgEL)
	}
	for _, leaf := range permLeaves {
		if e := env(t, b, "boot.grub_cfg."+leaf); e.Status != facts.StatusOK {
			t.Errorf("boot.grub_cfg.%s = %+v, want ok", leaf, e)
		}
	}
	for key, want := range map[string]any{
		"mode": 0o600, "uid": 0, "gid": 0, "group": "root",
		"group_readable": false, "group_writable": false,
		"other_readable": false, "other_writable": false, "acl_present": false,
	} {
		if e := env(t, b, "boot.grub_cfg."+key); e.Value != want {
			t.Errorf("boot.grub_cfg.%s = %#v, want %#v", key, e.Value, want)
		}
	}

	// The stat of /boot/grub2/grub.cfg is refused while an EFI candidate is
	// sitting there readable. The refusal is the answer on every leaf, and
	// the EFI file is never the answer.
	files := bootSeeds()
	files["/boot/efi/EFI/rocky/grub.cfg"] = "grub.cfg.sample"
	denied := &fsAccess{
		files: files,
		fails: map[string]error{grubCfgEL: os.ErrPermission},
		stats: bootStats("/boot/efi/EFI/rocky/grub.cfg"),
	}
	b = build(t, "boot", denied)
	for _, key := range append([]string{"path"}, permLeaves...) {
		e := env(t, b, "boot.grub_cfg."+key)
		if e.Status != facts.StatusDenied {
			t.Errorf("boot.grub_cfg.%s = %+v, want denied", key, e)
		}
		if !strings.Contains(e.Reason, grubCfgEL) {
			t.Errorf("boot.grub_cfg.%s reason %q does not name the refused candidate %s", key, e.Reason, grubCfgEL)
		}
	}
	if e := env(t, b, "boot.grub_cfg.path"); e.Value == "/boot/efi/EFI/rocky/grub.cfg" {
		t.Error("a refused candidate fell through to the EFI one: a denied /boot/grub2 must never read as another host's bootloader")
	}
	// The password leaf follows the same refusal (spec B-10): a chain whose
	// main file cannot be opened cannot report "no password is set".
	if e := env(t, b, "boot.grub_password_set"); e.Status != facts.StatusDenied {
		t.Errorf("boot.grub_password_set = %+v, want denied alongside the grub.cfg leaves", e)
	}

	// No candidate at all: every leaf is absent, so absent_means decides.
	none := &fsAccess{files: map[string]string{groupPath: "group"}}
	b = build(t, "boot", none)
	for _, key := range append([]string{"path"}, permLeaves...) {
		if e := env(t, b, "boot.grub_cfg."+key); e.Status != facts.StatusAbsent {
			t.Errorf("with no candidate, boot.grub_cfg.%s = %+v, want absent", key, e)
		}
	}
}

// A UEFI host keeps grub.cfg under a vendor directory of the EFI system
// partition, which has to be enumerated before it can be stat'd (K-4). The
// vendor name varies by distribution and more than one may be installed, so
// the candidates are taken in the sorted order Glob returns them in.
func TestBootGrubCfgOnTheEFIPartition(t *testing.T) {
	const rocky = "/boot/efi/EFI/rocky/grub.cfg"
	const centos = "/boot/efi/EFI/centos/grub.cfg"

	// Neither fixed candidate exists, so the EFI one is the answer, and the
	// permission leaves are that file's.
	files := map[string]string{groupPath: "group", rocky: "grub.cfg.sample"}
	b := build(t, "boot", &fsAccess{files: files, stats: bootStats(rocky)})
	if e := env(t, b, "boot.grub_cfg.path"); e.Status != facts.StatusOK || e.Value != rocky {
		t.Fatalf("boot.grub_cfg.path = %+v, want ok %s", e, rocky)
	}
	if e := env(t, b, "boot.grub_cfg.mode"); e.Status != facts.StatusOK || e.Value != 0o600 {
		t.Errorf("boot.grub_cfg.mode = %+v, want the 0600 of %s", e, rocky)
	}
	if e := env(t, b, "boot.grub_password_set"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("boot.grub_password_set = %+v, want the true of %s's hash", e, rocky)
	}

	// Two vendor directories: the sorted order decides, so the answer is the
	// same on every run whatever order the kernel listed them in.
	files = map[string]string{groupPath: "group", rocky: "grub.cfg.sample", centos: "grub.cfg.comments"}
	stats := bootStats(rocky)
	stats[centos] = statResult{mode: 0o644, uid: 0, gid: 0, kind: "regular"}
	b = build(t, "boot", &fsAccess{files: files, stats: stats})
	if e := env(t, b, "boot.grub_cfg.path"); e.Status != facts.StatusOK || e.Value != centos {
		t.Errorf("boot.grub_cfg.path = %+v, want %s: the EFI candidates are taken in sorted order", e, centos)
	}
	if e := env(t, b, "boot.grub_cfg.mode"); e.Value != 0o644 {
		t.Errorf("boot.grub_cfg.mode = %+v, want the 0644 of %s", e, centos)
	}
}

// A /boot/efi/EFI this run may not search is the answer at the position the
// EFI candidates occupy — after the two fixed paths have said "not there".
// Glob discards that refusal and would otherwise look like "no vendor
// directory", which is the NOT_APPLICABLE B-10 refuses.
func TestBootGrubCfgGlobRefused(t *testing.T) {
	a := &fsAccess{
		files:      map[string]string{groupPath: "group"},
		deniedDirs: map[string]bool{"/boot/efi/EFI": true},
	}
	b := build(t, "boot", a)
	for _, key := range append([]string{"path"}, permLeaves...) {
		e := env(t, b, "boot.grub_cfg."+key)
		if e.Status != facts.StatusDenied {
			t.Errorf("boot.grub_cfg.%s = %+v, want denied", key, e)
		}
		if !strings.Contains(e.Reason, grubEFIGlob) {
			t.Errorf("boot.grub_cfg.%s reason %q does not name %s", key, e.Reason, grubEFIGlob)
		}
	}
	if e := env(t, b, "boot.grub_password_set"); e.Status != facts.StatusDenied {
		t.Errorf("boot.grub_password_set = %+v, want denied with the rest", e)
	}
}

// A /sys/firmware/efi that exists and cannot be stat'd is neither uefi nor
// bios: the answer is the read's status, never a guess in either direction.
func TestBootFirmwareRefused(t *testing.T) {
	a := &fsAccess{files: bootSeeds(), fails: map[string]error{efiDir: unix.EACCES}}
	e := env(t, build(t, "boot", a), "boot.firmware")
	if e.Status != facts.StatusDenied {
		t.Errorf("boot.firmware = %+v, want denied", e)
	}
	if !strings.Contains(e.Reason, efiDir) {
		t.Errorf("the reason %q does not name %s", e.Reason, efiDir)
	}
	if e.Value != nil {
		t.Errorf("a denied firmware leaf carries the value %#v", e.Value)
	}
}

// The password is judged from the whole chain: the chosen grub.cfg, the
// user.cfg grub-setpassword writes and every /etc/grub.d fragment. What is
// judged is a literal grub.pbkdf2 hash (K-22) and nothing else. One file of
// that chain that exists and cannot be read is the answer for the leaf (C3),
// even when another file already said true — a run that could not read
// everything must not report a value as if it had.
func TestBootGrubPasswordSet(t *testing.T) {
	set := func(a *fsAccess) facts.Envelope {
		t.Helper()
		return env(t, build(t, "boot", a), "boot.grub_password_set")
	}

	files := bootSeeds()
	files[grubCfgEL] = "grub.cfg.sample" // password_pbkdf2 root grub.pbkdf2.…
	if e := set(&fsAccess{files: files, stats: bootStats(grubCfgEL)}); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf(`grub.cfg with a password_pbkdf2 hash -> %+v, want ok true`, e)
	}

	// The hash is in a hand-written fragment instead; the generated grub.cfg
	// says nothing.
	files = bootSeeds()
	files["/etc/grub.d/40_custom"] = "grub.d-40_custom.sample"
	if e := set(&fsAccess{files: files, stats: bootStats(grubCfgEL)}); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("password_pbkdf2 in /etc/grub.d/40_custom -> %+v, want ok true", e)
	}

	// EL's grub.cfg as 01_users generates it on EVERY host: `set superusers`
	// and `password_pbkdf2 root "${GRUB2_PASSWORD}"` are the template's own
	// text, and no hash is anywhere. Judging those tokens would have failed a
	// whole distribution for a password it does not have (K-22).
	files = bootSeeds()
	files[grubCfgEL] = "grub.cfg.el-stock"
	if e := set(&fsAccess{files: files, stats: bootStats(grubCfgEL)}); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("EL's stock 01_users block -> %+v, want ok false: it references a hash it does not have", e)
	}

	// The hash EL really keeps, in the user.cfg grub-setpassword writes.
	files = bootSeeds()
	files[grubCfgEL] = "grub.cfg.el-stock"
	files[grubUserCfg] = "user.cfg.sample"
	if e := set(&fsAccess{files: files, stats: bootStats(grubCfgEL)}); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("GRUB2_PASSWORD=grub.pbkdf2.… in user.cfg -> %+v, want ok true", e)
	}

	// An uncommented `set superusers` and two commented-out hashes, and
	// nothing else.
	plain := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	e := set(plain)
	if e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("a chain with a superuser but no hash -> %+v, want ok false", e)
	}
	if e.Source == nil || e.Source.Kind != "derived" || len(e.Source.Inputs) != 2 {
		t.Errorf("source %+v, want the two files that were read", e.Source)
	}

	// user.cfg exists and may not be read: 0600 on EL, so an unprivileged run
	// is refused there even when grub.cfg itself is world-readable and has
	// already answered true.
	files = bootSeeds()
	files[grubCfgEL] = "grub.cfg.sample"
	denied := &fsAccess{
		files: files,
		fails: map[string]error{grubUserCfg: unix.EACCES},
		stats: bootStats(grubCfgEL),
	}
	e = set(denied)
	if e.Status != facts.StatusDenied {
		t.Errorf("an unreadable user.cfg -> %+v, want denied even though grub.cfg said true", e)
	}
	if !strings.Contains(e.Reason, grubUserCfg) {
		t.Errorf("the reason %q does not name %s", e.Reason, grubUserCfg)
	}
	if e.Value != nil {
		t.Errorf("a denied leaf carries the value %#v", e.Value)
	}

	// Nothing of the chain exists at all.
	if e := set(&fsAccess{files: map[string]string{groupPath: "group"}}); e.Status != facts.StatusAbsent {
		t.Errorf("with no grub.cfg, user.cfg or fragment -> %+v, want absent", e)
	}
}

// Ruling K-21: /etc/grub.d is a .d directory, so a symlink to /dev/null in it
// is the documented MASK idiom — the fragment is switched off on purpose and
// reporting the administrator's own act as an error would be muster's bug.
// Any other symlink is that file's error (C4), and an entry that is not a
// regular file at all sets nothing and is skipped (the crypto-policies
// lesson).
func TestBootGrubDMaskAndNonRegular(t *testing.T) {
	set := func(a *fsAccess) facts.Envelope {
		t.Helper()
		return env(t, build(t, "boot", a), "boot.grub_password_set")
	}

	masked := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	seedLink(masked, "/etc/grub.d/20_linux_xen", devNull)
	if e := set(masked); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("a fragment masked with a link to %s -> %+v, want ok false", devNull, e)
	}

	other := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	seedLink(other, "/etc/grub.d/09_local", "/opt/local/grub.d/09_local")
	if e := set(other); e.Status != facts.StatusError {
		t.Errorf("a fragment symlinked elsewhere -> %+v, want error: its bytes were never read", e)
	}

	notRegular := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	notRegular.fails = map[string]error{
		"/etc/grub.d/backups": fmt.Errorf("%s: %w", "/etc/grub.d/backups", collect.ErrNotRegular),
	}
	notRegular.dirs = map[string]bool{"/etc/grub.d/backups": true}
	if e := set(notRegular); e.Status != facts.StatusOK || e.Value != false {
		t.Errorf("a directory named inside /etc/grub.d -> %+v, want ok false: it carries no settings", e)
	}
}

// The declaration is the whole contract with the guard: written out by hand
// here, so a typo in the table under test cannot rewrite what this expects.
func TestBootDeclarationCoversItsReads(t *testing.T) {
	c := collectorNamed(t, "boot")
	if c.Declare.Needs != "none" {
		t.Errorf("Needs %q, want none: every read here is a stat or an open", c.Declare.Needs)
	}
	if len(c.Declare.Commands) != 0 {
		t.Errorf("declares %d commands, want none", len(c.Declare.Commands))
	}
	if c.Declare.Walk {
		t.Error("declares the walk licence, which this collector has no use for")
	}

	want := []string{
		"/boot/efi/EFI/*/grub.cfg",
		"/boot/efi/EFI/*/user.cfg",
		"/boot/grub/grub.cfg",
		"/boot/grub2/grub.cfg",
		"/boot/grub2/user.cfg",
		"/etc/group",
		"/etc/grub.d/*",
		"/sys/firmware/efi",
		"/sys/firmware/efi/efivars/SecureBoot-*",
	}
	got := slices.Clone(c.Declare.Reads)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("Reads =\n%v\nwant\n%v", got, want)
	}
	// K-4: the group name writePermFacts needs comes from a declared read,
	// and the exact efivar the collector opens is licensed by the glob.
	if !slices.Contains(c.Declare.Reads, groupPath) {
		t.Errorf("%s is not declared, yet writePermFacts reads it for the group name", groupPath)
	}

	a := &fsAccess{files: bootSeeds(), stats: bootStats(grubCfgEL)}
	b := buildBegun(t, "boot", a)
	keys := b.Keys("boot")
	if len(keys) != 13 {
		t.Errorf("wrote %d keys, want the thirteen of B-2: %v", len(keys), keys)
	}
	for _, key := range append([]string{"boot.firmware", "boot.secure_boot", "boot.grub_cfg.path", "boot.grub_password_set"},
		prefixed("boot.grub_cfg.", permLeaves)...) {
		if !slices.Contains(keys, key) {
			t.Errorf("%s was not written", key)
		}
	}
}

func prefixed(prefix string, names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, prefix+n)
	}
	return out
}

func TestSecureBootFromEfivar(t *testing.T) {
	for _, tc := range []struct {
		name          string
		data          []byte
		enabled, want bool
	}{
		{"enabled", []byte{6, 0, 0, 0, 1}, true, true},
		{"disabled", []byte{6, 0, 0, 0, 0}, false, true},
		{"any non-zero byte is on", []byte{6, 0, 0, 0, 2, 0}, true, true},
		{"too short", []byte{6, 0, 0, 0}, false, false},
		{"empty", nil, false, false},
	} {
		enabled, ok := secureBootFromEfivar(tc.data)
		if enabled != tc.enabled || ok != tc.want {
			t.Errorf("%s: secureBootFromEfivar(%v) = %v, %v; want %v, %v", tc.name, tc.data, enabled, ok, tc.enabled, tc.want)
		}
	}
}

func TestGrubPasswordSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want bool
	}{
		{"pbkdf2 hash", "password_pbkdf2 root grub.pbkdf2.sha512.10000.SALT.HASH\n", true},
		{"pbkdf2 hash indented", "\t  password_pbkdf2 root grub.pbkdf2.sha512.10000.SALT.HASH\n", true},
		{"user.cfg bare", "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.SALT.HASH\n", true},
		{"user.cfg double-quoted", `GRUB2_PASSWORD="grub.pbkdf2.sha512.10000.SALT.HASH"`, true},
		{"user.cfg single-quoted", `GRUB2_PASSWORD='grub.pbkdf2.sha512.10000.SALT.HASH'`, true},
		{"superusers alone", `set superusers="root"`, false},
		{"superusers bare", "set superusers\n", false},
		{"a reference, not a hash", `password_pbkdf2 root "${GRUB2_PASSWORD}"`, false},
		{"an empty user.cfg variable", "GRUB2_PASSWORD=\n", false},
		{"a user.cfg reference", "GRUB2_PASSWORD=${SOMETHING}\n", false},
		{"pbkdf2 with no hash argument", "password_pbkdf2 root\n", false},
		{"commented out", "# password_pbkdf2 root grub.pbkdf2.sha512.10000.SALT.HASH\n", false},
		{"merely mentioned", `echo "password_pbkdf2 root grub.pbkdf2.sha512.x is the shape"`, false},
		{"empty", "", false},
	} {
		if got := grubPasswordSet([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: grubPasswordSet(%q) = %v, want %v", tc.name, tc.in, got, tc.want)
		}
	}
}

// Ruling K-28: an EL host installed before 9 and upgraded on UEFI keeps
// /boot/grub2/grub.cfg as a LINK to the grub.cfg on the EFI system
// partition, and grub2-mkconfig preserves it. The distribution ships that
// link, so C4 says muster models it: the facts are the TARGET's — its path,
// its permission bits — and grub-setpassword's user.cfg is read beside the
// target, which is where it actually is.
func TestBootGrubCfgOnAnUpgradedELHost(t *testing.T) {
	const target = "/boot/efi/EFI/redhat/grub.cfg"
	const beside = "/boot/efi/EFI/redhat/user.cfg"

	files := bootSeeds()
	delete(files, grubCfgEL)
	files[target] = "grub.cfg.el-stock" // the ${GRUB2_PASSWORD} reference, no hash
	files[beside] = "user.cfg.sample"   // the hash grub-setpassword wrote
	a := &fsAccess{files: files, stats: map[string]statResult{
		target: {mode: 0o644, uid: 0, gid: 0, kind: "regular"},
	}}
	seedLink(a, grubCfgEL, "../efi/EFI/redhat/grub.cfg")
	b := build(t, "boot", a)

	if e := env(t, b, "boot.grub_cfg.path"); e.Status != facts.StatusOK || e.Value != target {
		t.Fatalf("boot.grub_cfg.path = %+v, want ok %s: the link's target is where the file is", e, target)
	}
	// The permission leaves describe the target, not the link: a symlink is
	// 0777 and reporting that would say every host is world-writable.
	if e := env(t, b, "boot.grub_cfg.mode"); e.Status != facts.StatusOK || e.Value != 0o644 {
		t.Errorf("boot.grub_cfg.mode = %+v, want the 0644 of %s", e, target)
	}
	if e := env(t, b, "boot.grub_cfg.other_readable"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("boot.grub_cfg.other_readable = %+v, want the target's bits", e)
	}
	// The password is in the user.cfg BESIDE the target. /boot/grub2/user.cfg
	// does not exist on this host, so a collector that only ever looked there
	// would report false for a host that has a password.
	if e := env(t, b, "boot.grub_password_set"); e.Status != facts.StatusOK || e.Value != true {
		t.Errorf("boot.grub_password_set = %+v, want ok true from %s", e, beside)
	}
	if !slices.Contains(a.reads, beside) {
		t.Errorf("%s was never read; the chain read %v", beside, a.reads)
	}
}

// Any other link at a candidate stays that candidate's error (C4): its bytes
// were never read and this declaration does not cover wherever it points.
func TestBootGrubCfgForeignSymlinkIsAnError(t *testing.T) {
	files := bootSeeds()
	delete(files, grubCfgEL)
	a := &fsAccess{files: files}
	seedLink(a, grubCfgEL, "/opt/boot/grub.cfg")
	b := build(t, "boot", a)

	for _, key := range append([]string{"path"}, permLeaves...) {
		e := env(t, b, "boot.grub_cfg."+key)
		if e.Status != facts.StatusError {
			t.Errorf("boot.grub_cfg.%s = %+v, want error", key, e)
		}
		if !strings.Contains(e.Reason, grubCfgEL) {
			t.Errorf("boot.grub_cfg.%s reason %q does not name the link %s", key, e.Reason, grubCfgEL)
		}
	}
	if e := env(t, b, "boot.grub_password_set"); e.Status != facts.StatusError {
		t.Errorf("boot.grub_password_set = %+v, want error with the rest", e)
	}
	if slices.Contains(a.reads, "/opt/boot/grub.cfg") {
		t.Error("muster followed a link out of its declaration")
	}
}

// The user.cfg beside a grub.cfg is read only where the declaration covers
// it: /boot/efi/EFI/*/user.cfg, never /boot/grub/user.cfg, which no
// declaration names (C4).
func TestGrubEFIUserCfg(t *testing.T) {
	for _, tc := range []struct {
		cfg, want string
		ok        bool
	}{
		{"/boot/efi/EFI/redhat/grub.cfg", "/boot/efi/EFI/redhat/user.cfg", true},
		{"/boot/efi/EFI/ubuntu/grub.cfg", "/boot/efi/EFI/ubuntu/user.cfg", true},
		{grubCfgDebian, "", false},
		{grubCfgEL, "", false},
		{"", "", false},
	} {
		got, ok := grubEFIUserCfg(tc.cfg)
		if got != tc.want || ok != tc.ok {
			t.Errorf("grubEFIUserCfg(%q) = %q, %v; want %q, %v", tc.cfg, got, ok, tc.want, tc.ok)
		}
	}
}
