//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	// efiDir exists only when the kernel booted through EFI. Its presence is
	// the whole firmware fact: there is no file that says "bios".
	efiDir = "/sys/firmware/efi"

	// secureBootPath is the SecureBoot variable of EFI_GLOBAL_VARIABLE, whose
	// GUID the UEFI specification fixes — it is the same on every machine, so
	// the collector opens it by name rather than picking one out of a listing.
	// The declaration still carries the glob, which is what --list-actions
	// prints and what licenses this open.
	secureBootPath = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	secureBootGlob = "/sys/firmware/efi/efivars/SecureBoot-*"

	grubCfgDebian = "/boot/grub/grub.cfg"
	grubCfgEL     = "/boot/grub2/grub.cfg"
	grubEFIGlob   = "/boot/efi/EFI/*/grub.cfg"

	// grubUserCfg is what grub-setpassword writes on EL, 0600 and root-owned.
	grubUserCfg = "/boot/grub2/user.cfg"
	grubDGlob   = "/etc/grub.d/*"

	// grubEFIUserCfgGlob is the same file on the EFI system partition. An EL
	// host upgraded on UEFI keeps its grub.cfg there and only a LINK at
	// /boot/grub2/grub.cfg (K-28), and grub-setpassword writes user.cfg
	// beside the real file — so the chain that answers the password question
	// has to be able to read it.
	grubEFIUserCfgGlob = "/boot/efi/EFI/*/user.cfg"

	// grubUserCfgName is the base name both of those paths end in.
	grubUserCfgName = "user.cfg"

	// grubHashPrefix is what grub-mkpasswd-pbkdf2 puts in front of every hash
	// it prints, whichever digest was asked for.
	grubHashPrefix = "grub.pbkdf2."
)

// grubCfgFixed are the two candidates that need no enumeration, in the order
// spec B-2 gives them: Debian's tree first, then EL's.
var grubCfgFixed = []string{grubCfgDebian, grubCfgEL}

// bootCollector writes the thirteen boot leaves of spec B-2: what firmware
// started this host, whether that firmware is enforcing Secure Boot, which
// file the bootloader reads its menu from with the permissions of that file,
// and whether editing the menu at the console asks for a password.
//
// Nothing here runs a program. efibootmgr, grub2-editenv and bootctl would
// each answer one of these questions, and each would need a package muster
// cannot assume and a privilege it does not want; a stat and an open answer
// all four.
var bootCollector = collect.Collector{
	Name: "boot",
	Declare: collect.Declaration{Reads: []string{
		efiDir, secureBootGlob,
		grubCfgDebian, grubCfgEL, grubEFIGlob,
		grubUserCfg, grubEFIUserCfgGlob, grubDGlob,
		// K-4: writePermFacts turns the gid of grub.cfg into a group name,
		// and the file it reads to do that is declared here like any other.
		groupPath,
	}, Needs: "none"},
	Run: runBoot,
}

func runBoot(_ context.Context, a collect.Access, b *collect.Builder) error {
	b.Set("boot.firmware", bootFirmware(a))
	b.Set("boot.secure_boot", bootSecureBoot(a))

	cfg, cfgErr := grubCfgPath(a)
	if cfgErr != nil {
		// A candidate that could not be stat'd is the answer for the path and
		// for every permission leaf alike (C3): a partial set would let the
		// check side read "no ACL" or "no bootloader" out of a refusal.
		b.Set("boot.grub_cfg.path", *cfgErr)
		for _, l := range permLeaves {
			b.Set("boot.grub_cfg."+l, *cfgErr)
		}
	} else {
		b.Set("boot.grub_cfg.path", collect.OK(cfg, &facts.Source{Kind: "file", Path: cfg}))
		groups, gmeta, gerr := groupNames(a)
		writePermFacts(b, a, "boot.grub_cfg", cfg, groups, gmeta, gerr, false)
	}
	b.Set("boot.grub_password_set", grubPassword(a, cfg, cfgErr))
	return nil
}

// bootFirmware is the presence of /sys/firmware/efi. The path is the source
// on both answers: its absence is the evidence for "bios" exactly as its
// presence is the evidence for "uefi", and an envelope that cited nothing
// would leave the reader with no way to check the finding.
func bootFirmware(a collect.Access) facts.Envelope {
	src := &facts.Source{Kind: "sys", Path: efiDir}
	if _, err := a.Stat(efiDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.OK("bios", src)
		}
		return readErrorEnv(efiDir, err)
	}
	return collect.OK("uefi", src)
}

// bootSecureBoot is the one byte the firmware exports. A host with no
// efivarfs and a host that booted from BIOS answer the same way — the file is
// not there — and both are absent with the path named rather than false: a
// firmware that is not exporting the variable is not a firmware that has
// Secure Boot off, and control 10's absent_means is what decides between
// "not applicable" and "look at this by hand".
//
// The read is ReadFileBinary because an efivar's attribute word is NUL bytes
// (K-30): through ReadFile it came back empty on every UEFI host, which is
// the reader's answer and not the firmware's.
//
// A read that SUCCEEDS and still brings back too few bytes to hold that
// attribute word and a value is unsupported, not an error: the firmware
// exposes the variable and returns nothing from it, which is an environment
// muster cannot read Secure Boot from rather than a defect on the host or in
// muster. A read that FAILS — EIO, EACCES — keeps the read's own status.
func bootSecureBoot(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFileBinary(secureBootPath, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.Absent(secureBootPath + " does not exist")
		}
		return readErrorEnv(secureBootPath, err)
	}
	enabled, ok := secureBootFromEfivar(data)
	if !ok {
		return collect.Unsupported(secureBootPath + ": the firmware exposes the variable but returns " +
			strconv.Itoa(len(data)) + " bytes; Secure Boot cannot be read from here")
	}
	return collect.OKRead(enabled, &facts.Source{Kind: "sys", Path: secureBootPath}, meta)
}

// secureBootFromEfivar decodes one efivarfs file. Every variable efivarfs
// exports begins with the four-byte attribute word the firmware stored it
// with, so the value starts at offset 4 and SecureBoot's value is one byte.
//
// ok is false when the file is shorter than that, which is not a value at
// all: reading "off" out of four bytes — or out of none — would be an
// invention, so the caller reports a host that answers that short as one
// Secure Boot cannot be read from.
func secureBootFromEfivar(data []byte) (enabled, ok bool) {
	if len(data) < 5 {
		return false, false
	}
	return data[4] != 0, true
}

// grubCfgPath picks the bootloader's configuration file out of the candidate
// list, and returns the envelope every boot.grub_cfg.* leaf must carry when
// there is no path to report.
//
// The search STOPS at the first candidate that exists — and at the first that
// refuses to be stat'd. EL ships /boot/grub2 as 0700, so an unprivileged run
// is refused at the very stat of grub.cfg; treating that refusal as "not this
// one, try the next" would end at "no bootloader configuration on this host"
// and hand controls 8 and 9 a NOT_APPLICABLE for a host that has one (B-10).
// A refusal is the answer.
//
// A symlink at a candidate is an error by design (C4) with ONE exception the
// distributions themselves ship: ruling K-28, the upgraded EL host below.
// muster reads without following links, so an administrator who put a link
// anywhere else has moved the file somewhere this declaration does not cover.
func grubCfgPath(a collect.Access) (string, *facts.Envelope) {
	// K-4: the EFI vendor directories are enumerated BEFORE any stat, so the
	// candidate list is settled before the first question is put to the host.
	matches, globErr := a.Glob(grubEFIGlob)
	slices.Sort(matches)

	for _, p := range grubCfgFixed {
		switch resolved, found, e := grubCandidate(a, p); {
		case found:
			return resolved, nil
		case e != nil:
			return "", e
		}
	}
	// The glob's own failure — a /boot/efi/EFI this run may not search —
	// stands exactly where the EFI candidates stand: after the two fixed
	// paths have said "not there", never before them.
	if globErr != nil {
		e := readErrorEnv(grubEFIGlob, globErr)
		return "", &e
	}
	for _, p := range matches {
		switch resolved, found, e := grubCandidate(a, p); {
		case found:
			return resolved, nil
		case e != nil:
			return "", e
		}
	}
	e := collect.Absent("no bootloader configuration at " +
		strings.Join(grubCfgFixed, ", ") + " or " + grubEFIGlob)
	return "", &e
}

// grubCandidate stats one candidate: the path the facts are about, whether it
// was found, or the answer every leaf has to carry.
//
// Ruling K-28: an EL host installed before 9 and upgraded on UEFI keeps
// /boot/grub2/grub.cfg as a LINK to ../efi/EFI/<vendor>/grub.cfg, and
// grub2-mkconfig preserves it — the distribution ships that link, so C4 says
// muster models it rather than reporting the stock layout as an error. The
// link is resolved TEXTUALLY, through the same no-follow linkTarget every
// other modelled link goes through, and it is accepted only when the target
// is a path this collector already declared: /boot/efi/EFI/*/grub.cfg, the
// one place the upgrade moves the file to. The facts then describe the
// TARGET, which is where the bytes and the permission bits actually are.
//
// A link to anywhere else is still that candidate's error: its bytes were
// never read, and muster has no licence to read them.
func grubCandidate(a collect.Access, p string) (string, bool, *facts.Envelope) {
	switch _, err := a.Stat(p); {
	case err == nil:
		return p, true, nil
	case errors.Is(err, fs.ErrNotExist):
		return "", false, nil
	case errors.Is(err, collect.ErrSymlink):
		if target, ok := linkTarget(a, p); ok {
			if matched, merr := path.Match(grubEFIGlob, target); merr == nil && matched {
				return target, true, nil
			}
		}
		e := readErrorEnv(p, err)
		return "", false, &e
	default:
		e := readErrorEnv(p, err)
		return "", false, &e
	}
}

// grubEFIUserCfg is the user.cfg that sits beside a grub.cfg on the EFI
// system partition, and the second half of K-28: grub-setpassword writes the
// hash next to the file it generated, so a host whose grub.cfg is over there
// keeps its password over there too. ok is false for every other chosen path
// — /boot/grub/user.cfg is NOT declared and muster does not go looking for
// it.
func grubEFIUserCfg(cfg string) (string, bool) {
	if matched, err := path.Match(grubEFIGlob, cfg); err != nil || !matched {
		return "", false
	}
	return path.Join(path.Dir(cfg), grubUserCfgName), true
}

// grubPassword judges the whole chain GRUB reads a superuser out of: the
// grub.cfg that was chosen, the user.cfg grub-setpassword writes beside it,
// and every fragment of /etc/grub.d, which is where an administrator who set
// one by hand put it.
//
// C3 governs a file of that chain that exists and cannot be read: the leaf is
// the read's status, even when another file has already answered true. A run
// that could not see everything must not publish a value as though it had.
func grubPassword(a collect.Access, cfg string, cfgErr *facts.Envelope) facts.Envelope {
	// The grub.cfg candidate that refused its stat is that same answer here
	// (B-10). An ABSENT candidate is not: user.cfg and the fragments may still
	// be there, and a host with another bootloader entirely still deserves
	// whatever they say.
	if cfgErr != nil && cfgErr.Status != facts.StatusAbsent {
		return *cfgErr
	}

	var scan chainScan
	if cfg != "" {
		scan.read(a, cfg)
	}
	scan.read(a, grubUserCfg)
	if beside, ok := grubEFIUserCfg(cfg); ok {
		scan.read(a, beside)
	}
	matches, err := a.Glob(grubDGlob)
	if err != nil {
		scan.fail(grubDGlob, err)
	} else {
		slices.Sort(matches)
		for _, m := range matches {
			scan.read(a, m)
		}
	}
	if scan.readErr != nil {
		return *scan.readErr
	}
	if len(scan.files) == 0 {
		return collect.Absent("no grub.cfg, " + grubUserCfg + " or " + grubDGlob + " to read a password hash from")
	}

	set := false
	for _, f := range scan.files {
		if grubPasswordSet(f.data) {
			set = true
		}
	}
	return withTruncation(collect.OK(set, filesSource(pathsOf(scan.files))), scan.truncated)
}

// grubPasswordSet reports whether the bytes of one file of the boot chain
// carry a bootloader password (ruling K-22). The test is a literal
// `grub.pbkdf2.` hash and nothing else, in either of the two shapes a
// distribution writes one in:
//
//	password_pbkdf2 <user> grub.pbkdf2.sha512.…   (Debian and Ubuntu, in grub.cfg)
//	GRUB2_PASSWORD=grub.pbkdf2.sha512.…           (EL, in user.cfg, value possibly quoted)
//
// `set superusers` counts for nothing, and a `${GRUB2_PASSWORD}` reference is
// not a hash. EL's 01_users fragment emits BOTH tokens into every generated
// grub.cfg, inside an `if [ -n "${GRUB2_PASSWORD}" ]` GRUB evaluates at boot:
// naming a superuser is the template's text, present on every EL host whether
// or not anyone ever ran grub-setpassword, so judging by it would fail a
// whole distribution for a password it does not have. A hash is only ever
// there because someone put it there.
//
// A commented-out example — which every distribution ships — is skipped like
// the comment it is, and the token must be the line's FIRST field, so a
// message or an echo that merely mentions it is not a password.
func grubPasswordSet(data []byte) bool {
	for _, line := range splitLines(data) {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[0] == "password_pbkdf2" && len(fields) >= 3 &&
			strings.HasPrefix(fields[2], grubHashPrefix) {
			return true
		}
		if v, ok := strings.CutPrefix(fields[0], "GRUB2_PASSWORD="); ok &&
			strings.HasPrefix(unquoteShellValue(v), grubHashPrefix) {
			return true
		}
	}
	return false
}

// unquoteShellValue strips the one pair of matching quotes a shell assignment
// may carry. user.cfg is sourced by GRUB's own shell, which accepts the hash
// quoted or bare, and grub-setpassword has written it both ways.
func unquoteShellValue(v string) string {
	if len(v) >= 2 {
		if q := v[0]; (q == '"' || q == '\'') && v[len(v)-1] == q {
			return v[1 : len(v)-1]
		}
	}
	return v
}
