//go:build linux

package collectors

import (
	"context"
	"errors"
	"io/fs"
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
		grubUserCfg, grubDGlob,
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
func bootSecureBoot(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFile(secureBootPath, readLimit)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return collect.Absent(secureBootPath + " does not exist")
		}
		return readErrorEnv(secureBootPath, err)
	}
	enabled, ok := secureBootFromEfivar(data)
	if !ok {
		return collect.ErrorEnv(secureBootPath + ": " + strconv.Itoa(len(data)) +
			" bytes, too few for an efivar's four-byte attribute word and its value")
	}
	return collect.OKRead(enabled, &facts.Source{Kind: "sys", Path: secureBootPath}, meta)
}

// secureBootFromEfivar decodes one efivarfs file. Every variable efivarfs
// exports begins with the four-byte attribute word the firmware stored it
// with, so the value starts at offset 4 and SecureBoot's value is one byte.
//
// ok is false when the file is shorter than that, which is not a value at
// all: reading "off" out of four bytes would be an invention, and a host
// whose efivarfs answers something that short has a problem worth an error.
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
// A symlink at a candidate is an error by design (C4): muster reads without
// following links, no distribution ships grub.cfg as one, and an
// administrator who did put a link there has moved the file somewhere this
// declaration does not cover.
func grubCfgPath(a collect.Access) (string, *facts.Envelope) {
	// K-4: the EFI vendor directories are enumerated BEFORE any stat, so the
	// candidate list is settled before the first question is put to the host.
	matches, globErr := a.Glob(grubEFIGlob)
	slices.Sort(matches)

	for _, p := range grubCfgFixed {
		switch found, e := grubCandidate(a, p); {
		case found:
			return p, nil
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
		switch found, e := grubCandidate(a, p); {
		case found:
			return p, nil
		case e != nil:
			return "", e
		}
	}
	e := collect.Absent("no bootloader configuration at " +
		strings.Join(grubCfgFixed, ", ") + " or " + grubEFIGlob)
	return "", &e
}

// grubCandidate stats one candidate: found, not there, or an answer.
func grubCandidate(a collect.Access, p string) (bool, *facts.Envelope) {
	switch _, err := a.Stat(p); {
	case err == nil:
		return true, nil
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		e := readErrorEnv(p, err)
		return false, &e
	}
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
		return collect.Absent("no grub.cfg, " + grubUserCfg + " or " + grubDGlob + " to read a superuser from")
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
// configure a bootloader password. GRUB asks for one once a superuser is
// named (`set superusers`), and can check it once a hash is given
// (`password_pbkdf2`); either is enough to judge the file by.
//
// The token has to be the line's FIRST field, so a message or an echo that
// merely mentions it is not a password, and a commented-out example — which
// every distribution ships — is skipped like the comment it is.
func grubPasswordSet(data []byte) bool {
	for _, line := range splitLines(data) {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if fields[0] == "password_pbkdf2" {
			return true
		}
		if fields[0] == "set" && len(fields) > 1 &&
			(fields[1] == "superusers" || strings.HasPrefix(fields[1], "superusers=")) {
			return true
		}
	}
	return false
}
