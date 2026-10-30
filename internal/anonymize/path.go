package anonymize

import (
	path "path"
	"strings"
)

// MountTargets is the closed list of mount targets the control set names
// (AX-6): a home equal to one is never rewritten. internal/anonymize never
// reads the control set; a test in internal/controls pins this list to it.
var MountTargets = []string{"/boot", "/dev/shm", "/home", "/tmp", "/var", "/var/log", "/var/log/audit", "/var/tmp"}

func isMountTarget(p string) bool {
	for _, m := range MountTargets {
		if m == p {
			return true
		}
	}
	return false
}

// homeExceptions are the homes whose last component is never rewritten,
// beside the mount targets and the homes of fewer than two components.
var homeExceptions = map[string]bool{"/": true, "/tmp": true, "/var/tmp": true, "/dev/null": true, "/nonexistent": true}

// Homes is what AX-6 maps paths by: the mapped account names (every name the
// account rule maps anywhere in the snapshot, sigils stripped) and each
// home's accounts. The zero value is empty and ready to use.
type Homes struct {
	names map[string]bool
	homes map[string]map[string]bool // home, trailing "/" trimmed -> its mapped accounts
}

// AddName records an account name the account rule maps; a kept name, a uid
// and the empty string are ignored.
func (h *Homes) AddName(name string) {
	core, ok := accountCore(name)
	if !ok || Kept(core) {
		return
	}
	if h.names == nil {
		h.names = map[string]bool{}
	}
	h.names[core] = true
}

// AddHome records home as the home of each account (their names recorded as
// by AddName); a kept account's home is not one AX-6 rewrites.
func (h *Homes) AddHome(home string, accounts ...string) {
	home = cleanPath(home)
	for _, a := range accounts {
		core, ok := accountCore(a)
		if !ok || Kept(core) {
			continue
		}
		h.AddName(core)
		if h.homes == nil {
			h.homes = map[string]map[string]bool{}
		}
		if h.homes[home] == nil {
			h.homes[home] = map[string]bool{}
		}
		h.homes[home][core] = true
	}
}

// cleanPath cleans an absolute path by path.Clean; anything else is kept.
func cleanPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return p
	}
	return path.Clean(p)
}

// accountCore strips the sigils Account keeps (%, +, -, @, and # before a
// non-number) and reports false for "", a bare sigil and a #uid.
func accountCore(name string) (string, bool) {
	for name != "" {
		switch name[0] {
		case '%', '+', '-', '@':
			name = name[1:]
			continue
		case '#':
			if rest := name[1:]; rest == "" || allDigits(rest) {
				return "", false
			}
			name = name[1:]
			continue
		}
		return name, true
	}
	return "", false
}

// namePositions are the directories whose direct child is named after an
// account (AX-6).
var namePositions = map[string]bool{
	"/var/spool/cron/crontabs":       true,
	"/var/spool/cron":                true,
	"/var/mail":                      true,
	"/var/spool/mail":                true,
	"/var/lib/systemd/linger":        true,
	"/var/lib/AccountsService/users": true,
	"/etc/sudoers.d":                 true,
	"/etc/cron.d":                    true,
}

// journalDirs are the directories whose direct child journald names by the
// raw machine id; blsDirs are the Boot Loader Specification's, whose direct
// child is the machine id or <machine id>-<rest> (an entry, a kernel
// directory). The id's sha256 is the header's machine_id_hash, so the id is
// mapped too (AX-6's machine-id positions).
var (
	journalDirs = map[string]bool{"/var/log/journal": true, "/run/log/journal": true}
	blsDirs     = map[string]bool{"/boot": true, "/boot/loader/entries": true, "/efi": true, "/efi/loader/entries": true}
	// privateTmpDirs hold systemd's PrivateTmp directories,
	// systemd-private-<boot id>-<unit>-<random>: the boot id the header
	// blanks is mapped by the same sub-key under its own label.
	privateTmpDirs = map[string]bool{"/tmp": true, "/var/tmp": true}
)

const privateTmpPrefix = "systemd-private-"

// idNote is one raw host identifier a path held: in is the label and the
// raw 32 hex, out its 32-hex pseudonym.
type idNote struct{ in, out string }

// hostIDComponent maps component c under the cleaned directory parent when
// c sits at a machine-id position.
func (k *Key) hostIDComponent(parent, c string) (string, *idNote, bool) {
	switch {
	case journalDirs[parent] && isHex32(c):
		return k.idComponent(idLabel, c, "")
	case blsDirs[parent] && isHex32(c):
		return k.idComponent(idLabel, c, "")
	case blsDirs[parent] && len(c) > 33 && c[32] == '-' && isHex32(c[:32]):
		return k.idComponent(idLabel, c[:32], c[32:])
	case privateTmpDirs[parent] && strings.HasPrefix(c, privateTmpPrefix):
		rest := c[len(privateTmpPrefix):]
		if len(rest) > 33 && rest[32] == '-' && isHex32(rest[:32]) {
			out, n, ok := k.idComponent(bootLabel, rest[:32], rest[32:])
			return privateTmpPrefix + out, n, ok
		}
	}
	return "", nil, false
}

func (k *Key) idComponent(label, raw, rest string) (string, *idNote, bool) {
	out := k.hostID(label, raw)
	return out + rest, &idNote{label + raw, out}, true
}

// MapPath rewrites p at AX-6's positions only: the last component of every
// non-kept account's home that is p or a prefix of it (unless the home is /,
// /tmp, /var/tmp, /dev/null, /nonexistent, a mount target or of fewer than two
// components); the component after /home/ (an account's name or not); a
// component directly under a name position (the cron spools, the mail spools,
// linger, AccountsService, /etc/sudoers.d, /etc/cron.d) that is a mapped
// account name, whether it ends the path or is a parent in it; and, by the
// machine-id sub-key, the raw machine id that names a component directly
// under /var/log/journal or /run/log/journal (the whole component), or
// under /boot, /boot/loader/entries, /efi or /efi/loader/entries (the whole
// component or the 32 hex before its first "-"); and the boot id of a
// systemd-private-<boot id>-<rest> component directly under /tmp or /var/tmp,
// under its own label. Positions are
// decided on the cleaned prefix up to each component, and the rewrite is made
// in place on the components as written: each rewritten component becomes its
// account pseudonym, and "", "." and ".." are never rewritten. So two
// spellings of one file stay two strings, and a ".." never hides a name. A
// relative path is kept.
func (k *Key) MapPath(p string, homes Homes) string {
	out, _, _ := k.mapPath(p, homes)
	return out
}

// mapPath also returns the component names it mapped by the account rule
// and the host identifiers it mapped by the machine-id sub-key.
func (k *Key) mapPath(p string, homes Homes) (string, []string, []idNote) {
	if !strings.HasPrefix(p, "/") {
		return p, nil, nil
	}
	raw := strings.Split(p, "/") // raw[0] == ""
	comps := append([]string(nil), raw...)
	var names []string
	var ids []idNote
	changed := false
	for i := 1; i < len(comps); i++ {
		c := comps[i]
		if c == "" || c == "." || c == ".." {
			continue
		}
		parent := path.Clean("/" + strings.Join(raw[1:i], "/"))
		if out, n, ok := k.hostIDComponent(parent, c); ok {
			ids = append(ids, *n)
			comps[i] = out
			changed = true
			continue
		}
		if parent != "/home" && !(homes.names[c] && namePositions[parent]) && !homeEligible(path.Join(parent, c), c, homes) {
			continue
		}
		names = append(names, c)
		comps[i] = k.Account(c)
		changed = true
	}
	if !changed {
		return p, nil, nil
	}
	return strings.Join(comps, "/"), names, ids
}

func homeEligible(home, last string, homes Homes) bool {
	accts := homes.homes[home]
	if accts == nil || !accts[last] || homeExceptions[home] || isMountTarget(home) {
		return false
	}
	return strings.Count(home, "/") >= 2
}
