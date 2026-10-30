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

// MapPath rewrites p at AX-6's positions only, matched on the cleaned path:
// the last component of every non-kept account's home that is p or a prefix
// of it (unless the home is /, /tmp, /var/tmp, /dev/null, /nonexistent, a
// mount target or of fewer than two components); the component after /home/
// (an account's name or not); a component directly under a name position
// (the cron spools, the mail spools, linger, AccountsService, /etc/sudoers.d,
// /etc/cron.d) that is a mapped account name, whether it ends the path or is
// a parent in it. Each rewritten component becomes its account pseudonym, so
// a path maps the same standing alone or as a prefix. A rewritten path comes
// back cleaned (a trailing "/" kept); one with nothing to rewrite, and any
// relative path, comes back as it was.
func (k *Key) MapPath(p string, homes Homes) string {
	out, _ := k.mapPath(p, homes)
	return out
}

// mapPath also returns the component names it mapped by the account rule.
func (k *Key) mapPath(p string, homes Homes) (string, []string) {
	if !strings.HasPrefix(p, "/") {
		return p, nil
	}
	c := path.Clean(p)
	if c == "/" {
		return p, nil
	}
	comps := strings.Split(c, "/") // comps[0] == ""; no other empty component
	at := map[int]bool{}
	for n := 2; n < len(comps); n++ {
		parent := strings.Join(comps[:n], "/")
		if homeEligible(parent+"/"+comps[n], comps[n], homes) {
			at[n] = true
		}
		if homes.names[comps[n]] && namePositions[parent] {
			at[n] = true
		}
	}
	if len(comps) >= 3 && comps[1] == "home" {
		at[2] = true
	}
	if len(at) == 0 {
		return p, nil
	}
	var names []string
	for i := range comps {
		if !at[i] {
			continue
		}
		names = append(names, comps[i])
		comps[i] = k.Account(comps[i])
	}
	out := strings.Join(comps, "/")
	if strings.HasSuffix(p, "/") {
		out += "/"
	}
	return out, names
}

func homeEligible(home, last string, homes Homes) bool {
	accts := homes.homes[home]
	if accts == nil || !accts[last] || homeExceptions[home] || isMountTarget(home) {
		return false
	}
	return strings.Count(home, "/") >= 2
}
