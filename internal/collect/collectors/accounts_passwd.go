//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const shellsPath = "/etc/shells"

// passwdRow is one /etc/passwd line. shadowed is whether the password
// field defers to /etc/shadow ("x"); anything else in that field is hash
// material or an empty password, and neither is kept.
type passwdRow struct {
	name, home, shell string
	uid, gid          int
	shadowed          bool
	line              int
}

// parsePasswd keeps every line with the seven passwd fields and counts the
// rest, so a mangled file shows up as parse_failures rather than as a
// shorter, cleaner-looking account list. A row whose uid or gid is not a
// number is kept with -1 (the stage-1 contract) and counted as a failure.
// Blank lines and comments are neither.
func parsePasswd(data []byte) (rows []passwdRow, failures int) {
	for i, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] == "" {
			failures++
			continue
		}
		r := passwdRow{name: f[0], shadowed: f[1] == "x", uid: intField(f[2]), gid: intField(f[3]), home: f[5], shell: f[6], line: i + 1}
		if r.uid < 0 || r.gid < 0 {
			failures++
		}
		rows = append(rows, r)
	}
	return rows, failures
}

// libcShells is what getusershell(3) answers when /etc/shells is missing.
var libcShells = []string{"/bin/sh", "/bin/csh"}

// loginShells reads /etc/shells into a set for the shell_valid join and a
// list fact for evidence. A missing file is not a gap in the evidence: libc
// then answers /bin/sh and /bin/csh, so that is what the fact carries —
// derived, with a reason naming where it came from — rather than absent,
// which would leave a shell control with nothing to screen on (R126). An
// unreadable file carries the read's status with the path in the reason,
// and there too the fallback set keeps shell_valid present on every row, so
// a control never meets a record without the field.
func loginShells(a collect.Access) (map[string]bool, facts.Envelope) {
	data, meta, err := a.ReadFile(shellsPath, readLimit)
	if err != nil {
		set := make(map[string]bool, len(libcShells))
		list := make([]any, 0, len(libcShells))
		for _, s := range libcShells {
			set[s] = true
			list = append(list, s)
		}
		if errors.Is(err, fs.ErrNotExist) {
			e := collect.OK(list, &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: shellsPath}}})
			e.Reason = "libc default; " + shellsPath + " does not exist"
			return set, e
		}
		e := collect.FromReadError(err, meta)
		e.Reason = shellsPath + ": " + e.Reason
		return set, e
	}
	set := map[string]bool{}
	list := []any{} // R50: never nil
	for _, l := range splitLines(data) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		set[l] = true
		list = append(list, l)
	}
	return set, collect.OKRead(list, &facts.Source{Kind: "file", Path: shellsPath}, meta)
}

// noShadowRow is the shadow side of a passwd row /etc/shadow does not
// mention. Once shadow was read that absence is itself a finding — the
// account has no shadow entry — so the record says so instead of dropping
// the fields the other records carry (R132): a control that screens on
// password_status must be able to meet this row.
var noShadowRow = shadowRow{
	status: "noshadow", lastChange: -1, min: -1, max: -1, warn: -1, inactive: -1, expire: -1,
}

// deriveUsers builds the accounts.users records: the passwd fields, the
// joins that need only /etc/passwd itself (duplicate uid, duplicate name,
// system by the UID_MIN boundary, shell validity by /etc/shells) and, when
// /etc/shadow was read, the shadow-derived fields. Rows keep file order.
func deriveUsers(rows []passwdRow, shadow map[string]shadowRow, haveShadow bool, uidMin int, shells map[string]bool) []any {
	uidCount := map[int]int{}
	nameCount := map[string]int{}
	for _, r := range rows {
		if r.uid >= 0 {
			uidCount[r.uid]++
		}
		nameCount[r.name]++
	}
	users := []any{} // R50: a host with no parsable accounts yields [], not null
	for _, r := range rows {
		u := map[string]any{
			"name":           r.name,
			"uid":            r.uid,
			"gid":            r.gid,
			"home":           r.home,
			"shell":          r.shell,
			"system":         r.uid > 0 && r.uid < uidMin,
			"shadowed":       r.shadowed,
			"uid_duplicate":  r.uid >= 0 && uidCount[r.uid] > 1,
			"name_duplicate": nameCount[r.name] > 1,
			"shell_valid":    shells[r.shell],
		}
		// Without shadow the row simply has no password or ageing fields,
		// rather than zeroes that would read as a policy nobody set.
		if haveShadow {
			s, ok := shadow[r.name]
			if !ok {
				s = noShadowRow
			}
			u["password_status"] = s.status
			u["locked"] = s.status == "locked"
			u["hash_algo"] = s.algo
			u["last_change"] = s.lastChange
			u["min"] = s.min
			u["max"] = s.max
			u["warn"] = s.warn
			u["inactive"] = s.inactive
			u["expire"] = s.expire
		}
		users = append(users, u)
	}
	return users
}
