//go:build linux

package collectors

import (
	"errors"
	"io/fs"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// groupRow is one /etc/group line; members are the listed (secondary)
// members with duplicates removed, in list order.
type groupRow struct {
	name    string
	gid     int
	members []string
	line    int
}

// parseGroup mirrors parsePasswd: four fields or the line counts as a
// parse failure; a non-numeric gid is kept as -1 and counted.
func parseGroup(data []byte) (rows []groupRow, failures int) {
	for i, line := range splitLines(data) {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 4 || f[0] == "" {
			failures++
			continue
		}
		r := groupRow{name: f[0], gid: intField(f[2]), line: i + 1}
		if r.gid < 0 {
			failures++
		}
		seen := map[string]bool{}
		for _, m := range strings.Split(f[3], ",") {
			m = strings.TrimSpace(m)
			if m == "" || seen[m] {
				continue
			}
			seen[m] = true
			r.members = append(r.members, m)
		}
		rows = append(rows, r)
	}
	return rows, failures
}

// groupRecords is the accounts.groups value: file order, member_count from
// the de-duplicated member list, gid_duplicate over the whole file.
func groupRecords(rows []groupRow) []any {
	gidCount := map[int]int{}
	for _, r := range rows {
		if r.gid >= 0 {
			gidCount[r.gid]++
		}
	}
	out := []any{} // R50
	for _, r := range rows {
		members := []any{}
		for _, m := range r.members {
			members = append(members, m)
		}
		out = append(out, map[string]any{
			"name":          r.name,
			"gid":           r.gid,
			"members":       members,
			"member_count":  len(r.members),
			"gid_duplicate": r.gid >= 0 && gidCount[r.gid] > 1,
		})
	}
	return out
}

// orphanGIDs lists the accounts whose primary gid is not any group's gid,
// in passwd order. A row with an unparsable gid (-1) is not an orphan: it
// is already a parse failure.
func orphanGIDs(users []passwdRow, groups []groupRow) []any {
	exists := map[int]bool{}
	for _, g := range groups {
		if g.gid >= 0 {
			exists[g.gid] = true
		}
	}
	out := []any{}
	for _, u := range users {
		if u.gid >= 0 && !exists[u.gid] {
			out = append(out, map[string]any{"name": u.name, "gid": u.gid})
		}
	}
	return out
}

// adminGroups are the groups whose membership the administrator items
// judge (root on every host, wheel on the RHEL family, sudo and admin on
// the Debian family).
var adminGroups = []string{"root", "wheel", "sudo", "admin"}

// adminGroupMembers lists, for each administrative group in /etc/group
// order, the accounts that belong to it other than root itself: first the
// accounts whose primary gid is the group's (passwd order), then the listed
// secondary members (list order). An account is listed once per group.
func adminGroupMembers(users []passwdRow, groups []groupRow) []any {
	admin := map[string]bool{}
	for _, g := range adminGroups {
		admin[g] = true
	}
	out := []any{}
	for _, g := range groups {
		if !admin[g.name] {
			continue
		}
		seen := map[string]bool{"root": true}
		add := func(name, via string) {
			if seen[name] {
				return
			}
			seen[name] = true
			out = append(out, map[string]any{"name": name, "group": g.name, "via": via})
		}
		for _, u := range users {
			if u.gid >= 0 && u.gid == g.gid {
				add(u.name, "primary")
			}
		}
		for _, m := range g.members {
			add(m, "secondary")
		}
	}
	return out
}

// shadowInUse derives accounts.shadow_in_use from the two reads. A missing
// /etc/shadow is a legitimate (and bad) state, so it is a false with the
// reason, not an absent fact; an unreadable one is the read's status, so a
// control can never turn "could not look" into "not in use".
func shadowInUse(users []passwdRow, serr error, smeta, pmeta collect.ReadMeta) facts.Envelope {
	derived := &facts.Source{Kind: "derived", Inputs: []facts.Source{{Kind: "file", Path: passwdPath}, {Kind: "file", Path: shadowPath}}}
	if serr != nil {
		if errors.Is(serr, fs.ErrNotExist) {
			e := collect.OK(false, derived)
			e.Reason = shadowPath + " does not exist"
			e.Truncated = pmeta.Truncated
			return e
		}
		e := collect.FromReadError(serr, smeta)
		e.Reason = shadowPath + ": " + e.Reason
		return e
	}
	e := collect.OK(true, derived)
	e.Truncated = smeta.Truncated || pmeta.Truncated
	for _, u := range users {
		if !u.shadowed {
			e.Value = false
			e.Reason = "account " + u.name + " keeps its password field in " + passwdPath
			break
		}
	}
	return e
}
