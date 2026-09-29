//go:build linux

package collectors

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

// loginCapable is accounts.login_capable (P-1): the accounts the inactivity
// policy has to cover — an interactive shell by the rule files_home applies
// (interactive(): listed in /etc/shells and not nologin or false, because
// EL's /etc/shells lists nologin) and not a system account by deriveUsers'
// own rule (0 < uid < UID_MIN), so root is in. A password-locked account is
// in too, with locked recording it: pam_unix applies the inactivity field to
// a key login as well. A row without a shadow entry — no /etc/shadow at all
// (haveShadow true, the map empty; R138) or a passwd row shadow does not name
// — has no inactivity field, so it is unset. Every row carries every field
// (V-9). The caller publishes the result only when shadow was read or does
// not exist; a denied shadow is the read's status (C3), so haveShadow false
// is never published and reads like the no-shadow case. Sorted by name, then
// passwd order.
func loginCapable(rows []passwdRow, shadow map[string]shadowRow, haveShadow bool, uidMin int, shells map[string]bool) []any {
	type cand struct {
		r passwdRow
		s shadowRow
	}
	var picked []cand
	for _, r := range rows {
		if r.uid > 0 && r.uid < uidMin {
			continue
		}
		if !interactive(r.shell, shells) {
			continue
		}
		s, ok := shadow[r.name]
		if !ok || !haveShadow {
			s = noShadowRow
		}
		picked = append(picked, cand{r, s})
	}
	sort.SliceStable(picked, func(i, j int) bool { return picked[i].r.name < picked[j].r.name })
	out := make([]any, 0, len(picked)) // R50: never null
	for _, c := range picked {
		out = append(out, map[string]any{
			"name":           c.r.name,
			"uid":            c.r.uid,
			"inactive":       c.s.inactive,
			"expire":         c.s.expire,
			"inactive_unset": c.s.inactive == -1,
			"locked":         c.s.status == "locked",
		})
	}
	return out
}

// uidsOf is the uid → name index parseLastlog decodes: every parsable uid of
// /etc/passwd, the first name in file order when two accounts share one
// (lastlog has one record per uid, not per name).
func uidsOf(rows []passwdRow) map[int]string {
	m := make(map[int]string, len(rows))
	for _, r := range rows {
		if _, seen := m[r.uid]; r.uid >= 0 && !seen {
			m[r.uid] = r.name
		}
	}
	return m
}

// useraddInactive is accounts.useradd.inactive: a missing file is useradd's
// own default, -1; a file that exists and cannot be read is the read's status
// (C3), never that default.
func useraddInactive(a collect.Access) facts.Envelope {
	data, meta, err := a.ReadFile(useraddDefaultsPath, readLimit)
	src := &facts.Source{Kind: "file", Path: useraddDefaultsPath}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		e := collect.OK(-1, &facts.Source{Kind: "derived", Inputs: []facts.Source{*src}})
		e.Reason = "file does not exist"
		return e
	case err != nil:
		return readErrorEnv(useraddDefaultsPath, err)
	}
	v, reason := parseUseraddDefaults(data)
	e := collect.OKRead(v, src, meta)
	e.Reason = reason
	return e
}

// lastlogRows is accounts.lastlog, evidence only: the records of the
// accounts in /etc/passwd. On a read cut at the limit a uid whose record lies
// past it is not decoded — the zero record parseLastlog would answer is not
// what the file says — and the leaf is truncated.
func lastlogRows(a collect.Access, prows []passwdRow, pmeta collect.ReadMeta) facts.Envelope {
	data, meta, err := a.ReadFileBinary(lastlogPath, lastlogReadLimit)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return collect.Absent(lastlogPath + " does not exist: shadow 4.15 replaced it with lastlog2, which muster does not model")
	case err != nil:
		return readErrorEnv(lastlogPath, err)
	}
	size := lastlogRecordSize()
	uids := uidsOf(prows)
	if meta.Truncated {
		for uid := range uids {
			if uid >= len(data)/size { // division, never uid*size: a huge uid would wrap
				delete(uids, uid)
			}
		}
	}
	rows, capped := capRows(parseLastlog(data, size, uids), lastlogRowCap)
	e := collect.OKRead(rows, &facts.Source{Kind: "derived", Inputs: []facts.Source{
		{Kind: "file", Path: passwdPath}, {Kind: "file", Path: lastlogPath},
	}}, meta)
	e.Truncated = e.Truncated || capped || pmeta.Truncated
	e.Reason = fmt.Sprintf("record size %d", size)
	return e
}

// loginCapableEnv wraps loginCapable in its envelope. A shadow that exists
// and could not be read is the answer for every row's inactivity field (C3),
// and so is an /etc/shells that cannot be read or does not exist, which
// decides who is interactive: the libc fallback set loginShells keeps for
// shell_valid omits /bin/bash and is not the host's list, so the leaf is
// denied with the fallback's reason, as the files and sshkeys siblings
// write it (S3, V-67). A missing shadow is a known state (R138) and keeps
// the leaf ok.
func loginCapableEnv(prows []passwdRow, byName map[string]shadowRow, haveShadow bool, serr error, smeta, pmeta collect.ReadMeta, uidMin int, shells map[string]bool, shellsEnv facts.Envelope) facts.Envelope {
	if !haveShadow {
		return readErrorEnv(shadowPath, serr)
	}
	if e, untrusted := untrustedShells(shellsEnv); untrusted {
		return e
	}
	e := collect.OK(loginCapable(prows, byName, haveShadow, uidMin, shells), &facts.Source{Kind: "derived", Inputs: []facts.Source{
		{Kind: "file", Path: passwdPath}, {Kind: "file", Path: shadowPath}, {Kind: "file", Path: shellsPath},
	}})
	e.Truncated = pmeta.Truncated || (serr == nil && smeta.Truncated) || shellsEnv.Truncated
	return e
}
