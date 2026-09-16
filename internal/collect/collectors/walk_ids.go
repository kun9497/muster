//go:build linux

package collectors

import (
	"cmp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/kun9497/muster/internal/collect"
	"github.com/kun9497/muster/internal/facts"
)

const (
	subuidPath = "/etc/subuid"
	subgidPath = "/etc/subgid"
)

// dynamicUIDMin and dynamicUIDMax bound systemd's DynamicUser range, both
// ends inclusive, and the same pair bounds the gids it allocates. A unit
// with DynamicUser=yes runs under an id allocated from this range for the
// lifetime of the unit, and the files it left under StateDirectory keep
// that ownership afterwards, so an id in here is accounted for even though
// no line in /etc/passwd or /etc/group names it. Reporting those files as
// unowned would be a finding on every stock host that runs one such unit.
const dynamicUIDMin, dynamicUIDMax = 61184, 65519

// The four classes an id falls into. They are what the walk records beside
// a file whose owner is not a plain account, so a reviewer can tell
// "systemd allocated this" from "nothing on this host claims it".
const (
	classPasswd  = "passwd"  // a line in /etc/passwd (uid) or /etc/group (gid)
	classSubID   = "subid"   // inside a range delegated by /etc/subuid or /etc/subgid
	classDynamic = "dynamic" // inside systemd's DynamicUser range
	classUnknown = "unknown" // nothing on this host accounts for it
)

// idTables answers, for one uid or gid, whether anything on this host
// accounts for it and what accounts for it. The two functions are what the
// traversal calls per entry, so they do map and binary-search lookups only
// — no file is read after loadIDTables has returned.
type idTables struct {
	uidKnown func(uint32) (bool, string)
	gidKnown func(uint32) (bool, string)
}

// idRange is one delegated range, half-open: [start, end). It is kept in
// uint64 so a start plus a count that would overflow a uint32 can be
// clamped rather than wrapping around into low ids.
type idRange struct{ start, end uint64 }

// idSet is one side of the tables: the ids named outright by a file, and
// the ranges delegated to them merged into a disjoint sorted list so a
// lookup is one binary search however many lines the sub-id file had.
type idSet struct {
	ids    map[uint32]bool
	ranges []idRange
}

// known classifies one id. The order is deliberate: a file whose owner is a
// real account is reported as that even when the id also sits inside a
// delegated range or the DynamicUser range, because the account is the more
// specific and the more useful answer.
func (s *idSet) known(id uint32) (bool, string) {
	if s.ids[id] {
		return true, classPasswd
	}
	if s.inRange(uint64(id)) {
		return true, classSubID
	}
	if id >= dynamicUIDMin && id <= dynamicUIDMax {
		return true, classDynamic
	}
	return false, classUnknown
}

func (s *idSet) inRange(id uint64) bool {
	// The ranges are disjoint and sorted by start, so the only candidate is
	// the last one that starts at or below id.
	i := sort.Search(len(s.ranges), func(i int) bool { return s.ranges[i].start > id })
	return i > 0 && id < s.ranges[i-1].end
}

// loadIDTables reads the four id files and returns the tables plus one
// envelope per file that could not be read, keyed by its path and with the
// path prefixed onto the reason (convention C3).
//
// Each file contributes independently: a denied /etc/subuid leaves every
// /etc/passwd answer intact, and an /etc/passwd that could not be read
// still leaves the DynamicUser range and any numerically keyed sub-id row
// answering. That matters because the caller turns "unknown" into a
// finding — the tables must never widen a failure to read one file into a
// claim that a host's accounts do not exist.
//
// A file that is simply not there is reported too, as FromReadError
// classifies it: absent. The caller tells it from denied and from error by
// the envelope's status, because a host with no /etc/subuid has no
// delegation to miss, while a host that would not let muster read one does.
//
// A file whose read hit the size cap gets an entry as well, with what was
// read still folded into the tables: the accounts that were read are real,
// and the entry is what tells the caller that the ones past the cap were
// not. The map's promise is therefore "every path whose contribution is
// incomplete, and why" — a caller that degrades on any entry degrades
// correctly.
func loadIDTables(a collect.Access) (idTables, map[string]facts.Envelope) {
	failures := map[string]facts.Envelope{}
	note := func(path string, meta collect.ReadMeta) {
		if !meta.Truncated {
			return
		}
		e := collect.ErrorEnv(path + ": read hit the size cap; the ids past it were not read")
		e.Truncated = true
		failures[path] = e
	}
	read := func(path string) ([]byte, bool) {
		data, meta, err := a.ReadFile(path, readLimit)
		if err != nil {
			e := collect.FromReadError(err, meta)
			e.Reason = path + ": " + e.Reason
			failures[path] = e
			return nil, false
		}
		note(path, meta)
		return data, true
	}

	uids := &idSet{ids: map[uint32]bool{}}
	gids := &idSet{ids: map[uint32]bool{}}
	userNames := map[string]bool{}
	groupSet := map[string]bool{}

	if data, ok := read(passwdPath); ok {
		rows, _ := parsePasswd(data) // a mangled line is one lost account, not a lost file
		for _, r := range rows {
			userNames[r.name] = true
			if r.uid >= 0 {
				uids.ids[uint32(r.uid)] = true
			}
		}
	}
	// groupNames is the same gid -> name map the permission facts are built
	// from, so the walk and those facts cannot disagree about /etc/group. A
	// gid that only appears as an account's primary group is NOT taken as
	// known: no group claims it, which is exactly the dangling ownership the
	// unowned rule is looking for.
	if names, meta, err := groupNames(a); err != nil {
		e := collect.FromReadError(err, meta)
		e.Reason = groupPath + ": " + e.Reason
		failures[groupPath] = e
	} else {
		note(groupPath, meta)
		for gid, name := range names {
			if gid >= 0 {
				gids.ids[uint32(gid)] = true
			}
			groupSet[name] = true
		}
	}

	if data, ok := read(subuidPath); ok {
		uids.ranges = mergeRanges(parseSubIDs(data, func(n string) bool { return userNames[n] }))
	}
	if data, ok := read(subgidPath); ok {
		// shadow-utils keys /etc/subgid by login name, but an administrator
		// writing a group name there is common enough that both are accepted.
		gids.ranges = mergeRanges(parseSubIDs(data, func(n string) bool { return groupSet[n] || userNames[n] }))
	}

	return idTables{uidKnown: uids.known, gidKnown: gids.known}, failures
}

// idSpace is one past the largest id a uid_t or gid_t can hold.
const idSpace = 1 << 32

// parseSubIDs reads the name:start:count lines of /etc/subuid or
// /etc/subgid. A first field that is a number is that id's own range and
// needs no lookup, which is also what keeps the file useful when
// /etc/passwd could not be read. A line naming somebody this host does not
// have is dropped: a stale row must not vouch for a file's ownership. A
// malformed line is dropped the same way — this file's job is to widen what
// counts as accounted for, and a line that cannot be read widens nothing.
func parseSubIDs(data []byte, nameKnown func(string) bool) []idRange {
	var out []idRange
	for _, line := range splitLines(data) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) != 3 {
			continue
		}
		start, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			continue
		}
		count, err := strconv.ParseUint(f[2], 10, 64)
		if err != nil || count == 0 {
			continue
		}
		if _, numErr := strconv.ParseUint(f[0], 10, 32); numErr != nil && !nameKnown(f[0]) {
			continue
		}
		if start >= idSpace {
			continue
		}
		end := start + count
		if end > idSpace {
			end = idSpace // a count running past the end of the id space delegates no further
		}
		out = append(out, idRange{start: start, end: end})
	}
	return out
}

// mergeRanges sorts the ranges by start and merges every pair that overlaps
// or touches, so the result is disjoint and inRange's binary search has
// exactly one candidate. Touching ranges are merged too — 100000..165536
// and 165536..165636 cover one contiguous span, and keeping them apart
// would only cost a comparison.
func mergeRanges(in []idRange) []idRange {
	if len(in) == 0 {
		return nil
	}
	rs := slices.Clone(in)
	slices.SortFunc(rs, func(a, b idRange) int {
		if c := cmp.Compare(a.start, b.start); c != 0 {
			return c
		}
		return cmp.Compare(a.end, b.end)
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if r.start <= last.end {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
