// Package snapshots lists and selects the snapshot files collect writes
// (RL-16, RL-17). It is pure: cmd/muster reads and changes the directory and
// hands in each file's header and the clock.
package snapshots

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/kun9497/muster/internal/facts"
)

// DefaultDir is where collect writes snapshots.
const DefaultDir = "/var/lib/muster/snapshots"

// Class is how a snapshot file reads to this binary.
type Class string

const (
	ClassOK         Class = "ok"
	ClassNewer      Class = "newer"
	ClassUnreadable Class = "unreadable"
)

// Entry is one snapshot file in the directory. An unreadable entry carries
// only Name and Size; a newer one keeps its header fields as written.
type Entry struct {
	Name                                     string
	Class                                    Class
	Size                                     int64
	SchemaVersion                            int
	CollectedAt                              string
	Hostname, MusterVersion, ControlsVersion string
	Latest                                   bool
}

// ErrNoBounds is a prune with neither a count nor an age bound.
var ErrNoBounds = errors.New("prune needs --keep or --keep-days")

const (
	nameSuffix = ".json"
	hexTail    = 13 // "-" + 12 lowercase hex
	stampPart  = 19 // "-" + YYYY-MM-DDTHHMMSSZ
	maxHost    = 64
	stampForm  = "2006-01-02T150405Z"
)

// ParseName splits a snapshot file name, <host>-<YYYY-MM-DDTHHMMSSZ>-<12
// lowercase hex>.json, into its host and stamp. It reads fixed widths from
// the right (RA-5): the host may hold '-' and '.', and the stamp holds '-'
// itself. The host is 0..64 bytes of [A-Za-z0-9._-].
func ParseName(name string) (host, stamp string, ok bool) {
	base, found := strings.CutSuffix(name, nameSuffix)
	if !found || len(base) < stampPart+hexTail {
		return "", "", false
	}
	tail := base[len(base)-hexTail:]
	if tail[0] != '-' {
		return "", "", false
	}
	for i := 1; i < len(tail); i++ {
		if c := tail[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", "", false
		}
	}
	st := base[len(base)-hexTail-stampPart : len(base)-hexTail]
	// st is "-DDDD-DD-DDTDDDDDDZ".
	for i := 0; i < len(st); i++ {
		c := st[i]
		switch i {
		case 0, 5, 8:
			if c != '-' {
				return "", "", false
			}
		case 11:
			if c != 'T' {
				return "", "", false
			}
		case 18:
			if c != 'Z' {
				return "", "", false
			}
		default:
			if c < '0' || c > '9' {
				return "", "", false
			}
		}
	}
	host = base[:len(base)-hexTail-stampPart]
	if len(host) > maxHost {
		return "", "", false
	}
	for i := 0; i < len(host); i++ {
		if c := host[i]; !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return "", "", false
		}
	}
	return host, st[1:], true
}

// ParseCollectedAt accepts only YYYY-MM-DDTHH:MM:SSZ, round-trip equal.
func ParseCollectedAt(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UTC().Format("2006-01-02T15:04:05Z") != s {
		return time.Time{}, errors.New("collected_at is not YYYY-MM-DDTHH:MM:SSZ")
	}
	return t.UTC(), nil
}

// Classify turns one file's header read into an entry: a failed read or a
// schema below 1 is unreadable, a schema above this binary's is newer (its
// fields kept as written), and a readable schema needs a strict
// collected_at to be ok.
func Classify(name string, size int64, h facts.Header, err error) Entry {
	e := Entry{Name: name, Class: ClassUnreadable, Size: size}
	if err != nil || h.SchemaVersion < 1 {
		return e
	}
	if h.SchemaVersion <= facts.SchemaVersion {
		if _, perr := ParseCollectedAt(h.Run.CollectedAt); perr != nil {
			return e
		}
		e.Class = ClassOK
	} else {
		e.Class = ClassNewer
	}
	e.SchemaVersion = h.SchemaVersion
	e.CollectedAt = h.Run.CollectedAt
	e.Hostname = h.Run.Host.Hostname
	e.MusterVersion = h.Run.MusterVersion
	e.ControlsVersion = h.Run.ControlsVersion
	return e
}

// nameTime is the time the name's stamp spells, or the zero time.
func nameTime(name string) time.Time {
	_, st, ok := ParseName(name)
	if !ok {
		return time.Time{}
	}
	t, err := time.Parse(stampForm, st)
	if err != nil {
		return time.Time{}
	}
	return t
}

// sortKey is the parsed collected_at when it parses, else the name's stamp
// (RA-10).
func sortKey(e Entry) time.Time {
	if t, err := ParseCollectedAt(e.CollectedAt); err == nil {
		return t
	}
	return nameTime(e.Name)
}

// Sort orders entries newest first: by sortKey, then by the name's stamp,
// then by name, so the order is total.
func Sort(entries []Entry) {
	slices.SortStableFunc(entries, func(a, b Entry) int {
		if c := sortKey(b).Compare(sortKey(a)); c != 0 {
			return c
		}
		if c := nameTime(b.Name).Compare(nameTime(a.Name)); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
}

// Newest is the first ok entry in Sort order.
func Newest(entries []Entry) (Entry, bool) {
	sorted := slices.Clone(entries)
	Sort(sorted)
	for _, e := range sorted {
		if e.Class == ClassOK {
			return e, true
		}
	}
	return Entry{}, false
}

// Bounds are prune's limits: keep the newest Keep ok snapshots, keep those
// collected within KeepDays days. Has* says which are set.
type Bounds struct {
	Keep, KeepDays       int
	HasKeep, HasKeepDays bool
}

// Prune selects the entries to remove, in Sort order. Only ok entries are
// candidates and the newest ok one never is (RL-17). With both bounds set an
// entry goes only when it is beyond the newest Keep ok entries and collected
// strictly before now - KeepDays*24h; with one set, that bound alone. The
// cutoff is a calendar step back (AddDate), so no KeepDays wraps it into the
// future; now and every parsed CollectedAt are UTC, where a day is 86400 s.
func Prune(entries []Entry, b Bounds, now time.Time) ([]Entry, error) {
	if !b.HasKeep && !b.HasKeepDays {
		return nil, ErrNoBounds
	}
	sorted := slices.Clone(entries)
	Sort(sorted)
	cutoff := now.AddDate(0, 0, -b.KeepDays)
	var out []Entry
	rank := 0 // position among ok entries, newest is 0
	for _, e := range sorted {
		if e.Class != ClassOK {
			continue
		}
		r := rank
		rank++
		if r == 0 {
			continue
		}
		if b.HasKeep && r < b.Keep {
			continue
		}
		if b.HasKeepDays {
			t, err := ParseCollectedAt(e.CollectedAt)
			if err != nil || !t.Before(cutoff) {
				continue
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// Repoint is the name latest should point at after a removal: the newest ok
// entry left, or false when none is.
func Repoint(remaining []Entry) (target string, ok bool) {
	e, ok := Newest(remaining)
	if !ok {
		return "", false
	}
	return e.Name, true
}
