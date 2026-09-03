//go:build linux

package collect

import (
	"errors"
	"io/fs"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/kun9497/muster/internal/facts"
)

// Builder accumulates facts by registry key and renders the nested tree.
// Setting an unregistered key panics: it is a programming error the
// collector tests must catch, never a runtime condition.
type Builder struct {
	reg     *facts.Registry
	tree    map[string]any
	header  *facts.Run
	current string
	keys    map[string][]string // collector name -> keys set under it (R71)
}

func NewBuilder(reg *facts.Registry) *Builder {
	return &Builder{reg: reg, tree: map[string]any{}, header: &facts.Run{}, keys: map[string][]string{}}
}

// Header returns the run header being assembled for this snapshot; it
// starts empty and later tasks fill it in as collection proceeds.
func (b *Builder) Header() *facts.Run { return b.header }

// Begin marks name as the collector whose keys are being set from here on,
// so Keys and Worst can later be asked about it (R71).
func (b *Builder) Begin(name string) { b.current = name }

func (b *Builder) place(key string, leaf any) {
	e, ok := b.reg.Lookup(key)
	if !ok {
		panic("collect: unregistered fact key " + key)
	}
	_, isSetting := leaf.(facts.Setting)
	if b.reg.IsSetting(e) != isSetting {
		panic("collect: key " + key + " has type " + e.Type + "; wrong leaf kind")
	}
	segs := strings.Split(key, ".")
	cur := b.tree
	for _, s := range segs[:len(segs)-1] {
		next, ok := cur[s].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[s] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = leaf
	b.keys[b.current] = append(b.keys[b.current], key)
}

// Set records an envelope under key. A nil []any or []string value is
// stored as an empty, non-nil []any (R50) so it serialises as "[]" rather
// than "null" — encoding/json's omitempty on an `any` field only elides a
// truly nil interface, and a typed nil slice boxed into that interface is
// not one.
func (b *Builder) Set(key string, env facts.Envelope) {
	env.Value = normalizeListValue(env.Value)
	b.place(key, env)
}

func normalizeListValue(v any) any {
	switch vv := v.(type) {
	case []any:
		if vv == nil {
			return []any{}
		}
	case []string:
		if vv == nil {
			return []any{}
		}
	}
	return v
}

// SetSetting records a two-home setting under key.
func (b *Builder) SetSetting(key string, s facts.Setting) { b.place(key, s) }

// Tree returns the nested facts tree for the snapshot.
func (b *Builder) Tree() map[string]any { return b.tree }

// Keys returns, sorted, every key set for collector name.
func (b *Builder) Keys(name string) []string {
	ks := append([]string(nil), b.keys[name]...)
	sort.Strings(ks)
	return ks
}

// leaf walks the tree already built by place, by dotted key.
func (b *Builder) leaf(key string) any {
	var cur any = b.tree
	for _, s := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		v, ok := m[s]
		if !ok {
			return nil
		}
		cur = v
	}
	return cur
}

// statusRank orders statuses for Worst: ok < denied < timeout < error.
// absent and unsupported rank as ok — a collector that correctly determined
// a thing is absent, or that this environment has no such mechanism, is not
// thereby worse off than one that read successfully (R71).
func statusRank(s facts.Status) int {
	switch s {
	case facts.StatusDenied:
		return 1
	case facts.StatusTimeout:
		return 2
	case facts.StatusError:
		return 3
	default: // ok, absent, unsupported
		return 0
	}
}

// Worst is the worst status among name's keys. A setting counts each
// present side (runtime/persisted/effective) on its own, so a setting whose
// persisted side errored is worst=error even if its effective side is ok. A
// name with no keys is ok (R71).
func (b *Builder) Worst(name string) facts.Status {
	worst := 0
	for _, k := range b.Keys(name) {
		switch leaf := b.leaf(k).(type) {
		case facts.Envelope:
			worst = max(worst, statusRank(leaf.Status))
		case facts.Setting:
			for _, side := range []*facts.Envelope{leaf.Runtime, leaf.Persisted, leaf.Effective} {
				if side != nil {
					worst = max(worst, statusRank(side.Status))
				}
			}
		}
	}
	switch worst {
	case 1:
		return facts.StatusDenied
	case 2:
		return facts.StatusTimeout
	case 3:
		return facts.StatusError
	default:
		return facts.StatusOK
	}
}

func OK(value any, src *facts.Source) facts.Envelope {
	return facts.Envelope{Status: facts.StatusOK, Value: value, Source: src}
}

// OKRead is OK plus the truncation flag from a read (R70): FromReadError
// classifies errors only, so a caller that got data back — truncated or
// not — builds its envelope here instead.
func OKRead(value any, src *facts.Source, meta ReadMeta) facts.Envelope {
	e := OK(value, src)
	e.Truncated = meta.Truncated
	return e
}

func Absent(reason string) facts.Envelope {
	return facts.Envelope{Status: facts.StatusAbsent, Reason: reason}
}
func Denied(reason string) facts.Envelope {
	return facts.Envelope{Status: facts.StatusDenied, Reason: reason}
}
func Unsupported(reason string) facts.Envelope {
	return facts.Envelope{Status: facts.StatusUnsupported, Reason: reason}
}
func TimeoutEnv(reason string) facts.Envelope {
	return facts.Envelope{Status: facts.StatusTimeout, Reason: reason}
}
func ErrorEnv(reason string) facts.Envelope {
	return facts.Envelope{Status: facts.StatusError, Reason: reason}
}

// FromReadError turns a read primitive error into the right status (spec
// §7.1, R42): file-not-found (ENOENT, and ENOTDIR from an intermediate
// component that turned out not to be a directory) is absent; a permission
// error (EACCES/EPERM, or an os/fs-wrapped equivalent) is denied with the
// privilege named; anything else — including ErrSymlink and ErrNotRegular —
// is error with the wrapped message. Both a raw syscall.Errno and an
// os/fs-sentinel-wrapped error classify, because callers see both: the read
// primitive returns bare unix.Errno values, but a double or a future
// caller may inject the os/fs form.
//
// It classifies errors only: a value that came back truncated is still ok
// (R70) and is built with OKRead instead, so meta — kept for signature
// symmetry with OKRead and call-site consistency — is unused here.
func FromReadError(err error, _ ReadMeta) facts.Envelope {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return Absent("not present")
	case errors.Is(err, fs.ErrPermission):
		reason, _ := DeniedReason(err)
		return Denied(reason)
	default:
		return ErrorEnv(err.Error())
	}
}
